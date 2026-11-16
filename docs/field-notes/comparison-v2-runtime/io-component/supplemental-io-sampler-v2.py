#!/usr/bin/env python3
"""Private, supplemental host I/O observations; default prints a plan only.

Explicit --sample reads three fixed kernel text interfaces, emits JSONL to stdout,
and uses a finite monotonic budget (maximum 6255 seconds). No
commands, network calls, SMART queries, files created, or device writes.
No final record means incomplete capture, including a closed/backpressured sink.
"""
import argparse
from datetime import datetime, timezone
import json
import math
import os
import re
from pathlib import Path
import select
import signal
import stat
import sys
import time

MAX_SECONDS = 6255  # Proposed v2: 120+5400+45+600+15+15+60; job adds 20 seconds.
MAX_OUTPUT_BYTES = 32 * 1024 * 1024
MAX_LINE_BYTES = 8192
MAX_RECORDS = MAX_SECONDS + 2
BLOCK = "/sys/class/block/nvme0n1/stat"
PRESSURE = "/proc/pressure/io"
CPU = "/proc/stat"
BLOCK_NAMES = (
    "reads_completed", "reads_merged", "read_sectors_512b", "read_time_ms",
    "writes_completed", "writes_merged", "write_sectors_512b", "write_time_ms",
    "in_flight", "io_time_ms", "weighted_io_time_ms", "discards_completed",
    "discards_merged", "discard_sectors_512b", "discard_time_ms", "flushes_completed", "flush_time_ms",
)
CPU_NAMES = ("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal", "guest", "guest_nice")


def require(ok, message):
    if not ok:
        raise ValueError(message)


def duration(value):
    try:
        seconds = int(value)
    except (TypeError, ValueError) as error:
        raise argparse.ArgumentTypeError("Integer seconds required") from error
    if str(seconds) != str(value) or not 1 <= seconds <= MAX_SECONDS:
        raise argparse.ArgumentTypeError("Seconds must be an integer from 1 to 6255")
    return seconds


def nonnegative_integer(value):
    require(value.isascii() and value.isdecimal(), "Expected nonnegative decimal integer")
    return int(value)


def parse_block(text):
    words = text.split()
    require(len(words) in (11, 15, 17), "Unknown block stat field count")
    return dict(zip(BLOCK_NAMES, map(nonnegative_integer, words)))


def parse_pressure(text):
    result = {}
    for line in text.splitlines():
        fields = line.split()
        require(len(fields) == 5 and fields[0] in ("some", "full") and fields[0] not in result, "Invalid I/O PSI line")
        pairs = [field.split("=") for field in fields[1:]]
        require(all(len(pair) == 2 for pair in pairs), "Invalid I/O PSI value")
        values = dict(pairs)
        require(set(values) == {"avg10", "avg60", "avg300", "total"}, "Unknown I/O PSI fields")
        row = {key: float(values[key]) for key in ("avg10", "avg60", "avg300")}
        require(all(math.isfinite(value) and 0 <= value <= 100 for value in row.values()), "Invalid I/O PSI percentage")
        row["total_us"] = nonnegative_integer(values["total"])
        result[fields[0]] = row
    require(set(result) == {"some", "full"}, "Missing I/O PSI scope")
    return result


def parse_cpu(text):
    aggregate = [line.split()[1:] for line in text.splitlines() if line.startswith("cpu ")]
    boot = [line.split()[1:] for line in text.splitlines() if line.startswith("btime ")]
    require(len(aggregate) == 1 and len(aggregate[0]) == 10 and len(boot) == 1 and len(boot[0]) == 1,
            "Missing or unknown aggregate CPU counters/boot time")
    return {"ticks": dict(zip(CPU_NAMES, map(nonnegative_integer, aggregate[0]))),
            "boot_time_unix_seconds": nonnegative_integer(boot[0][0])}


def read_kernel_text(path):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "Kernel input is not a regular text interface")
        raw = stream.read(1024 * 1024 + 1)
    require(len(raw) <= 1024 * 1024, "Kernel text input exceeded bound")
    return raw.decode("ascii")


def device_identity():
    info = os.stat(BLOCK)
    return {"resolved_stat_path": os.path.realpath(BLOCK), "stat_inode": info.st_ino, "stat_device": info.st_dev}


def counters(sample):
    result = {"block." + key: value for key, value in sample["block"].items() if key != "in_flight"}
    result.update({"io_pressure." + scope + ".total_us": row["total_us"] for scope, row in sample["io_pressure"].items()})
    result.update({"cpu." + key: value for key, value in sample["cpu"]["ticks"].items()})
    return result


def decreases(previous, current):
    before, after = counters(previous), counters(current)
    require(before.keys() == after.keys(), "Counter schema changed between observations")
    return [{"counter": key, "previous": before[key], "current": value,
             "cause": "iowait_can_decrease_without_reset" if key == "cpu.iowait" else "reset_wrap_or_other_decrease_unresolved"}
            for key, value in after.items() if value < before[key]]


def stamp():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def plan(seconds):
    return {"artifact": "aotg-supplemental-io-plan", "version": 1, "sample_requested": False,
            "sources": [BLOCK, PRESSURE, CPU], "interval_seconds": 1, "wall_budget_seconds": seconds,
            "maximum_seconds": MAX_SECONDS, "maximum_records": MAX_RECORDS,
            "maximum_output_bytes": MAX_OUTPUT_BYTES, "maximum_line_bytes": MAX_LINE_BYTES, "final_record_reserve_seconds": .25,
            "output": "stdout JSONL only", "sector_bytes": 512,
            "counter_semantics": "Raw cumulative counters except block.in_flight gauge and PSI average percentages; no rates computed",
            "cpu_tick_unit": "SC_CLK_TCK; guest/guest_nice already included in user/nice; iowait may decrease",
            "correlation": "UTC at read start/end and monotonic_ns bracket sequential reads; not one atomic host snapshot",
            "coverage": "First sample is observed baseline. Inspect actual sample timestamps; missing final record means incomplete capture",
            "interpretation": "Host/device totals include unrelated activity. Decreases do not prove a reset. These counters alone do not prove saturation or bottleneck cause",
            "references": ["https://docs.kernel.org/block/stat.html", "https://docs.kernel.org/admin-guide/iostats.html",
                           "https://docs.kernel.org/accounting/psi.html", "https://docs.kernel.org/filesystems/proc.html"]}


def emit(row, deadline, stopped=None, output_state=None):
    payload = memoryview((json.dumps(row, sort_keys=True, allow_nan=False) + "\n").encode("ascii"))
    require(len(payload) <= MAX_LINE_BYTES, "Output record exceeds fixed bound")
    if output_state is not None:
        require(output_state[0] + len(payload) <= MAX_OUTPUT_BYTES, "Output exceeds fixed bound")
        output_state[0] += len(payload)
    while payload:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or (stopped is not None and stopped[0]):
            raise TimeoutError("Output interrupted or unavailable before deadline")
        if not select.select([], [sys.stdout.fileno()], [], min(.05, remaining))[1]:
            continue
        try:
            count = os.write(sys.stdout.fileno(), payload)
        except BlockingIOError:
            continue
        if not count:
            raise BrokenPipeError("Output sink closed")
        payload = payload[count:]


def sample(seconds, run_id, binding_sha256):
    seconds = duration(seconds)
    require(isinstance(run_id, str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{1,95}", run_id), "Explicit bounded run ID required")
    require(isinstance(binding_sha256, str) and re.fullmatch(r"[0-9a-f]{64}", binding_sha256), "Capture binding SHA required")
    association = {"run_id": run_id, "capture_binding_sha256": binding_sha256}
    output_state = [0]
    started = time.monotonic()
    hard_deadline = started + seconds
    collection_deadline = hard_deadline - .25
    stopped = [None]
    previous = identity = None
    count = reset_observations = 0
    reason, error, code = "deadline", None, 0
    previous_handlers = {}
    was_blocking = os.get_blocking(sys.stdout.fileno())
    try:
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            previous_handlers[sig] = signal.signal(sig, lambda number, _frame: stopped.__setitem__(0, number))
        os.set_blocking(sys.stdout.fileno(), False)
        metadata = {**plan(seconds), **association, "sample_requested": True, "utc": stamp(), "monotonic_ns": time.monotonic_ns(),
                    "cpu_ticks_per_second": os.sysconf("SC_CLK_TCK")}
        emit(metadata, min(collection_deadline, time.monotonic() + .25), stopped, output_state)
        next_sample = started
        while not stopped[0] and time.monotonic() < collection_deadline:
            if time.monotonic() < next_sample:
                time.sleep(max(0, min(.1, next_sample - time.monotonic())))
                continue
            row = {**association, "artifact": "aotg-supplemental-io-sample", "version": 1, "index": count,
                   "observed_baseline": count == 0, "utc_read_start": stamp(), "monotonic_read_start_ns": time.monotonic_ns()}
            before = device_identity()
            if identity is not None:
                require(before == identity, "Block device identity changed since baseline")
            row.update(block=parse_block(read_kernel_text(BLOCK)), io_pressure=parse_pressure(read_kernel_text(PRESSURE)),
                       cpu=parse_cpu(read_kernel_text(CPU)))
            require(device_identity() == before, "Block device identity changed during read")
            identity = before
            row.update(device_identity=identity, utc_read_end=stamp(), monotonic_read_end_ns=time.monotonic_ns())
            if previous is not None:
                require(row["cpu"]["boot_time_unix_seconds"] == previous["cpu"]["boot_time_unix_seconds"], "Host boot identity changed")
            row["counter_decreases"] = decreases(previous, row) if previous is not None else []
            row["counter_reset_or_decrease_detected"] = bool(row["counter_decreases"])
            reset_observations += int(bool(row["counter_decreases"]))
            emit(row, min(collection_deadline, time.monotonic() + .25), stopped, output_state)
            previous = row
            count += 1
            # Skip missed slots; never issue catch-up sampling bursts.
            next_sample = started + math.floor(time.monotonic() - started) + 1
        if stopped[0]:
            reason, code = "signal", 128 + stopped[0]
    except (OSError, ValueError, RuntimeError) as failure:
        if stopped[0]:
            reason, code = "signal", 128 + stopped[0]
        else:
            reason, error, code = "observation_or_output_error", str(failure)[:512], 2
    finally:
        final = {**association, "artifact": "aotg-supplemental-io-final", "version": 1, "reason": reason, "signal": stopped[0],
                 "error": error, "emitted_samples": count, "observations_with_counter_decreases": reset_observations,
                 "utc": stamp(), "monotonic_ns": time.monotonic_ns(), "elapsed_seconds": time.monotonic() - started,
                 "complete_to_configured_deadline": reason == "deadline" and count > 0}
        try:
            emit(final, min(hard_deadline, time.monotonic() + .25), output_state=output_state)
        except (OSError, ValueError):
            code = code or 2
        os.set_blocking(sys.stdout.fileno(), was_blocking)
        for sig, handler in previous_handlers.items():
            signal.signal(sig, handler)
    return code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", action="store_true", help="Explicitly start read-only kernel counter observation")
    parser.add_argument("--seconds", type=duration, default=MAX_SECONDS)
    parser.add_argument("--run-id")
    parser.add_argument("--capture-binding-sha256")
    args = parser.parse_args()
    if not args.sample:
        print(json.dumps(plan(args.seconds), sort_keys=True, indent=2))
        return 0
    return sample(args.seconds, args.run_id, args.capture_binding_sha256)


if __name__ == "__main__":
    raise SystemExit(main())
