"""Bounded independent reader of PR38's compact *synthetic* observation JSONL.

Checks raw byte/record limits, canonical line encoding and local linkage only.
It cannot establish the identity of a live guard, durability, restore, or quality.
No subprocess, file writing, /proc, network or private worker imports.
"""

import hashlib
import json

MAX_LINE = 16_384
MAX_BYTES = 128 * 1024 * 1024
MAX_ROWS = 60_001
MAX_PRIMARY = 28_200
MAX_CONTEXT = 2_671
CAPS = {"startup": 2_048, "observed": 2_048, "guard": 1_024,
        "context": 16_384}
PASS_SKIPS = {"interval-skipped-no-context", "deadline-headroom-skipped-no-context",
              "context-attempt-quota", "context-capacity-refused"}


class JournalIntegrityError(ValueError):
    """An invalid or incomplete serialized observation chain."""


def _unique_pairs(pairs):
    output = {}
    for key, value in pairs:
        if key in output:
            raise JournalIntegrityError("duplicate-json-key")
        output[key] = value
    return output


def _reject_constant(_):
    raise JournalIntegrityError("nonfinite-json")


def verify_stream(stream, *, expected_run_id):
    """Read a binary stream once; never label synthetics as runtime-qualified.

    expected_run_id comes from a separately trusted run manifest. Every
    synthetic record must carry the same ID. This is structural matching,
    not producer authentication or proof of runtime execution.
    """
    if not isinstance(expected_run_id, str) or not 1 <= len(expected_run_id) <= 64:
        raise ValueError("expected-run-id-required")
    state = "startup"
    total = rows = primary = contexts = 0
    rejected = False
    pending_sha = None
    pending_seq = None
    file_hash = hashlib.sha256()
    while True:
        raw = stream.readline(MAX_LINE + 1)
        if not raw:
            break
        if not isinstance(raw, bytes):
            raise JournalIntegrityError("binary-stream-required")
        total += len(raw)
        rows += 1
        if rows > MAX_ROWS or total > MAX_BYTES:
            raise JournalIntegrityError("aggregate-budget-exceeded")
        if len(raw) > MAX_LINE or not raw.endswith(b"\n") or raw.endswith(b"\r\n"):
            raise JournalIntegrityError("oversized-or-truncated-jsonl")
        if state == "done":
            raise JournalIntegrityError("record-after-rejected-guard")
        if len(raw) > CAPS[state]:
            raise JournalIntegrityError("phase-line-cap")
        try:
            record = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_pairs,
                                parse_constant=_reject_constant)
            canonical = (json.dumps(record, ensure_ascii=True, sort_keys=True,
                                    allow_nan=False, separators=(",", ":")) + "\n").encode("ascii")
        except (UnicodeError, ValueError, TypeError, OverflowError, RecursionError) as exc:
            raise JournalIntegrityError("invalid-jsonl") from exc
        if not isinstance(record, dict) or canonical != raw:
            raise JournalIntegrityError("noncanonical-jsonl")
        if record.get("run_id") != expected_run_id:
            raise JournalIntegrityError("record-run-id-unbound")
        file_hash.update(raw)
        if state == "startup":
            if record.get("phase") != "startup-anchor":
                raise JournalIntegrityError("missing-startup-anchor")
            state = "observed"
        elif state == "observed":
            if record.get("phase") != "observed" or type(record.get("sequence")) is not int or record["sequence"] != primary:
                raise JournalIntegrityError("observed-sequence-or-phase")
            if primary >= MAX_PRIMARY:
                raise JournalIntegrityError("primary-quota")
            pending_seq = primary
            pending_sha = hashlib.sha256(raw).hexdigest()
            state = "guard"
        elif state == "guard":
            schedule = record.get("context_schedule")
            if (record.get("phase") != "guard-result" or type(record.get("sequence")) is not int
                    or record["sequence"] != pending_seq or record.get("primary_sha256") != pending_sha
                    or "sample" in record or "anchor" in record or type(schedule) is not dict):
                raise JournalIntegrityError("guard-primary-binding")
            verdict = record.get("guard_verdict")
            reason = schedule.get("reason")
            if (type(schedule.get("attempts_before")) is not int
                    or schedule["attempts_before"] != contexts
                    or type(schedule.get("interval_skips")) is not int
                    or schedule["interval_skips"] < 0):
                raise JournalIntegrityError("guard-scheduler-metadata")
            primary += 1
            if verdict == "rejected" and reason == "guard-rejected-no-context":
                rejected = True
                state = "done"
            elif verdict == "passed" and reason == "context-selected":
                state = "context"
            elif verdict == "passed" and reason in PASS_SKIPS:
                state = "observed"
            else:
                raise JournalIntegrityError("guard-schedule-contradiction")
        elif state == "context":
            if (record.get("artifact") != "aotg-memory-context-link" or type(record.get("version")) is not int
                    or record["version"] != 1 or record.get("run_id") != expected_run_id
                    or type(record.get("sequence")) is not int or record["sequence"] != pending_seq
                    or record.get("primary_sha256") != pending_sha or type(record.get("context")) is not dict):
                raise JournalIntegrityError("context-primary-binding")
            contexts += 1
            if contexts > MAX_CONTEXT:
                raise JournalIntegrityError("context-quota")
            state = "observed"
    if state in ("startup", "guard", "context") or (state == "observed" and primary == 0):
        raise JournalIntegrityError("missing-startup-verdict-or-selected-context")
    return {"status": "incomplete-unverified-runtime", "structure_consistent": True,
            "run_id_bound": True,
            "runtime_qualified": False, "authorizes_retry": False,
            "root_cause_proven": False, "rejected_guard_recorded": rejected,
            "primary_ticks": primary, "context_rows": contexts, "rows": rows,
            "bytes": total, "raw_sha256": file_hash.hexdigest()}
