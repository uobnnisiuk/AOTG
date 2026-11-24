"""Offline observation-only accounting reconciliation, not a collector or grader.

Inputs must be the bytes of one bounded recovered journal and its separately
transported adapter summary, bound to the same run by a trusted caller. Counts
and canonical JSON do not authenticate bytes or prove fsync/restore/quality.
No filesystem, subprocess, hardware or live reader access.
"""
import json

MAX_ROWS = 59072
MAX_BYTES = 130394112
MAX_LINE = 16384
MAX_SUMMARY = 8192


def _unique(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate-key")
        out[key] = value
    return out


def _constant(_):
    raise ValueError("nonfinite-json")


def _object(raw):
    obj = json.loads(raw.decode("ascii"), object_pairs_hook=_unique,
                     parse_constant=_constant)
    if type(obj) is not dict:
        raise ValueError("not-object")
    return obj


def reconcile(raw, summary_bytes, *, expected_run_id):
    """Compare a confirmed prefix and any uncertain tail without promoting it.

    All results are unqualified. Even a stopped run can have consistent
    accounting, which does not mean the experiment or restoration succeeded.
    A failed flush may leave visible bytes: never count them as confirmed.
    """
    result = {"status": "incomplete", "reason": None,
              "runtime_qualified": False, "quality_accepted": False}

    def finish(reason, consistent=False):
        return {**result, "reason": reason,
                "status": "accounting-consistent" if consistent else "incomplete"}

    if type(expected_run_id) is not str or not 1 <= len(expected_run_id) <= 64:
        return finish("invalid-run-id")
    if type(raw) is not bytes or len(raw) > MAX_BYTES:
        return finish("invalid-or-oversize-journal")
    if type(summary_bytes) is not bytes or not 1 <= len(summary_bytes) <= MAX_SUMMARY:
        return finish("missing-or-oversize-summary")
    try:
        s = _object(summary_bytes)
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        return finish("invalid-summary-json")
    if (s.get("artifact") != "aotg-offline-serialized-budget"
            or type(s.get("version")) is not int or s["version"] != 1
            or type(s.get("adapter_version")) is not int or s["adapter_version"] != 1
            or s.get("runtime_qualified") is not False
            or "stopped_reason" not in s):
        return finish("invalid-summary-schema")
    stopped = s["stopped_reason"]
    if ((stopped is not None and (type(stopped) is not str or not stopped))
            or s.get("status") != ("incomplete-stopped" if stopped is not None
                                   else "incomplete-unverified-runtime")):
        return finish("invalid-summary-status")
    prefixes = ("admitted_", "flush_confirmed_", "unconfirmed_admitted_")
    for unit, cap in (("rows", MAX_ROWS), ("bytes", MAX_BYTES)):
        names = (unit,) + tuple(prefix + unit for prefix in prefixes)
        if any(type(s.get(key)) is not int or not 0 <= s[key] <= cap for key in names):
            return finish("invalid-accounting-counter")
        total, admitted, confirmed, uncertain = (s[key] for key in names)
        if total != admitted or confirmed + uncertain != admitted:
            return finish("contradictory-accounting")
    ar, ab = s["admitted_rows"], s["admitted_bytes"]
    cr, cb = s["flush_confirmed_rows"], s["flush_confirmed_bytes"]
    ur, ub = s["unconfirmed_admitted_rows"], s["unconfirmed_admitted_bytes"]
    for rows, size in ((ar, ab), (cr, cb), (ur, ub)):
        if not 3 * rows <= size <= MAX_LINE * rows:
            return finish("impossible-accounting-size")
    result.update(admitted_rows=ar, admitted_bytes=ab, flush_confirmed_rows=cr,
                  flush_confirmed_bytes=cb, unconfirmed_admitted_rows=ur,
                  unconfirmed_admitted_bytes=ub, recovered_bytes=len(raw))
    if not cb <= len(raw) <= ab:
        return finish("recovered-byte-count-mismatch")
    # Bound allocations to one line, rather than splitting a 124 MiB journal.
    offset = rows = 0
    while offset < cb:
        end = raw.find(b"\n", offset, min(cb, offset + MAX_LINE))
        if end < 0:
            return finish("confirmed-prefix-line-boundary")
        if rows >= cr:
            return finish("confirmed-prefix-row-count")
        line = raw[offset:end + 1]
        try:
            obj = _object(line)
            canonical = (json.dumps(obj, ensure_ascii=True, sort_keys=True,
                                    allow_nan=False, separators=(",", ":")) + "\n").encode("ascii")
        except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
            return finish("invalid-confirmed-json")
        if canonical != line:
            return finish("noncanonical-confirmed-json")
        if obj.get("run_id") != expected_run_id:
            return finish("confirmed-run-id-mismatch")
        if rows == 0 and obj.get("phase") != "startup-anchor":
            return finish("missing-startup-anchor")
        rows += 1
        offset = end + 1
    if rows != cr:
        return finish("confirmed-prefix-row-count")
    if raw.count(b"\n", cb) > ur:
        return finish("uncertain-tail-row-count")
    if ur or ub:
        return finish("unconfirmed-admission")
    if not cr:
        return finish("empty-confirmed-journal")
    return finish("counts-and-confirmed-prefix-consistent", consistent=True)
