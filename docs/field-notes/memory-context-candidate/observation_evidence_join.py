"""Pure offline join of two recovered observation artifacts.

The caller supplies an independently trusted manifest binding both byte strings
to a fixed run and plan. Hash matching is not producer authentication or proof
that the manifest itself is trustworthy. No IO, recovery or deployment occurs.
"""
import hashlib
import io
import json
import re

import observation_reconciliation as accounting
import verify_observation_journal as reader


def _digest(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _entry(entry, cap):
    return (type(entry) is dict and _digest(entry.get("sha256"))
            and type(entry.get("bytes")) is int and 1 <= entry["bytes"] <= cap)


def join_observation(raw, summary_bytes, *, trusted_manifest,
                     expected_run_id, expected_plan_sha256):
    """Require matching manifest, complete accounting, strict chain and stop reason.

    The caller retains original bytes, even on rejection. No status qualifies
    runtime, restoration, quality or retry. The manifest is a distinct trusted
    input, not reconstructed from the untrusted returned artifacts.
    """
    out = {"status": "incomplete", "reason": None,
           "runtime_qualified": False, "independent_restore_verified": False,
           "quality_accepted": False, "authorizes_retry": False,
           "root_cause_proven": False}

    def finish(reason, consistent=False):
        return {**out, "reason": reason,
                "status": "joined-observation-consistent" if consistent else "incomplete"}

    if (type(expected_run_id) is not str or not 1 <= len(expected_run_id) <= 64
            or not _digest(expected_plan_sha256)):
        return finish("invalid-expected-identity")
    m = trusted_manifest
    if (type(m) is not dict or m.get("artifact") != "aotg-observation-recovery-manifest"
            or type(m.get("version")) is not int or m["version"] != 1
            or m.get("run_id") != expected_run_id
            or m.get("plan_sha256") != expected_plan_sha256):
        return finish("manifest-run-plan-mismatch")
    j, s = m.get("journal"), m.get("adapter_summary")
    if (not _entry(j, accounting.MAX_BYTES) or not _entry(s, accounting.MAX_SUMMARY)
            or type(j.get("rows")) is not int or not 1 <= j["rows"] <= accounting.MAX_ROWS):
        return finish("invalid-manifest-artifact")
    if type(raw) is not bytes or not 1 <= len(raw) <= accounting.MAX_BYTES:
        return finish("invalid-recovered-journal")
    if type(summary_bytes) is not bytes or not 1 <= len(summary_bytes) <= accounting.MAX_SUMMARY:
        return finish("invalid-recovered-summary")
    out.update(journal_sha256=hashlib.sha256(raw).hexdigest(),
               summary_sha256=hashlib.sha256(summary_bytes).hexdigest(),
               recovered_bytes=len(raw), recovered_rows=raw.count(b"\n"),
               recovered_summary_bytes=len(summary_bytes))
    if (out["journal_sha256"] != j["sha256"] or len(raw) != j["bytes"]
            or out["recovered_rows"] != j["rows"]):
        return finish("journal-manifest-mismatch")
    if out["summary_sha256"] != s["sha256"] or len(summary_bytes) != s["bytes"]:
        return finish("summary-manifest-mismatch")
    a = accounting.reconcile(raw, summary_bytes, expected_run_id=expected_run_id)
    out["accounting"] = a
    if a["status"] != "accounting-consistent":
        return finish("accounting:" + a["reason"])
    try:
        # The reader uses the adapter's actual configured 128 MiB/60,001 caps
        # for reservation semantics; accounting applies the tighter derived
        # maximum serialized output independently. Do not substitute one for the other.
        chain = reader.verify_stream(io.BytesIO(raw), expected_run_id=expected_run_id)
    except reader.JournalIntegrityError as exc:
        return finish("strict-journal:" + str(exc))
    out["strict_journal"] = chain
    if (chain["raw_sha256"] != j["sha256"] or chain["bytes"] != j["bytes"]
            or chain["rows"] != j["rows"]
            or chain["rows"] != a["flush_confirmed_rows"]
            or chain["bytes"] != a["flush_confirmed_bytes"]):
        return finish("strict-accounting-mismatch")
    # reconcile already checked bounded JSON, duplicate keys and summary schema.
    summary = json.loads(summary_bytes)
    for key, value in (("primary_ticks", chain["primary_ticks"]),
                       ("context_ticks", chain["context_rows"]),
                       ("context_attempts", chain["context_rows"]),
                       ("context_skipped_interval", chain["context_skipped_interval"]),
                       ("context_skipped_guard", chain["context_skipped_guard"])):
        if type(summary.get(key)) is not int or summary[key] != value:
            return finish("summary-chain-counter-mismatch")
    # A structurally closed chain has no unresolved producer reservation.
    # A forced tick is not separately encoded in the journal; check its
    # reported type and bounds, not an unprovable exact forced count.
    for key in ("reserved_rows", "reserved_bytes"):
        if type(summary.get(key)) is not int or summary[key] != 0:
            return finish("summary-unresolved-reservation")
    for key, quota in (("primary_hard_quota", reader.MAX_PRIMARY),
                       ("context_hard_quota", reader.MAX_CONTEXT),
                       ("forced_hard_quota", 65)):
        if type(summary.get(key)) is not int or summary[key] != quota:
            return finish("summary-fixed-quota-mismatch")
    forced = summary.get("forced_samples")
    if type(forced) is not int or not 0 <= forced <= min(65, chain["primary_ticks"]):
        return finish("summary-forced-count-out-of-bounds")
    terminal = chain["terminal_stop_reason"]
    stop = summary["stopped_reason"]
    out.update(terminal_stop_reason=terminal, summary_stopped_reason=stop)
    if terminal != stop:
        # A stop outside a terminal guard (e.g. deadline after a flushed
        # context) requires additional evidence. Do not promote that prefix.
        return finish("terminal-summary-mismatch")
    return finish("strict-chain-and-accounting-consistent", consistent=True)
