"""Validate bounded proxy-observable tool intervals; no task score or authority."""
import math
import re


class ToolMetricError(ValueError):
    pass


def need(value, reason):
    if not value:
        raise ToolMetricError(reason)


def exact(value, fields, reason):
    need(isinstance(value, dict) and set(value) == set(fields.split()), reason)


def number(value):
    need(type(value) in (int, float) and math.isfinite(value) and value >= 0, "invalid_monotonic_time")
    return value


def digest(value):
    need(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value), "invalid_digest")
    return value


def call(value):
    exact(value, "call_index tool_call_id_sha256", "invalid_call_schema")
    need(type(value["call_index"]) is int and 0 <= value["call_index"] < 32, "invalid_call_index")
    digest(value["tool_call_id_sha256"])


def source_call(value, current_index):
    exact(value, "call_index tool_call_id_sha256 source_request_index source_response_sha256 response_completed_seconds",
          "source_call_schema_invalid")
    call({key: value[key] for key in ("call_index", "tool_call_id_sha256")})
    need(type(value["source_request_index"]) is int and 0 <= value["source_request_index"] < current_index,
         "source_request_index_invalid")
    digest(value["source_response_sha256"])
    number(value["response_completed_seconds"])


ERRORS = {
    "tool_calls_shape_or_limit", "tool_call_index_invalid", "tool_call_id_invalid",
    "tool_call_id_limit", "tool_call_id_missing", "tool_call_id_ambiguous",
    "tool_result_id_missing_or_invalid", "tool_call_response_incomplete", "tool_call_id_reused",
    "monotonic_order_invalid",
}
UNMATCHED = {"request_body_unavailable", "tool_result_id_missing_or_invalid", "tool_result_missing",
             "tool_result_ambiguous", "monotonic_order_invalid"}


def tool_roundtrip_diagnostics(requests):
    """Requests must also pass their enclosing v2 capture/source/transport checks.

    Missing producer data are incomplete, never zero-duration samples. Conflicting
    bindings raise. This validates recorded observations, not their external origin.
    """
    need(isinstance(requests, list) and len(requests) <= 128, "request_limit")
    previous, intervals, unresolved, unavailable, seen = [], [], [], [], set()
    call_count, latest = 0, 0
    for index, request in enumerate(requests):
        need(isinstance(request, dict) and type(request.get("index")) is int
             and request["index"] == index, "request_sequence_invalid")
        metric = request.get("tool_roundtrip")
        if metric is None:
            unavailable.append({"request_index": index, "reason": "metric_record_missing"})
            unresolved.extend({**source, "reason": "metric_record_missing"} for source in previous)
            previous = []
            continue
        exact(metric, "artifact version boundary clock request_received_seconds expected_calls matches unmatched_calls "
              "tool_result_message_count input_status response_calls response_completed_seconds response_status errors",
              "metric_schema_invalid")
        need(metric["artifact"] == "aotg-proxy-tool-roundtrip" and type(metric["version"]) is int
             and metric["version"] == 1 and metric["boundary"] == "response-done-flushed-to-next-request-body-received"
             and metric["clock"] == "proxy-relative-monotonic-seconds", "metric_protocol_invalid")
        need(isinstance(metric["errors"], list) and len(metric["errors"]) <= 16
             and all(isinstance(reason, str) and reason in ERRORS for reason in metric["errors"]), "metric_errors_invalid")
        need(isinstance(metric["expected_calls"], list) and len(metric["expected_calls"]) <= 32, "expected_call_limit")
        for source in metric["expected_calls"]:
            source_call(source, index)
        need(metric["expected_calls"] == previous, "adjacent_response_binding_mismatch")
        need(metric["input_status"] in ("observed", "incomplete", "unavailable"), "input_status_invalid")
        received = metric["request_received_seconds"]
        if metric["input_status"] == "unavailable":
            need(received is None and metric["tool_result_message_count"] is None, "unavailable_body_claimed_observed")
        else:
            number(received)
            need(received >= latest, "request_clock_reversed")
            latest = received
            need(type(metric["tool_result_message_count"]) is int
                 and 0 <= metric["tool_result_message_count"] <= 1024 * 1024, "tool_result_count_invalid")
        for name in ("matches", "unmatched_calls", "response_calls"):
            need(isinstance(metric[name], list) and len(metric[name]) <= 32, "call_list_limit")
        partition = {}
        for row in metric["matches"]:
            exact(row, "call_index tool_call_id_sha256 source_request_index source_response_sha256 "
                  "response_completed_seconds tool_result_received_seconds seconds", "match_schema_invalid")
            source = {key: row[key] for key in ("call_index", "tool_call_id_sha256", "source_request_index",
                       "source_response_sha256", "response_completed_seconds")}
            source_call(source, index)
            number(row["tool_result_received_seconds"])
            need(source in previous and source["tool_call_id_sha256"] not in partition, "match_source_binding_mismatch")
            need(metric["input_status"] == "observed" and received is not None
                 and row["tool_result_received_seconds"] == received, "match_receiver_binding_mismatch")
            number(row["seconds"])
            need(row["seconds"] == received - source["response_completed_seconds"], "interval_mismatch")
            partition[source["tool_call_id_sha256"]] = "matched"
            intervals.append({**row, "result_request_index": index})
        for row in metric["unmatched_calls"]:
            exact(row, "call_index tool_call_id_sha256 source_request_index source_response_sha256 "
                  "response_completed_seconds reason", "unmatched_schema_invalid")
            source = {key: row[key] for key in row if key != "reason"}
            source_call(source, index)
            need(source in previous and source["tool_call_id_sha256"] not in partition
                 and row["reason"] in UNMATCHED, "unmatched_source_binding_mismatch")
            partition[source["tool_call_id_sha256"]] = "unmatched"
            unresolved.append(row)
        need(len(partition) == len(previous), "missing_source_call_partition")
        need(not metric["matches"] or metric["tool_result_message_count"] >= len(metric["matches"]),
             "tool_result_count_contradicts_matches")
        if metric["input_status"] != "observed" or metric["errors"]:
            unavailable.append({"request_index": index, "reason": "metric_input_or_protocol_incomplete",
                                "input_status": metric["input_status"], "errors": metric["errors"]})
        previous = []
        status = metric["response_status"]
        need(status in ("observed", "no_tool_calls", "incomplete"), "response_status_invalid")
        if status == "observed":
            need(set(metric["errors"]) <= {"tool_result_id_missing_or_invalid"}, "outgoing_error_claimed_observed")
            need(request.get("status") == "completed" and request.get("finish_reason") == "tool_calls"
                 and request.get("sse_done") is True and metric["response_calls"], "outgoing_response_not_complete")
            response_hash = digest(request.get("response_sha256"))
            completed = number(metric["response_completed_seconds"])
            need(received is not None and completed >= received and completed >= latest, "response_clock_reversed")
            latest = completed
            indices, identities = set(), set()
            for row in metric["response_calls"]:
                call(row)
                need(row["call_index"] not in indices and row["tool_call_id_sha256"] not in identities
                     and row["tool_call_id_sha256"] not in seen, "outgoing_call_duplicate_or_reused")
                indices.add(row["call_index"])
                identities.add(row["tool_call_id_sha256"])
                previous.append({**row, "source_request_index": index, "source_response_sha256": response_hash,
                                 "response_completed_seconds": completed})
            need([row["call_index"] for row in metric["response_calls"]] == sorted(indices), "outgoing_order_invalid")
            seen.update(identities)
            call_count += len(previous)
        else:
            need(metric["response_calls"] == [] and metric["response_completed_seconds"] is None,
                 "unavailable_response_claimed_observed")
            if status == "no_tool_calls":
                need(request.get("status") == "completed" and request.get("finish_reason") == "stop"
                     and request.get("sse_done") is True, "non_tool_response_incomplete")
            else:
                unavailable.append({"request_index": index, "reason": "tool_call_response_incomplete"})
    unresolved.extend({**row, "reason": "final_response_without_next_request"} for row in previous)
    complete = bool(intervals) and not unresolved and not unavailable
    return {"artifact": "aotg-tool-roundtrip-diagnostics", "version": 1,
            "boundary": "response-done-flushed-to-next-request-body-received",
            "status": "observed" if complete else "incomplete" if unresolved or unavailable else "not_observed",
            "measurement_complete": complete, "request_count": len(requests),
            "source_call_count": call_count, "matched_call_count": len(intervals),
            "unmatched_call_count": len(unresolved), "intervals": intervals,
            "unmatched_calls": unresolved, "unavailable": unavailable,
            "external_capture_identity_verified": False, "quality_accepted": False,
            "task_scalar_computed": False, "performance_adoption_gate": False}
