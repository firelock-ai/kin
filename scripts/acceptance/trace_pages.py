#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
"""Strict trace-page transport for acceptance probes, preserving semantic fields."""
import json
import os
import selectors
import subprocess
import tempfile
import time


class TraceAnswer(dict):
    """Reconstructed evidence with out-of-band observations of the raw pages."""
    page_bytes = ()
    page_ceilings = ()
    page_observations = ()


def drain_trace(fetch, requested=None):
    """fetch(cursor) returns (decoded page, exact emitted JSON text)."""
    return _drain_pages(fetch, requested, "chain")


def drain_references(fetch, requested=None):
    """Reconstruct reference records and their original safety readings."""
    return _drain_pages(fetch, requested, "references")


def _drain_pages(fetch, requested, primary):
    result, rows, fields, fragments, seen, sizes, ceilings = {}, {}, {}, {}, set(), [], []
    cursor = None
    observations = []
    collections = (("chain", "candidates", "more_candidates", "target_candidates")
                   if primary == "chain" else
                   ("references", "candidates", "interface_dispatch.candidates",
                    "call_sites.candidates", "candidates_by_owner", "target_candidates"))

    def record(collection, key, value):
        if collection == "readings":
            if key in result:
                raise ValueError("trace reading appeared twice: %s" % key)
            result[key] = value
        else:
            if collection not in collections:
                raise ValueError("unknown semantic collection: %s" % collection)
            rows.setdefault(collection, []).append(value)

    for _ in range(10000):
        page, wire = fetch(cursor)
        metadata = (page.get("_kin") or {}).get("page") or {}
        if metadata.get("version") != 1:
            raise ValueError("trace response is missing its page contract")
        if primary == "references" and metadata.get("kind") != "references":
            raise ValueError("reference response has another page kind")
        accounting = page["_kin"].get("response") or {}
        ceiling = accounting.get("max_chars")
        size = len(wire.encode("utf-8"))
        if not isinstance(ceiling, int) or not 2000 <= ceiling <= 60000:
            raise ValueError("trace page reports an invalid byte ceiling")
        if requested is not None and ceiling != max(2000, min(60000, requested)):
            raise ValueError("trace page did not honor the requested byte ceiling")
        if size > ceiling or accounting.get("chars_after_budget") != size:
            raise ValueError("trace page wire bytes disagree with its bound/accounting")
        sizes.append(size)
        ceilings.append(ceiling)
        observations.append({"page": dict(metadata),
                             "verdict": dict(page["_kin"].get("verdict") or {}),
                             "negative": dict(page.get("negative") or {})})
        if metadata.get("complete") is True:
            if cursor is not None or page.get("next_cursor") is not None:
                raise ValueError("complete trace cannot occur inside a continuation")
            factors = ((page["_kin"].get("verdict") or {}).get("limiting_factor") or "")
            labels = {clause.strip().split(":", 1)[0] for clause in factors.split(";")}
            if labels.intersection(("trace_page_partial", "reference_page_partial")):
                raise ValueError("complete response carries a partial-page verdict")
            answer = TraceAnswer(page)
            answer.page_bytes = tuple(sizes)
            answer.page_ceilings = tuple(ceilings)
            answer.page_observations = tuple(observations)
            return answer
        if (page.get("negative") or {}).get("safe_to_conclude_absent") is not False:
            raise ValueError("an individual trace page certifies absence")
        verdict = page["_kin"].get("verdict") or {}
        if verdict.get("safe_to_conclude_absent") is not False or verdict.get("state") != "inconclusive":
            raise ValueError("an individual trace page has an unqualified verdict")
        for collection in collections:
            values = page
            for part in collection.split("."):
                values = values.get(part) if isinstance(values, dict) else None
            for value in values or []:
                record(collection, None, value)
        for reading in page.get("readings") or []:
            record("readings", reading["key"], reading["value"])
        fragment = page.get("record_fragment")
        if fragment:
            address = (fragment["collection"], fragment["index"])
            field = fragment.get("field")
            key = address + (field,)
            accumulated = fragments.get(key, "")
            if len(accumulated.encode("utf-8")) != fragment["byte_offset"]:
                raise ValueError("trace fragment offset has a gap or overlap")
            accumulated += fragment["text"]
            fragments[key] = accumulated
            if fragment["field_complete"]:
                if len(accumulated.encode("utf-8")) != fragment["total_bytes"]:
                    raise ValueError("trace field completed at the wrong byte count")
                encoding = fragment["encoding"]
                if encoding not in ("utf8", "json_utf8"):
                    raise ValueError("unknown trace fragment encoding")
                value = accumulated if encoding == "utf8" else json.loads(accumulated)
                del fragments[key]
                if field is not None:
                    assembled = fields.setdefault(address, {})
                    if field in assembled:
                        raise ValueError("trace field appeared twice")
                    assembled[field] = value
                    if fragment["record_complete"]:
                        value = fields.pop(address)
                if field is None or fragment["record_complete"]:
                    record(address[0], fragment.get("key"), value)
        cursor = page.get("next_cursor")
        if cursor is None:
            if fields or fragments:
                raise ValueError("trace ended with unfinished semantic fields")
            target = rows.pop("target_candidates", None)
            for collection, values in rows.items():
                destination = result
                path = collection.split(".")
                for part in path[:-1]:
                    destination = destination.setdefault(part, {})
                if path[-1] in destination:
                    raise ValueError("semantic collection appeared in both readings and rows")
                destination[path[-1]] = values
            result.setdefault(primary, [])
            if target is not None:
                result.setdefault("target_ambiguity", {})["candidates"] = target
            count = "total_steps" if primary == "chain" else "total_references"
            if len(result[primary]) != metadata.get(count):
                raise ValueError("trace continuation lost chain steps" if primary == "chain"
                                 else "reference continuation lost caller rows")
            answer = TraceAnswer(result)
            answer.page_bytes = tuple(sizes)
            answer.page_ceilings = tuple(ceilings)
            answer.page_observations = tuple(observations)
            return answer
        if not isinstance(cursor, str) or len(cursor) > 256 or cursor in seen:
            raise ValueError("trace cursor is malformed or did not advance")
        seen.add(cursor)
    raise ValueError("trace page count exceeded the probe limit")


def mcp_trace(kin, repo, env, arguments, timeout=600):
    """Keep one stdio process/session for the complete continuation sequence."""
    return _mcp_pages(kin, repo, env, arguments, timeout, "trace_data_flow", drain_trace)


def mcp_references(kin, repo, env, arguments, timeout=600):
    """A reference cursor belongs to the same live stdio session as its first page."""
    return _mcp_pages(kin, repo, env, arguments, timeout, "find_references", drain_references)


def _mcp_pages(kin, repo, env, arguments, timeout, tool, drain):
    with tempfile.TemporaryFile(mode="w+") as errors:
        proc = subprocess.Popen([kin, "mcp", "start", "--repo", repo], cwd=repo,
                                env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=errors, text=True, bufsize=1)
        selector = selectors.DefaultSelector()
        selector.register(proc.stdout, selectors.EVENT_READ)
        sequence = [0]
        pending = bytearray()

        def request(method, params=None, notification=False):
            sequence[0] += 1
            frame = {"jsonrpc": "2.0", "method": method}
            if params is not None:
                frame["params"] = params
            if not notification:
                frame["id"] = sequence[0]
            proc.stdin.write(json.dumps(frame) + "\n")
            proc.stdin.flush()
            if notification:
                return None
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                if b"\n" not in pending:
                    if not selector.select(max(0, deadline - time.monotonic())):
                        break
                    chunk = os.read(proc.stdout.fileno(), 65536)
                    if not chunk:
                        raise ValueError("trace MCP process exited before replying")
                    pending.extend(chunk)
                    continue
                line, _, rest = pending.partition(b"\n")
                pending[:] = rest
                try:
                    response = json.loads(line)
                except ValueError:
                    continue
                if response.get("id") != sequence[0]:
                    continue
                if "error" in response:
                    raise ValueError("trace MCP error: %s" % response["error"])
                return response.get("result") or {}
            raise ValueError("trace MCP request timed out")

        try:
            request("initialize", {"protocolVersion":"2024-11-05", "capabilities":{},
                    "clientInfo":{"name":"kin-trace-pages-acceptance", "version":"1"}})
            request("notifications/initialized", notification=True)

            def fetch(cursor):
                args = dict(arguments)
                if cursor is not None:
                    args["cursor"] = cursor
                result = request("tools/call", {"name":tool, "arguments":args})
                content = result.get("content") or []
                if (result.get("isError") and tool == "trace_data_flow") or not content or "text" not in content[0]:
                    raise ValueError("trace MCP refused the page: %s" % result)
                wire = content[0]["text"]
                return json.loads(wire), wire

            return drain(fetch, arguments.get("max_chars", arguments.get("max_response_chars")))
        finally:
            selector.close()
            proc.stdin.close()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            proc.stdout.close()
