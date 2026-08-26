#!/usr/bin/env python3
"""One MCP tools/call against a fixture repo, printing the payload and its verdict.

The instrument for lane recall's verification pass. It exists as a committed file
rather than an inline shell one-liner so a published number names a sha.

The real payload is a JSON string inside content[0].text. Reading fields off the
outer result object returns empty for every one of them, which reads exactly like a
zero, so this pierces the envelope and reports an unreadable response as UNREADABLE
rather than as an absence.
"""
import json
import os
import subprocess
import sys


def call(kin, repo, tool, args, timeout=600):
    env = dict(os.environ)
    env["KIN_MCP_REPO"] = repo
    env.setdefault("KIN_EMBED_BACKEND", "cpu")
    proc = subprocess.Popen(
        [kin, "mcp", "start", "--repo", repo],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        cwd=repo, env=env, text=True,
    )
    msgs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                    "clientInfo": {"name": "recall-probe", "version": "1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": tool, "arguments": args}},
    ]
    payload = "".join(json.dumps(m) + "\n" for m in msgs)
    try:
        out, err = proc.communicate(payload, timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        return {"__probe_error__": "timeout after %ss" % timeout}
    resp = None
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if msg.get("id") == 2:
            resp = msg
    if resp is None:
        return {"__probe_error__": "no id=2 response; stderr tail: %s"
                % err[-400:]}
    if "error" in resp:
        return {"__probe_error__": "mcp error: %s" % json.dumps(resp["error"])[:400]}
    try:
        text = resp["result"]["content"][0]["text"]
    except (KeyError, IndexError, TypeError):
        return {"__probe_error__": "no content[0].text in result: %s"
                % json.dumps(resp.get("result"))[:400]}
    try:
        return json.loads(text)
    except ValueError:
        return {"__probe_error__": "content[0].text is not JSON",
                "__raw__": text[:2000]}


def main():
    if len(sys.argv) < 4:
        print("usage: probe.py <repo> <tool> <args-json> [--full]", file=sys.stderr)
        return 3
    kin = os.environ.get("KIN_BIN")
    if not kin:
        print("KIN_BIN must name the binary under test", file=sys.stderr)
        return 3
    repo, tool, args_json = sys.argv[1], sys.argv[2], sys.argv[3]
    full = "--full" in sys.argv[4:]
    payload = call(kin, repo, tool, json.loads(args_json))
    if "__probe_error__" in payload:
        print("UNREADABLE %s" % payload["__probe_error__"])
        return 2
    kin_env = payload.get("_kin", {})
    verdict = kin_env.get("verdict", {})
    print("VERDICT state=%s absence_claim=%s safe_to_conclude_absent=%s limiting_factor=%s"
          % (verdict.get("state"), verdict.get("absence_claim"),
             verdict.get("safe_to_conclude_absent"), verdict.get("limiting_factor")))
    comp = kin_env.get("completeness", {})
    print("COMPLETENESS status=%s bound=%s classes=%s"
          % (comp.get("status"), comp.get("bound"),
             json.dumps(comp.get("classes"), sort_keys=True)))
    resp_block = kin_env.get("response", {})
    if resp_block:
        print("RESPONSE bounded=%s max_chars=%s chars_before=%s"
              % (resp_block.get("bounded"), resp_block.get("max_chars"),
                 resp_block.get("chars_before_budget")))
    print("---PAYLOAD---")
    print(json.dumps(payload, indent=2, sort_keys=True)
          if full else json.dumps({k: v for k, v in payload.items() if k != "_kin"},
                                  indent=2, sort_keys=True)[:12000])
    return 0


if __name__ == "__main__":
    sys.exit(main())
