"""Stateful, budget-enforcing MCP transport for blinded microbench agents.

The subject model chooses tools and interprets evidence.  This utility only
handles MCP session mechanics and records an auditable sidecar.
"""

from __future__ import annotations

import argparse
import json
import time
import urllib.request
from pathlib import Path
from typing import Any


MAX_CALLS = 6
MAX_TOOL_BYTES = 8192


def post(endpoint: str, body: dict[str, Any], session: str | None = None) -> tuple[dict[str, Any], str | None, int]:
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "MCP-Protocol-Version": "2025-11-25",
    }
    if session:
        headers["Mcp-Session-Id"] = session
    request = urllib.request.Request(endpoint, json.dumps(body, separators=(",", ":")).encode(), headers, method="POST")
    started = time.perf_counter()
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read()
        next_session = response.headers.get("Mcp-Session-Id") or session
    latency_ms = round((time.perf_counter() - started) * 1000)
    text = raw.decode("utf-8", "replace")
    if text.lstrip().startswith("data:") or "\ndata:" in text:
        events = [line[5:].strip() for line in text.splitlines() if line.startswith("data:") and line[5:].strip()]
        text = events[-1]
    return json.loads(text) if text.strip() else {}, next_session, latency_ms


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def save(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")


def initialize(path: Path, case_id: str, endpoint: str, visible_input_bytes: int) -> None:
    result, session, _ = post(endpoint, {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                   "clientInfo": {"name": "windy-microbench-subject", "version": "0.3"}},
    })
    if "error" in result or not session:
        raise RuntimeError(f"MCP initialization failed: {result}")
    post(endpoint, {"jsonrpc": "2.0", "method": "notifications/initialized"}, session)
    save(path, {
        "case_id": case_id, "endpoint": endpoint, "session": session,
        "started_ms": round(time.time() * 1000), "visible_input_bytes": visible_input_bytes,
        "steps": [], "answer": "", "failure_stage": None,
    })
    print(json.dumps({"ready": True, "remaining_calls": MAX_CALLS, "remaining_bytes": MAX_TOOL_BYTES}))


def call(path: Path, tool: str, arguments_json: str) -> None:
    state = load(path)
    arguments = json.loads(arguments_json)
    if not isinstance(arguments, dict):
        raise RuntimeError("arguments must decode to a JSON object")
    used_bytes = sum(int(step["response_bytes"]) for step in state["steps"])
    if len(state["steps"]) >= MAX_CALLS:
        raise RuntimeError("six-call budget exhausted")
    if used_bytes >= MAX_TOOL_BYTES:
        raise RuntimeError("8 KiB tool-output budget exhausted")
    # Sessions may be initialized in a batch long before an agent receives its
    # case.  Measure model-facing wall time from the first actual tool decision,
    # not from transport setup, so queued cases do not inherit scheduler delay.
    state.setdefault("first_call_ms", round(time.time() * 1000))
    request_id = len(state["steps"]) + 2
    result, session, latency_ms = post(state["endpoint"], {
        "jsonrpc": "2.0", "id": request_id, "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }, state["session"])
    state["session"] = session
    call_result = result.get("result", result)
    response_bytes = len(json.dumps(call_result, separators=(",", ":")).encode())
    error = None
    if call_result.get("isError") is True:
        error = str(call_result.get("structuredContent", {}).get("data", {}).get("error", {}).get("code", "TOOL_ERROR"))
    state["steps"].append({
        "tool": tool, "arguments": arguments, "response_bytes": response_bytes,
        "latency_ms": latency_ms, "error": error,
    })
    save(path, state)
    remaining = MAX_TOOL_BYTES - used_bytes - response_bytes
    output = {
        "evidence": call_result.get("structuredContent", {}),
        "remaining_calls": MAX_CALLS - len(state["steps"]),
        "remaining_bytes": max(0, remaining),
    }
    print(json.dumps(output, separators=(",", ":")))


def finish(path: Path, answer: str, failure_stage: str | None) -> None:
    state = load(path)
    state["answer"] = answer[:2000]
    state["failure_stage"] = failure_stage
    wall_start = state.get("first_call_ms", state.get("started_ms"))
    if wall_start is not None:
        state["wall_ms"] = max(0, round(time.time() * 1000) - int(wall_start))
    else:
        state.setdefault("wall_ms", 0)
    state.pop("endpoint", None)
    state.pop("session", None)
    state.pop("started_ms", None)
    state.pop("first_call_ms", None)
    save(path, state)
    print(json.dumps({"recorded": True, "calls": len(state["steps"]), "answer": state["answer"]}))


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--state", type=Path, required=True)
    commands = result.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init")
    init.add_argument("--case-id", required=True)
    init.add_argument("--endpoint", required=True)
    init.add_argument("--visible-input-bytes", type=int, default=0)
    invoke = commands.add_parser("call")
    invoke.add_argument("tool")
    invoke.add_argument("arguments")
    done = commands.add_parser("finish")
    done.add_argument("answer")
    done.add_argument("--failure-stage")
    return result


def main() -> int:
    args = parser().parse_args()
    if args.command == "init":
        initialize(args.state, args.case_id, args.endpoint, args.visible_input_bytes)
    elif args.command == "call":
        call(args.state, args.tool, args.arguments)
    else:
        finish(args.state, args.answer, args.failure_stage)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
