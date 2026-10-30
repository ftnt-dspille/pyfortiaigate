"""A minimal tool-using agent whose every model call goes through FortiAIGate.

The agent holds a conversation, offers the model the tools of one MCP server,
runs the tools the model asks for, and hands their results back to the model.
Both the user's prompts and the tool results reach the model only through the
gateway, under a virtual key, so the key's guardrails see -- and can block --
an injection hidden in data a tool returned (indirect prompt injection).

  agent = Agent(client, key, model, McpClient([...]))
  for event in agent.ask("summarise ticket 4411"):
      ...   # ("tool", name, args) / ("result", name, text) / ("answer", text) / ("blocked", text)

Standard library only: MCP's stdio transport is newline-delimited JSON-RPC.
"""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Iterator, Sequence
from typing import Any, cast

from .client import FaigError, FortiAIGate, blocked

SYSTEM = (
    "You are a helpdesk assistant. Use the tools to look up tickets before you answer "
    "a question about one. Answer briefly."
)

DEMO_SERVER = [sys.executable, "-m", "pyfortiaigate.mcp_demo"]
"""The bundled helpdesk MCP server (``faig mcp-demo``)."""


class McpClient:
    """An MCP server started as a child process, spoken to over stdio."""

    def __init__(self, command: Sequence[str]) -> None:
        self.proc = subprocess.Popen(
            list(command), stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1
        )
        self._id = 0
        self.info = self.request(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "faig-agent", "version": "1"},
            },
        )
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        self.tools: list[dict[str, Any]] = self.request("tools/list").get("tools", [])

    def _send(self, msg: dict[str, Any]) -> None:
        assert self.proc.stdin
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self._id += 1
        self._send({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or {}})
        assert self.proc.stdout
        for line in self.proc.stdout:
            msg = json.loads(line)
            if msg.get("id") != self._id:
                continue  # a notification or a server-side request: not ours
            if "error" in msg:
                raise RuntimeError(f"MCP {method}: {msg['error'].get('message')}")
            return dict(msg.get("result") or {})
        raise RuntimeError(f"MCP server exited during {method}")

    def call(self, name: str, args: dict[str, Any]) -> str:
        r = self.request("tools/call", {"name": name, "arguments": args})
        parts = [c for c in r.get("content", []) if c.get("type") == "text"]
        return "\n".join(str(c.get("text", "")) for c in parts)

    def openai_tools(self) -> list[dict[str, Any]]:
        """The server's tools in the shape a chat completion's ``tools`` takes."""
        return [
            {
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t.get("description", ""),
                    "parameters": t.get("inputSchema", {"type": "object"}),
                },
            }
            for t in self.tools
        ]

    def close(self) -> None:
        if self.proc.stdin:
            self.proc.stdin.close()
        self.proc.wait(timeout=5)

    def __enter__(self) -> McpClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class Agent:
    """One conversation. ``ask`` yields what happens during a turn."""

    def __init__(
        self,
        client: FortiAIGate,
        key: str,
        model: str,
        mcp: McpClient | None = None,
        system: str = SYSTEM,
        max_tokens: int = 256,
    ) -> None:
        self.c, self.key, self.model, self.mcp = client, key, model, mcp
        self.max_tokens = max_tokens
        self.messages: list[dict[str, Any]] = [{"role": "system", "content": system}]
        self.tokens = 0

    def ask(self, text: str) -> Iterator[tuple[Any, ...]]:
        """One turn: at most one round of tool calls, then the answer.

        Tools are offered on the turn's first model call only. llama.cpp answers HTTP
        500 ("does not match the expected peg-native format") when a small model,
        offered tools, writes a reply its tool-call parser cannot read -- reliably the
        answer that follows a tool result -- and a few 500s make FortiAIGate take the
        upstream out of service for minutes (503 "every upstream credential for this
        model is currently unavailable") for every workspace. Temperature 0 keeps the
        model's tool choice repeatable from run to run.

        The tool-choosing call sees only the system prompt and this question: with
        earlier turns in front of it a 1B model imitates its last answer instead of
        calling the tool. The answer is written with the whole conversation."""
        start = len(self.messages)
        self.messages.append({"role": "user", "content": text})
        tools = self.mcp.openai_tools() if self.mcp else None
        fresh = [self.messages[0], self.messages[-1]]
        for step in range(2):
            choosing = bool(tools) and step == 0
            extra: dict[str, Any] = {"tools": tools} if choosing else {}
            try:
                out = self.c.chat_completion(
                    self.key,
                    self.model,
                    fresh if choosing else self.messages,
                    max_tokens=self.max_tokens,
                    temperature=0,
                    **extra,
                )
            except FaigError as e:
                del self.messages[start:]
                yield ("error", str(e))
                return
            self.tokens += int((out.get("usage") or {}).get("total_tokens") or 0)
            msg = dict((out.get("choices") or [{}])[0].get("message") or {})
            if blocked(out):
                # What was blocked never reached the model: drop the whole turn so
                # the conversation can go on without the poisoned messages.
                last = self.messages[-1]["role"]
                del self.messages[start:]
                yield ("blocked", str(msg.get("content") or ""), last)
                return
            calls = cast("list[dict[str, Any]]", msg.get("tool_calls") or [])
            if not calls and choosing and start > 1:
                continue  # no tool needed: answer again, this time with the conversation
            if not calls or not self.mcp or step:
                # Keep only the question and the answer: later turns then never send
                # tool messages alongside the tools (the 500 above).
                answer = str(msg.get("content") or "")
                del self.messages[start + 1 :]
                self.messages.append({"role": "assistant", "content": answer})
                yield ("answer", answer)
                return
            self.messages.append(
                {"role": "assistant", "content": msg.get("content"), "tool_calls": calls}
            )
            for call in calls:
                fn = call.get("function") or {}
                try:
                    args = json.loads(fn.get("arguments") or "{}")
                except json.JSONDecodeError:
                    args = {}
                yield ("tool", fn.get("name"), args)
                result = self.mcp.call(str(fn.get("name")), args)
                yield ("result", fn.get("name"), result)
                self.messages.append(
                    {"role": "tool", "tool_call_id": call.get("id"), "content": result}
                )
