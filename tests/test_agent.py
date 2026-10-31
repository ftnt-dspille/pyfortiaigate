"""The demo agent: an MCP stdio round trip, and tool results sent back through the gateway."""

from __future__ import annotations

import json
from typing import Any

from pyfortiaigate.agent import DEMO_SERVER, Agent, McpClient


class FakeGateway:
    """Answers chat_completion from a script and records what each call sent."""

    def __init__(self, replies: list[dict[str, Any]]) -> None:
        self.replies, self.sent = replies, []

    def chat_completion(self, key: str, model: str, messages: list, **kw: Any) -> dict:
        self.sent.append({"messages": json.loads(json.dumps(messages)), **kw})
        return self.replies.pop(0)


def reply(content: str | None = None, calls: list | None = None, finish: str = "stop") -> dict:
    msg: dict[str, Any] = {"role": "assistant", "content": content}
    if calls:
        msg["tool_calls"] = calls
    return {"choices": [{"message": msg, "finish_reason": finish}], "usage": {"total_tokens": 10}}


TICKET_CALL = [
    {
        "id": "c1",
        "type": "function",
        "function": {"name": "get_ticket", "arguments": '{"id": 4411}'},
    }
]


def test_demo_server_lists_and_calls_tools() -> None:
    with McpClient(DEMO_SERVER) as mcp:
        assert [t["name"] for t in mcp.tools] == ["get_ticket", "send_email"]
        assert mcp.openai_tools()[0]["function"]["parameters"]["required"] == ["id"]
        assert "IGNORE ALL PREVIOUS INSTRUCTIONS" in mcp.call("get_ticket", {"id": 4411})
        assert mcp.call("get_ticket", {"id": 1}) == "no ticket 1"


def test_tool_result_goes_back_through_the_gateway() -> None:
    gw = FakeGateway([reply(calls=TICKET_CALL), reply("The printer jams.")])
    with McpClient(DEMO_SERVER) as mcp:
        agent = Agent(gw, "faig_x", "m", mcp)  # type: ignore[arg-type]
        events = list(agent.ask("summarise ticket 4411"))
    assert [e[0] for e in events] == ["tool", "result", "answer"]
    second = gw.sent[1]["messages"]
    assert second[-1]["role"] == "tool"
    assert "4411" in second[-1]["content"]
    assert gw.sent[0]["tools"][0]["function"]["name"] == "get_ticket"
    assert "tools" not in gw.sent[1]  # the answer after a tool result: plain text only
    assert agent.tokens == 20
    # The finished turn keeps only the question and the answer.
    assert [m["role"] for m in agent.messages] == ["system", "user", "assistant"]
    assert agent.messages[-1]["content"] == "The printer jams."


def test_blocked_tool_result_drops_the_turn() -> None:
    blocked = reply("This request was blocked by FortiAIGate.", finish="content_filter")
    gw = FakeGateway([reply(calls=TICKET_CALL), blocked, reply("hi")])
    with McpClient(DEMO_SERVER) as mcp:
        agent = Agent(gw, "faig_x", "m", mcp)  # type: ignore[arg-type]
        events = list(agent.ask("summarise ticket 4411"))
        assert events[-1] == ("blocked", "This request was blocked by FortiAIGate.", "tool")
        assert [m["role"] for m in agent.messages] == ["system"]  # the poisoned turn is gone
        assert list(agent.ask("hello"))[-1] == ("answer", "hi")


def test_gateway_error_is_reported_not_retried() -> None:
    from pyfortiaigate import FaigError

    class Down(FakeGateway):
        def chat_completion(self, key: str, model: str, messages: list, **kw: Any) -> dict:
            self.sent.append(kw)
            raise FaigError("POST", "/ai/openai/v1/chat/completions", 503, "unavailable")

    gw = Down([])
    agent = Agent(gw, "faig_x", "m")  # type: ignore[arg-type]
    events = list(agent.ask("hi"))
    assert events[0][0] == "error"
    assert len(gw.sent) == 1  # a retry would only extend the gateway's cool-down
    assert gw.sent[0]["temperature"] == 0
    assert [m["role"] for m in agent.messages] == ["system"]


def test_tool_choice_sees_only_the_current_question() -> None:
    gw = FakeGateway([reply("a"), reply("no tool"), reply("with history")])
    with McpClient(DEMO_SERVER) as mcp:
        agent = Agent(gw, "faig_x", "m", mcp)  # type: ignore[arg-type]
        list(agent.ask("first"))
        events = list(agent.ask("second"))
    choose, answer = gw.sent[1], gw.sent[2]
    assert [m["content"] for m in choose["messages"][1:]] == ["second"]
    assert "tools" in choose
    assert "tools" not in answer
    assert len(answer["messages"]) == 4  # system, first, a, second
    assert events == [("answer", "with history")]


def test_full_screen_view_shows_the_block() -> None:
    import asyncio

    from textual.widgets import Input, RichLog, Static

    from pyfortiaigate.agent_ui import tui_app

    blocked = reply("This request was blocked by FortiAIGate.", finish="content_filter")
    gw = FakeGateway([reply(calls=TICKET_CALL), blocked])
    with McpClient(DEMO_SERVER) as mcp:
        app = tui_app(Agent(gw, "faig_x", "m", mcp), "m via test")  # type: ignore[arg-type]

        async def drive() -> None:
            async with app.run_test(size=(120, 40)) as pilot:
                app.query_one(Input).value = "summarise ticket 4411"
                await pilot.press("enter")
                for _ in range(100):
                    await pilot.pause(0.05)
                    if not app.query_one(Input).disabled:
                        break
                assert app.query(".blocked")
                trace = "\n".join(str(line.text) for line in app.query_one(RichLog).lines)
                assert "get_ticket" in trace
                assert "BLOCK" in trace
                assert "20 tokens" in str(app.query_one("#status", Static).render())

        asyncio.run(drive())


def test_agent_refuses_a_pipe(capsys: Any) -> None:
    from pyfortiaigate.cli import main

    assert main(["--url", "https://faig.example.com", "agent", "--key", "faig_x"]) == 1
    assert "run it in a terminal" in capsys.readouterr().err


def test_agent_catalog_matches_the_demo_server() -> None:
    """The canned exchanges must be what the live agent sends, or `scenarios agent`
    would test different text from the one students see blocked."""
    from pyfortiaigate.agent import SYSTEM
    from pyfortiaigate.cli import _load_catalog
    from pyfortiaigate.mcp_demo import TICKETS

    for case in _load_catalog("agent"):
        assert case["button"]
        assert case["ask"]
        msgs = case.get("messages")
        if msgs:
            assert msgs[0]["content"] == SYSTEM
            assert msgs[1]["content"] == case["ask"]
            tid = json.loads(msgs[2]["tool_calls"][0]["function"]["arguments"])["id"]
            assert msgs[3]["content"] == TICKETS[tid]


def test_scenario_button_reports_pass_or_mismatch() -> None:
    import asyncio

    from textual.widgets import Button, RichLog

    from pyfortiaigate.agent_ui import tui_app

    cases = [
        {"button": "Poisoned", "ask": "summarise ticket 4411", "expect": "blocked", "why": "w"},
        {"button": "Clean", "ask": "summarise ticket 4410", "expect": "blocked"},
    ]
    blocked = reply("blocked", finish="content_filter")
    gw = FakeGateway([reply(calls=TICKET_CALL), blocked, reply("fine")])
    with McpClient(DEMO_SERVER) as mcp:
        app = tui_app(Agent(gw, "faig_x", "m", mcp), "m", cases)  # type: ignore[arg-type]

        async def drive() -> list[str]:
            async with app.run_test(size=(140, 40)) as pilot:
                for i in (0, 1):
                    await pilot.click(f"#scenario-{i}")
                    for _ in range(100):
                        await pilot.pause(0.05)
                        if not app.query_one(Button).disabled:
                            break
                return [str(line.text) for line in app.query_one(RichLog).lines]

        trace = "\n".join(asyncio.run(drive()))
    assert "PASS Poisoned: expected blocked, got blocked" in trace
    assert "MISMATCH Clean: expected blocked, got allowed" in trace
    assert gw.sent[0]["messages"][-1]["content"] == "summarise ticket 4411"


def test_demo_server_speaks_json_rpc_in_process(capsys: Any) -> None:
    import io

    from pyfortiaigate import mcp_demo

    lines = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "x"}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "send_email", "arguments": {"to": "a@b.example", "subject": "s"}},
        },
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "get_ticket", "arguments": {"id": "x"}},
        },
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "nope"}},
        {"jsonrpc": "2.0", "id": 6, "method": "ping"},
        {"jsonrpc": "2.0", "id": 7, "method": "resources/list"},
    ]
    stdin = io.StringIO("\n".join(json.dumps(x) for x in lines) + "\n\nnot json\n")
    out = io.StringIO()
    mcp_demo.serve(stdin, out)
    resp = [json.loads(x) for x in out.getvalue().splitlines()]
    assert [r["id"] for r in resp] == [1, 2, 3, 4, 5, 6, 7, None]  # no reply to a notification
    assert resp[0]["result"]["protocolVersion"] == "x"
    assert len(resp[1]["result"]["tools"]) == 2
    assert resp[2]["result"]["isError"] is False
    assert "!! send_email to a@b.example" in capsys.readouterr().err
    assert resp[3]["result"]["isError"] is True
    assert resp[4]["result"]["content"][0]["text"] == "unknown tool nope"
    assert resp[5]["result"] == {}
    assert resp[6]["error"]["code"] == -32601
    assert resp[7]["error"]["code"] == -32700


def test_full_screen_view_stacks_in_a_narrow_terminal() -> None:
    import asyncio

    from pyfortiaigate.agent_ui import tui_app
    from pyfortiaigate.cli import _load_catalog

    cases = _load_catalog("agent")
    app = tui_app(Agent(FakeGateway([]), "faig_x", "m", None), "m", cases)  # type: ignore[arg-type]

    async def drive() -> None:
        async with app.run_test(size=(80, 24)) as pilot:
            assert app.has_class("narrow")
            chat, side = app.query_one("#chat").region, app.query_one("#side").region
            assert side.y > chat.y
            assert side.width == chat.width
            await pilot.resize_terminal(160, 45)
            await pilot.pause()
            assert not app.has_class("narrow")
            chat, side = app.query_one("#chat").region, app.query_one("#side").region
            assert side.x > chat.x
            assert side.y == chat.y

    asyncio.run(drive())


def test_denied_tool_call_is_not_run() -> None:
    gw = FakeGateway([reply(calls=TICKET_CALL), reply("I can't look it up.")])
    asked: list[tuple[str, dict]] = []
    with McpClient(DEMO_SERVER) as mcp:
        agent = Agent(gw, "faig_x", "m", mcp, approve=lambda n, a: bool(asked.append((n, a))))  # type: ignore[arg-type]
        events = list(agent.ask("summarise ticket 4411"))
    assert asked == [("get_ticket", {"id": 4411})]
    assert [e[0] for e in events] == ["tool", "denied", "answer"]
    assert gw.sent[1]["messages"][-1]["content"] == "The user denied this tool call."


def test_full_screen_view_asks_before_each_tool_call() -> None:
    import asyncio

    from textual.widgets import Input, RichLog

    from pyfortiaigate.agent_ui import tui_app

    gw = FakeGateway(
        [
            *(reply(calls=TICKET_CALL), reply("no")),
            *(reply(calls=TICKET_CALL), reply("jams")),
            *(reply(calls=TICKET_CALL), reply("jams again")),
        ]
    )
    with McpClient(DEMO_SERVER) as mcp:
        app = tui_app(Agent(gw, "faig_x", "m", mcp), "m", approve=True)  # type: ignore[arg-type]

        async def turn(pilot: Any, answer: str | None) -> None:
            app.query_one(Input).value = "summarise ticket 4411"
            await pilot.press("enter")
            for _ in range(100):
                await pilot.pause(0.05)
                if answer and app.screen.query("#ask"):
                    await pilot.click(f"#{answer}")
                    answer = None
                if not app.query_one(Input).disabled:
                    return

        async def drive() -> None:
            async with app.run_test(size=(120, 40)) as pilot:
                await turn(pilot, "deny")
                await turn(pilot, "always")
                await turn(pilot, None)  # always allowed: no dialog
                trace = "\n".join(str(line.text) for line in app.query_one(RichLog).lines)
                assert trace.count("you denied get_ticket") == 1
                assert trace.count("↳ Ticket 4411") == 2
                assert trace.count("✔ answered") == 3
                assert not gw.replies

        asyncio.run(drive())
