"""``faig agent``'s full-screen view (Textual): the chat on the left, every tool
call and gateway verdict on the right."""

from __future__ import annotations

import json
import threading
from typing import Any, ClassVar

from .agent import Agent

HINT = "Pick a scenario below, or type your own question."


def _block_reason(ev: tuple[Any, ...]) -> str:
    return "a tool result" if ev[2] == "tool" else "your message"


def _short(text: str, n: int = 100) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[: n - 1] + "…"


NARROW = 100


def run_tui(
    agent: Agent,
    header: str,
    footer: str,
    scenarios: list[dict[str, Any]] | None = None,
    approve: bool = False,
) -> None:
    tui_app(agent, header, scenarios, approve).run()
    print(footer.format(tokens=agent.tokens))


def tui_app(
    agent: Agent,
    header: str,
    scenarios: list[dict[str, Any]] | None = None,
    approve: bool = False,
) -> Any:
    """The full-screen app, unstarted (tests drive it with ``run_test``). Each
    scenario with a ``button`` becomes a quick prompt that asks its ``ask`` and
    checks the turn's outcome against its ``expect`` (blocked or allowed). With
    ``approve`` every tool call waits for Allow, Always allow or Deny."""
    quick = [x for x in scenarios or [] if x.get("button") and x.get("ask")]
    try:
        from textual.app import App, ComposeResult
        from textual.containers import Horizontal, Vertical, VerticalScroll
        from textual.screen import ModalScreen
        from textual.widgets import Button, Footer, Header, Input, Markdown, RichLog, Static
    except ImportError as e:
        raise ValueError(
            'the full-screen agent needs Textual: pip install "pyfortiaigate[cli]"'
        ) from e
    from rich.panel import Panel
    from rich.text import Text

    class Approve(ModalScreen[str]):
        """Allow once, always (this tool, this session) or deny one tool call."""

        CSS = """
        Approve { align: center middle; }
        #ask { width: 70; max-width: 95%; height: auto; border: heavy $warning;
               background: $surface; padding: 1 2; }
        #ask Horizontal { height: auto; margin-top: 1; }
        #ask Button { margin-right: 1; }
        """
        BINDINGS: ClassVar = [("escape", "dismiss('deny')", "Deny")]

        def __init__(self, name: str, args: dict[str, Any]) -> None:
            super().__init__()
            self.tool, self.args = name, args

        def compose(self) -> ComposeResult:
            with Vertical(id="ask"):
                yield Static(f"The agent wants to run [b]{self.tool}[/b]")
                yield Static(Text(_short(json.dumps(self.args), 600)))
                with Horizontal():
                    yield Button("Allow", id="once", variant="success", compact=True)
                    yield Button("Always allow", id="always", compact=True)
                    yield Button("Deny", id="deny", variant="error", compact=True)

        def on_mount(self) -> None:
            self.query_one("#deny").focus()  # a stray Enter must not run the tool

        def on_button_pressed(self, event: Button.Pressed) -> None:
            event.stop()  # not a scenario button
            self.dismiss(str(event.button.id))

    class AgentApp(App[None]):
        TITLE = "faig agent"
        SUB_TITLE = header
        CSS = """
        #chat { width: 3fr; padding: 0 1; }
        #side { width: 2fr; border-left: solid $primary; }
        #trace { height: 1fr; }
        #status { height: 1; padding: 0 1; color: $text-muted; }
        #quick { height: auto; padding: 0 1; }
        #quick Button { margin-right: 1; min-width: 16; }
        .narrow #main { layout: vertical; }
        .narrow #chat { width: 1fr; height: 3fr; }
        .narrow #side { width: 1fr; height: 2fr; border-left: none; border-top: solid $primary; }
        .narrow #quick { layout: grid; grid-size: 2; grid-gutter: 0 1; }
        .narrow #quick Button { width: 1fr; margin-right: 0; }
        .you { color: $accent; text-style: bold; margin-top: 1; }
        .who { color: $success; text-style: bold; margin-top: 1; }
        .blocked { border: heavy $error; color: $error; padding: 0 1; margin-top: 1; }
        .error { border: round $warning; padding: 0 1; margin-top: 1; }
        """
        BINDINGS: ClassVar = [("ctrl+q", "quit", "Quit"), ("ctrl+l", "clear", "Clear trace")]

        def compose(self) -> ComposeResult:
            yield Header()
            with Horizontal(id="main"):
                yield VerticalScroll(Static(HINT, classes="who"), id="chat")
                with Vertical(id="side"):
                    yield RichLog(id="trace", wrap=True, markup=False, min_width=20)
            yield Static("0 tokens", id="status")
            if quick:
                with Horizontal(id="quick"):
                    for i, x in enumerate(quick):
                        yield Button(str(x["button"]), id=f"scenario-{i}", compact=True)
            yield Input(placeholder="Ask the agent… (Enter to send, Ctrl+Q to quit)")
            yield Footer()

        def on_mount(self) -> None:
            self.query_one("#side").border_title = "Tool calls · gateway verdicts"
            self.query_one(Input).focus()
            self._fit(self.size.width)
            self.allowed: set[str] = set()
            if approve:
                agent.approve = self._approve

        def _approve(self, name: str, args: dict[str, Any]) -> bool:
            # Runs on the worker thread: wait there for the answer from the dialog.
            if name in self.allowed:
                return True
            answer: list[str] = []
            done = threading.Event()

            def answered(r: str | None) -> None:
                answer.append(r or "deny")
                done.set()

            def ask() -> None:
                self.push_screen(Approve(name, args), answered)

            self.call_from_thread(ask)
            done.wait()
            if answer[0] == "always":
                self.allowed.add(name)
            return answer[0] != "deny"

        def on_resize(self, event: Any) -> None:
            self._fit(event.size.width)

        def _fit(self, width: int) -> None:
            # Below NARROW columns the trace stacks under the chat, buttons go two a row
            self.set_class(width < NARROW, "narrow")

        def action_clear(self) -> None:
            self.query_one(RichLog).clear()

        expect: dict[str, Any] | None = None
        outcome = ""

        def on_input_submitted(self, event: Input.Submitted) -> None:
            text = event.value.strip()
            event.input.value = ""
            if text in ("/exit", "/quit"):
                self.exit()
            elif text:
                self._submit(text)

        def on_button_pressed(self, event: Button.Pressed) -> None:
            x = quick[int(str(event.button.id).rsplit("-", 1)[1])]
            self.query_one(RichLog).write(
                Text(f"▶ scenario {x['button']}: expect {x['expect']}", style="bold magenta")
            )
            self._submit(str(x["ask"]), x)

        def _submit(self, text: str, expect: dict[str, Any] | None = None) -> None:
            self.expect, self.outcome = expect, ""
            chat = self.query_one("#chat", VerticalScroll)
            chat.mount(Static(f"you > {text}", classes="you"))
            chat.scroll_end(animate=False)
            self._busy(True)
            self.run_worker(lambda: self._turn(text), thread=True, exclusive=True)

        def _busy(self, busy: bool) -> None:
            self.query_one(Input).disabled = busy
            for b in self.query(Button):
                b.disabled = busy
            if not busy:
                self.query_one(Input).focus()

        def _turn(self, text: str) -> None:
            # A thread: the gateway calls block. Every UI change goes back through
            # call_from_thread.
            for ev in agent.ask(text):
                self.call_from_thread(self._show, ev)
            self.call_from_thread(self._done)

        def _show(self, ev: tuple[Any, ...]) -> None:
            self.outcome = {"blocked": "blocked", "answer": "allowed", "error": "error"}.get(
                ev[0], self.outcome
            )
            chat = self.query_one("#chat", VerticalScroll)
            trace = self.query_one(RichLog)
            if ev[0] == "tool":
                trace.write(
                    Text.assemble(
                        ("⚙ ", "cyan"), (f"{ev[1]} ", "bold cyan"), (json.dumps(ev[2]), "cyan")
                    )
                )
            elif ev[0] == "result":
                trace.write(Text(f"  ↳ {_short(ev[2], 400)}", style="dim"))
                trace.write(
                    Text("  → sent back to the model through FortiAIGate", style="dim italic")
                )
            elif ev[0] == "denied":
                trace.write(Text(f"  ✋ you denied {ev[1]}: not run", style="yellow"))
            elif ev[0] == "blocked":
                msg = f"BLOCKED by FortiAIGate · {_block_reason(ev)} tripped a guardrail\n{ev[1]}"
                chat.mount(Static(msg, classes="blocked"))
                trace.write(Panel(Text(ev[1]), title="✖ BLOCK", border_style="bold red"))
            elif ev[0] == "error":
                chat.mount(Static(f"the gateway refused this turn\n{ev[1]}", classes="error"))
                trace.write(Text(f"! {ev[1]}", style="yellow"))
            else:
                chat.mount(Static("agent", classes="who"))
                chat.mount(Markdown(ev[1]))
                trace.write(Text("✔ answered", style="green"))
            chat.scroll_end(animate=False)
            self.query_one("#status", Static).update(
                f"{agent.tokens} tokens this session · `faig logs` lists every call"
            )

        def _done(self) -> None:
            x = self.expect
            if x:
                ok = self.outcome == x["expect"]
                verdict = "PASS" if ok else "MISMATCH"
                got = f"expected {x['expect']}, got {self.outcome or 'nothing'}"
                self.query_one(RichLog).write(
                    Text.assemble(
                        (f"{verdict} ", "bold green" if ok else "bold red"),
                        (f"{x['button']}: {got}", ""),
                    )
                )
                if x.get("why"):
                    self.query_one(RichLog).write(Text(f"  {x['why']}", style="dim italic"))
            self._busy(False)

    return AgentApp()
