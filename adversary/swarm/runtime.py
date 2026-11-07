"""The swarm on Fetch.ai uAgents.

One ``Agent`` per specialist plus a ``coordinator`` agent, all run in-process by a
``uagents.Bureau``. For each job the coordinator sends every specialist a ``ReviewRequest``
(its evidence slice + sha256), collects the staked ``Vote`` replies over uAgents messaging,
aggregates them with reputation weights, records the decision and (when ground truth is known)
settles the stakes.

Local mode is offline: the agents have no endpoints, registration is a no-op, and the Almanac
contract lookup that ``Agent.__init__`` would otherwise do over gRPC is stubbed out.

uagents 0.26 gotchas handled here:
  * ``Agent()``/``Bureau()`` query the Almanac contract on the Fetch ledger at construction time
    (blocking gRPC, ~1s each). We stub ``uagents.agent.get_almanac_contract`` and pass no-op
    registration policies in local mode.
  * ``Bureau.run_async()`` must be the top-level task: on shutdown it cancels *every* other task
    on the loop, so awaiting it from another task recurses. We run it with
    ``loop.run_until_complete`` and stop it by flagging the uvicorn server to exit.
  * ``Agent.run_startup_tasks`` always POSTs an "active" status to the Almanac API; offline we
    replace ``_update_agent_status`` per instance. ``mark_inactive_on_shutdown`` and
    ``report_events`` would also talk to Almanac/Agentverse, so both are off.
"""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import socket
from typing import Callable

from .consensus import DEFAULT_THRESHOLD, SwarmDecision
from .engine import Job, build_request, decide, specialist_vote, validate_vote
from .models import ReviewRequest, Vote
from .policies import SPECIALISTS
from .reputation import Ledger, Settlement

EventSink = Callable[[str, dict], None]
SEED_PREFIX = "adversary-swarm-v1"


async def _no_status_update(active: bool) -> None:
    return None


def _offline_policies():
    from uagents_core.registration import AgentRegistrationPolicy, BatchRegistrationPolicy

    class NoAgentRegistration(AgentRegistrationPolicy):
        async def register(self, *a, **k):
            return None

    class NoBatchRegistration(BatchRegistrationPolicy):
        async def register(self):
            return None

        def add_agent(self, *a, **k):
            return None

    return NoAgentRegistration, NoBatchRegistration


@contextlib.contextmanager
def _offline_almanac():
    import uagents.agent as ua
    orig = ua.get_almanac_contract
    ua.get_almanac_contract = lambda network="testnet": None
    try:
        yield
    finally:
        ua.get_almanac_contract = orig


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _arrival_rank(job_id: str, agent: str) -> int:
    """Deterministic pseudo-random ordering of vote arrival per job (for the paced demo)."""
    return int(hashlib.sha256(f"{job_id}|{agent}".encode()).hexdigest()[:8], 16)


class SwarmRuntime:
    def __init__(
        self,
        ledger: Ledger,
        *,
        agents: tuple[str, ...] = SPECIALISTS,
        on_event: EventSink | None = None,
        pace: float = 0.0,
        job_delay: float = 0.0,
        vote_timeout: float = 10.0,
        threshold: float = DEFAULT_THRESHOLD,
        port: int | None = None,
        agentverse: bool = False,
        log_level: int = logging.ERROR,
    ) -> None:
        self.ledger = ledger
        self.agents = tuple(agents)
        self.emit = on_event or (lambda kind, payload: None)
        self.pace = pace
        self.job_delay = job_delay
        self.vote_timeout = vote_timeout
        self.threshold = threshold
        self.port = port
        self.agentverse = agentverse
        self.log_level = log_level
        self.addresses: dict[str, str] = {}

    # ------------------------------------------------------------------------------------------
    def run(self, jobs: list[Job]) -> list[tuple[SwarmDecision, list[Settlement] | None]]:
        """Review a fixed list of jobs, then shut the Bureau down."""
        return self._with_loop(lambda loop: self._run(loop, jobs=jobs))

    def serve(self, chat_script: list[str] | None = None, forever: bool = False) -> list[tuple[str, str]]:
        """Run the coordinator as a chat-protocol agent (AgentChatProtocol, what ASI:One speaks).

        With ``chat_script`` a local ``demo-user`` agent sends each line to the coordinator over the
        chat protocol and the run ends when every reply is in. With ``forever`` (Agentverse mode)
        the Bureau keeps serving until Ctrl+C. Returns the [(sent, reply)] transcript.
        """
        transcript: list[tuple[str, str]] = []
        self._with_loop(lambda loop: self._run(loop, jobs=[], chat_script=chat_script or [], forever=forever, transcript=transcript))
        return transcript

    def _with_loop(self, fn):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            with (contextlib.nullcontext() if self.agentverse else _offline_almanac()):
                return fn(loop)
        finally:
            with contextlib.suppress(Exception):
                loop.close()
            asyncio.set_event_loop(None)

    def _run(self, loop, jobs, chat_script=None, forever=False, transcript=None):
        from uagents import Agent, Bureau, Context, Protocol
        from uagents_core.contrib.protocols.chat import (ChatAcknowledgement, ChatMessage, EndSessionContent, TextContent,
                                                         chat_protocol_spec)

        common = dict(loop=loop, enable_agent_inspector=False, publish_agent_details=False, report_events=False,
                      mark_inactive_on_shutdown=False, log_level=self.log_level)
        bureau_kw = {}
        if not self.agentverse:
            NoAgentReg, NoBatchReg = _offline_policies()
            common["registration_policy"] = NoAgentReg()
            bureau_kw["registration_policy"] = NoBatchReg()

        def make_agent(name: str, description: str, public: bool = False) -> Agent:
            kw = dict(common)
            if public and self.agentverse:  # only the coordinator faces Agentverse / ASI:One
                kw.update(mailbox=True, enable_agent_inspector=True, publish_agent_details=True)
            ag = Agent(name=name, seed=f"{SEED_PREFIX}:{name}", description=description, **kw)
            if not self.agentverse:
                ag._update_agent_status = _no_status_update
            self.addresses[name] = ag.address
            return ag

        results: list[tuple[SwarmDecision, list[Settlement] | None]] = []
        pending: dict[str, dict] = {}  # job_id -> {"req": {agent: req}, "votes": {agent: vote}, "done": Event}
        by_address: dict[str, str] = {}

        # ---- specialists --------------------------------------------------------------------
        specialists = []
        for name in self.agents:
            ag = make_agent(name, f"Adversary swarm specialist: {name}")
            proto = Protocol(name="adversary-swarm-review", version="0.1.0")

            def make_handler(agent_name: str):
                async def on_review(ctx: Context, sender: str, msg: ReviewRequest):
                    vote = specialist_vote(agent_name, msg.model_dump())
                    if self.pace:
                        rank = sorted(self.agents, key=lambda a: _arrival_rank(msg.job_id, a)).index(agent_name)
                        await asyncio.sleep(self.pace * (rank + 1))
                    await ctx.send(sender, Vote(**vote))
                return on_review

            proto.on_message(model=ReviewRequest, replies=Vote)(make_handler(name))
            ag.include(proto, publish_manifest=False)
            specialists.append(ag)
            by_address[ag.address] = name

        # ---- coordinator --------------------------------------------------------------------
        coord = make_agent("coordinator", "Adversary Swarm Verify coordinator: specialist verifier agents vote on whether an "
                                          "AI-generated code change is safe to merge, weighted by earned reputation.", public=True)
        port = self.port or _free_port()
        bureau = Bureau(agents=[*specialists, coord], port=port, loop=loop, log_level=self.log_level, **bureau_kw)

        @coord.on_message(model=Vote)
        async def on_vote(ctx: Context, sender: str, msg: Vote):
            agent = by_address.get(sender)
            st = pending.get(msg.job_id)
            if agent is None or st is None or agent in st["votes"]:
                return  # unknown sender, stale job, or duplicate vote
            v = validate_vote(msg.model_dump(), agent, st["req"][agent])
            st["votes"][agent] = v
            self.emit("vote", {"job_id": msg.job_id, "vote": v, "weight": self.ledger.weight(agent)})
            if len(st["votes"]) == len(self.agents):
                st["done"].set()

        lock = asyncio.Lock()  # one review at a time: reputations must update in order

        async def review(ctx: Context, job: Job, index: int):
            async with lock:
                jid = job.job_id
                reqs = {a: build_request(job.verdict, a, self.ledger.weight(a), jid) for a in self.agents}
                pending[jid] = {"req": reqs, "votes": {}, "done": asyncio.Event()}
                self.emit("job_start", {"index": index, "job": job, "weights": self.ledger.weights(), "addresses": dict(self.addresses)})
                for a in self.agents:
                    await ctx.send(self.addresses[a], ReviewRequest(**reqs[a]))
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(pending[jid]["done"].wait(), self.vote_timeout)
                st = pending.pop(jid)
                votes = [st["votes"][a] for a in self.agents if a in st["votes"]]
                decision, settlements = decide(job, votes, self.ledger, self.agents, self.threshold)
                results.append((decision, settlements))
                self.emit("decision", {"job": job, "decision": decision, "settlements": settlements})
                return decision, settlements

        async def drive(ctx: Context):
            try:
                for i, job in enumerate(jobs):
                    await review(ctx, job, i)
                    if self.job_delay and i + 1 < len(jobs):
                        await asyncio.sleep(self.job_delay)
            except Exception as e:  # surface, then stop the bureau
                self.emit("error", {"error": f"{type(e).__name__}: {e}"})
                raise
            finally:
                if not chat_script and not forever:
                    await _stop(bureau)

        @coord.on_event("startup")
        async def start(ctx: Context):
            # Run the job loop in its own task so the coordinator keeps processing Vote messages.
            loop.create_task(drive(ctx))

        # ---- chat protocol (ASI:One / Agentverse compatible) -------------------------------------
        chat = Protocol(spec=chat_protocol_spec)

        def reply(text: str, end: bool = True) -> ChatMessage:
            content = [TextContent(text=text)] + ([EndSessionContent()] if end else [])
            return ChatMessage(content=content)

        async def answer(ctx: Context, sender: str, text: str):
            from .chat import handle_text
            try:
                out = await handle_text(text, self.ledger, lambda job: review(ctx, job, len(results)))
            except Exception as e:  # never leave a chat user hanging
                out = f"swarm error: {type(e).__name__}: {e}"
            await ctx.send(sender, reply(out))

        @chat.on_message(ChatMessage)
        async def on_chat(ctx: Context, sender: str, msg: ChatMessage):
            await ctx.send(sender, ChatAcknowledgement(acknowledged_msg_id=msg.msg_id))
            text = msg.text().strip()
            if not text:
                return
            # Reviewing needs this agent to keep receiving Vote messages, so don't block the handler.
            loop.create_task(answer(ctx, sender, text))

        @chat.on_message(ChatAcknowledgement)
        async def on_ack(ctx: Context, sender: str, msg: ChatAcknowledgement):
            return None

        coord.include(chat, publish_manifest=self.agentverse)

        agents = [*specialists, coord]
        if chat_script:
            user = make_agent("demo-user", "local stand-in for an ASI:One user")
            user_chat = Protocol(spec=chat_protocol_spec)
            got: asyncio.Queue = asyncio.Queue()

            @user_chat.on_message(ChatMessage)
            async def on_reply(ctx: Context, sender: str, msg: ChatMessage):
                await ctx.send(sender, ChatAcknowledgement(acknowledged_msg_id=msg.msg_id))
                await got.put(msg.text())

            @user_chat.on_message(ChatAcknowledgement)
            async def on_user_ack(ctx: Context, sender: str, msg: ChatAcknowledgement):
                return None

            user.include(user_chat)

            async def converse(ctx: Context):
                try:
                    for line in chat_script:
                        self.emit("chat_out", {"text": line, "to": coord.address})
                        await ctx.send(coord.address, ChatMessage(content=[TextContent(text=line)]))
                        r = await asyncio.wait_for(got.get(), self.vote_timeout + 5 + self.pace * (len(self.agents) + 1))
                        transcript.append((line, r))
                        self.emit("chat_in", {"text": r, "from": coord.address})
                finally:
                    await _stop(bureau)

            @user.on_event("startup")
            async def user_start(ctx: Context):
                loop.create_task(converse(ctx))

            bureau.add(user)
            agents.append(user)

        if self.agentverse:
            self.emit("agentverse", {"coordinator": coord.address, "port": port,
                                     "inspector": f"https://agentverse.ai/inspect/?uri=http%3A//127.0.0.1%3A{port}&address={coord.address}"})

        if not forever:
            # Watchdog: never hang the CLI or the tests.
            n = max(len(jobs), len(chat_script or []))
            budget = 15.0 + n * (self.vote_timeout + self.job_delay + self.pace * (len(self.agents) + 1))
            loop.call_later(budget, lambda: loop.create_task(_stop(bureau)))
        with contextlib.suppress(KeyboardInterrupt):
            loop.run_until_complete(bureau.run_async())
        return results


async def _stop(bureau) -> None:
    """Ask the Bureau's uvicorn server to exit; Bureau.run_async then shuts the agents down."""
    for _ in range(200):
        server = getattr(bureau._server, "_server", None)
        if server is not None:
            server.should_exit = True
            return
        await asyncio.sleep(0.01)
