"""Client for an external SQIsign verify-timing adapter.

The adapter is any process that speaks this line protocol:

  * stdin:  ``<id> <pk_hex> <msg_hex> <sig_hex>`` per line
  * stdout: ``<id> <accept|reject> <cost_ns>`` per line

``<id>`` is an opaque token chosen by the caller (echoed back so answers may
arrive in any order). ``-`` denotes an empty hex value. ``<cost_ns>`` is a
wall-clock cost measurement in nanoseconds; the reference adapter reports the
best of five ``CLOCK_MONOTONIC`` timings per call.

This module ships **no cryptography**. It only drives such an adapter, exactly
like the author's ``sqisign-conformance`` project. The bundled reference
adapter (``oracle/timing.c``) links the SQIsign reference implementation, but
any conforming verifier can be substituted.
"""

from __future__ import annotations

import itertools
import shlex
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class Query:
    """A single verify request."""

    qid: str
    pk_hex: str
    msg_hex: str
    sig_hex: str

    def to_line(self) -> str:
        def norm(h: str) -> str:
            return h if h else "-"
        return f"{self.qid} {norm(self.pk_hex)} {norm(self.msg_hex)} {norm(self.sig_hex)}"


@dataclass(frozen=True)
class Answer:
    """One adapter response."""

    qid: str
    accept: bool
    cost_ns: float


class AdapterError(RuntimeError):
    pass


def parse_answer(line: str) -> Answer | None:
    """Parse one ``<id> <verdict> <cost_ns>`` line.

    Returns ``None`` for blank lines. Raises :class:`AdapterError` on a line
    the adapter emitted for a malformed request (e.g. ``<id> error_hex``),
    which has no cost field.
    """
    parts = line.split()
    if not parts:
        return None
    if len(parts) < 3:
        raise AdapterError(f"adapter reported no cost for {parts!r}")
    qid, verdict, cost = parts[0], parts[1], parts[2]
    if verdict not in ("accept", "reject"):
        raise AdapterError(f"adapter error for id {qid!r}: {verdict}")
    try:
        cost_ns = float(cost)
    except ValueError as exc:
        raise AdapterError(f"unparseable cost {cost!r} for id {qid!r}") from exc
    return Answer(qid=qid, accept=(verdict == "accept"), cost_ns=cost_ns)


class Adapter:
    """Spawns and drives a timing adapter subprocess.

    Use as a context manager::

        with Adapter.from_command("./oracle/timing_lvl1") as ad:
            ans = ad.query(pk_hex, msg_hex, sig_hex)
    """

    def __init__(self, argv: list[str]):
        self.argv = argv
        self._proc: subprocess.Popen[str] | None = None
        self._ids = ("q%d" % i for i in itertools.count())

    # -- construction -------------------------------------------------------
    @classmethod
    def from_command(cls, command: str | list[str]) -> "Adapter":
        argv = shlex.split(command) if isinstance(command, str) else list(command)
        if not argv:
            raise ValueError("empty adapter command")
        return cls(argv)

    # -- lifecycle ----------------------------------------------------------
    def __enter__(self) -> "Adapter":
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def start(self) -> None:
        if self._proc is not None:
            return
        self._proc = subprocess.Popen(
            self.argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

    def close(self) -> None:
        proc = self._proc
        self._proc = None
        if proc is None:
            return
        try:
            if proc.stdin and not proc.stdin.closed:
                proc.stdin.close()
        except (OSError, ValueError):
            pass
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    # -- I/O ----------------------------------------------------------------
    def _require(self) -> subprocess.Popen[str]:
        if self._proc is None or self._proc.stdin is None or self._proc.stdout is None:
            raise AdapterError("adapter not started")
        return self._proc

    def query(self, pk_hex: str, msg_hex: str, sig_hex: str,
              qid: str | None = None) -> Answer:
        """Send one request and read exactly one answer."""
        q = Query(qid or next(self._ids), pk_hex, msg_hex, sig_hex)
        (answer,) = self.batch([q])
        return answer

    def batch(self, queries: list[Query]) -> list[Answer]:
        """Send several requests, return answers in the *input* order.

        Answers may be streamed back in any order; they are matched by id.
        """
        proc = self._require()
        assert proc.stdin is not None and proc.stdout is not None
        wanted = [q.qid for q in queries]
        seen: dict[str, Answer] = {}

        for q in queries:
            proc.stdin.write(q.to_line() + "\n")
        proc.stdin.flush()

        remaining = set(wanted)
        while remaining:
            line = proc.stdout.readline()
            if line == "":
                raise AdapterError(
                    f"adapter closed with {len(remaining)} answers outstanding"
                )
            ans = parse_answer(line)
            if ans is None:
                continue
            if ans.qid in remaining:
                seen[ans.qid] = ans
                remaining.discard(ans.qid)
        return [seen[qid] for qid in wanted]


class BestOfN:
    """Wraps an adapter to take the minimum cost over ``n`` repeats.

    The reference adapter already does best-of-5 internally; this adds an
    optional outer layer for callers driving a single-shot adapter.
    """

    def __init__(self, adapter: Adapter, n: int = 1):
        if n < 1:
            raise ValueError("n must be >= 1")
        self.adapter = adapter
        self.n = n

    def query(self, pk_hex: str, msg_hex: str, sig_hex: str) -> Answer:
        best: Answer | None = None
        for _ in range(self.n):
            ans = self.adapter.query(pk_hex, msg_hex, sig_hex)
            if best is None or ans.cost_ns < best.cost_ns:
                best = ans
        assert best is not None
        return best
