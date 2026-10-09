"""Admission control and thread pools for the lookup pipeline.

The gate. At most LOOKUP_CONCURRENCY lookups run at once, across every surface
that starts one: the page and the JSON API, ?format=text and ?fields=, and the
MCP tools. Only MCP used to be bounded, by a semaphore of its own; a burst of
GET /{target} or of the self page started as many pipelines as there were
requests. A lookup that finds every slot taken waits up to
LOOKUP_GATE_WAIT_SECONDS for one, then gets LookupBusy, which main.py answers
with a 503 and mcp_server.py with {"error": ...}.

The pools. asyncio.to_thread runs on the event loop's default executor,
min(32, cpus + 4) threads shared by every leg. RDAP, port-43 WHOIS and crt.sh
are the slow ones, seconds to tens of seconds, and the wait_for that gives up on
one cannot stop its thread, so a pile-up of them filled that executor and
queued the DNS and TLS legs of every other lookup behind them. They now run on
pools of their own: a backlog of slow legs waits behind itself, and the default
executor is left to the DNS and TLS legs, each bounded by its own timeout.

subdomains.py uses the crt.sh pool, and must not import lookup or main, so this
module imports nothing app-local but config.
"""

import asyncio
import contextlib
import contextvars
import functools
import logging
from concurrent.futures import Executor, ThreadPoolExecutor

from config import (
    LOOKUP_CONCURRENCY,
    LOOKUP_GATE_WAIT_SECONDS,
    REGISTRATION_WORKERS,
    SUBDOMAIN_MAX_CONCURRENT,
)

# RDAP and port-43 WHOIS. Sized well under the default executor: RDAP's own
# request budget is 3.5s and every answer is cached, so a handful of workers
# keeps up with the gate, and a dead registry costs this pool, not every lookup.
registration_pool = ThreadPoolExecutor(
    max_workers=REGISTRATION_WORKERS, thread_name_prefix="registration"
)
# crt.sh, one thread per connection SUBDOMAIN_MAX_CONCURRENT allows. A fetch's
# caller can be cancelled while urllib holds the thread for up to
# SUBDOMAIN_TIMEOUT_SECONDS; the pool still caps the connections.
subdomain_pool = ThreadPoolExecutor(
    max_workers=SUBDOMAIN_MAX_CONCURRENT, thread_name_prefix="crtsh"
)


async def run_in(pool: Executor, func, /, *args, **kwargs):
    """asyncio.to_thread, on `pool` instead of the default executor.

    The context is copied the same way to_thread copies it, so the request's
    OpenTelemetry span is still the parent of whatever the thread does. A call
    whose awaiter is cancelled (a wait_for deadline) before a worker picks it up
    is dropped from the queue, so a burst cannot leave work behind that outlives
    its requests; one already running finishes on its own timeout.
    """
    loop = asyncio.get_running_loop()
    call = functools.partial(contextvars.copy_context().run, func, *args, **kwargs)
    return await loop.run_in_executor(pool, call)


class LookupBusy(Exception):
    """Every slot at a LookupGate was taken and none came free within its wait.

    Raised rather than answered, like lookup.PrivateAddressError, so each
    transport words the refusal itself. It is the server's state, not the
    caller's doing, so nothing that answers it may count it towards a ban.
    """

    message = "Too many lookups are running; try again in a few seconds"

    def __init__(self):
        super().__init__(self.message)


class LookupGate:
    """At most `size` holders of slot() at once.

    A caller that finds every slot taken waits up to `wait` seconds for one,
    then gets LookupBusy. Waiting costs a suspended coroutine and never a
    thread: nothing reaches a pool until the slot is held.
    """

    def __init__(self, name: str, size: int, wait: float = LOOKUP_GATE_WAIT_SECONDS):
        self.name = name
        self.size = size
        self.wait = wait
        self._loop: asyncio.AbstractEventLoop | None = None
        self._semaphore: asyncio.Semaphore | None = None

    def _current(self) -> asyncio.Semaphore:
        # An asyncio.Semaphore belongs to the first event loop that waits on
        # it. Production runs one loop for the life of the process, but the
        # test client starts one per request, so the semaphore follows the
        # running loop rather than failing in the next one.
        loop = asyncio.get_running_loop()
        if loop is not self._loop:
            self._loop, self._semaphore = loop, asyncio.Semaphore(self.size)
        return self._semaphore

    @contextlib.asynccontextmanager
    async def slot(self):
        semaphore = self._current()
        try:
            # A free slot is taken without suspending, so even a zero wait
            # times out only a caller that actually had to queue.
            async with asyncio.timeout(self.wait):
                await semaphore.acquire()
        except TimeoutError:
            logging.warning(
                "%s gate full: %d running, none free within %.2fs",
                self.name,
                self.size,
                self.wait,
            )
            raise LookupBusy() from None
        try:
            yield
        finally:
            semaphore.release()


# The one gate every lookup takes a slot at: gather() for a target, and the
# self page, which does not go through gather(), for the visitor's own address.
lookup_gate = LookupGate("Lookup", LOOKUP_CONCURRENCY)
