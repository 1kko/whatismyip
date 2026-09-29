"""SQLite persistence for subdomain lists.

No network, and no knowledge of where the names came from: `subdomains.py` owns
the sources, this module owns durability. Split that way so the store can be
tested against a temporary database with no mocking at all.

SQLite rather than one JSON file per domain, for three reasons in order of
weight. The key is a domain supplied by whoever made the request, and a bound
parameter cannot be talked into traversing a path the way a filename can.
Finding the oldest rows is one indexed query rather than a directory walk with a
parse per file. Bounding the store is one DELETE.

Every operation is wrapped: this is a cache in front of a third party, so a
read-only volume, a full disk, or a truncated file must cost us the cache and
not the request.
"""

import json
import logging
import os
import sqlite3
import threading
import time
from dataclasses import dataclass

from config import SUBDOMAIN_MAX_ROWS, SUBDOMAIN_STORE_FILE

_SCHEMA = """
CREATE TABLE IF NOT EXISTS subdomains (
  domain     TEXT PRIMARY KEY,
  names      TEXT    NOT NULL,
  count      INTEGER NOT NULL,
  truncated  INTEGER NOT NULL DEFAULT 0,
  source     TEXT    NOT NULL,
  fetched_at REAL    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_subdomains_fetched_at ON subdomains(fetched_at);
"""


@dataclass(frozen=True)
class Entry:
    domain: str
    names: list[str]
    count: int
    truncated: bool
    source: str
    fetched_at: float

    def age(self) -> float:
        return time.time() - self.fetched_at


class SubdomainStore:
    """One connection guarded by a lock.

    Rows are small and writes are rare, so a lock is both sufficient and
    obviously correct — cheaper to reason about than a connection pool. Callers
    on the event loop must still reach these methods through asyncio.to_thread,
    because sqlite3 blocks.
    """

    def __init__(
        self,
        path: str = SUBDOMAIN_STORE_FILE,
        max_rows: int = SUBDOMAIN_MAX_ROWS,
    ):
        self._path = path
        self._max_rows = max_rows
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None
        self._open()

    def _open(self) -> None:
        conn = None
        try:
            os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
            conn = sqlite3.connect(self._path, check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(_SCHEMA)
            conn.commit()
            self._conn = conn
        except Exception:
            # Degraded, not broken: get() returns None and put() is a no-op, so
            # every lookup pays the fetch and nothing else changes.
            logging.exception("Subdomain store unavailable at %s", self._path)
            # Close the handle explicitly if connect() succeeded but setup failed.
            if conn is not None:
                try:
                    conn.close()
                except Exception:  # noqa: S110
                    pass
            self._conn = None

    def get(self, domain: str) -> Entry | None:
        if self._conn is None:
            return None
        try:
            with self._lock:
                row = self._conn.execute(
                    "SELECT domain, names, count, truncated, source, fetched_at "
                    "FROM subdomains WHERE domain = ?",
                    (domain,),
                ).fetchone()
        except Exception:
            logging.exception("Subdomain store read failed")
            return None
        if row is None:
            return None
        return Entry(
            domain=row[0],
            names=json.loads(row[1]),
            count=row[2],
            truncated=bool(row[3]),
            source=row[4],
            fetched_at=row[5],
        )

    def put(
        self,
        domain: str,
        names: list[str],
        count: int,
        truncated: bool,
        source: str,
    ) -> None:
        if self._conn is None:
            return
        try:
            with self._lock:
                self._conn.execute(
                    "INSERT INTO subdomains "
                    "(domain, names, count, truncated, source, fetched_at) "
                    "VALUES (?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(domain) DO UPDATE SET "
                    "names=excluded.names, count=excluded.count, "
                    "truncated=excluded.truncated, source=excluded.source, "
                    "fetched_at=excluded.fetched_at",
                    (
                        domain,
                        json.dumps(names),
                        count,
                        int(truncated),
                        source,
                        time.time(),
                    ),
                )
                self._conn.commit()
        except Exception:
            logging.exception("Subdomain store write failed for %s", domain)
            return
        self.prune()

    def prune(self) -> int:
        """Trim to max_rows, oldest first.

        Called after a write rather than on a timer: a write is the only thing
        that can breach the bound, and a store nobody writes to needs no
        trimming. That is also why this feature adds no scheduler job.
        """
        if self._conn is None:
            return 0
        try:
            with self._lock:
                cursor = self._conn.execute(
                    "DELETE FROM subdomains WHERE domain IN ("
                    "  SELECT domain FROM subdomains"
                    "  ORDER BY fetched_at DESC LIMIT -1 OFFSET ?"
                    ")",
                    (self._max_rows,),
                )
                self._conn.commit()
                return cursor.rowcount
        except Exception:
            logging.exception("Subdomain store prune failed")
            return 0

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.close()
                except Exception:
                    logging.exception("Subdomain store close failed")
                finally:
                    self._conn = None
