#!/usr/bin/env python3
"""Honeypot sensor agent.

Runs next to a Cowrie instance on a remote sensor, tails its JSON event log,
and pushes batches to the hub's /api/ingest endpoint.

Design constraints this satisfies:

- The sensor sits behind NAT, so it must connect *outbound*; the hub never
  initiates.
- A trans-Pacific link drops. Events are spooled to disk and replayed later
  rather than lost, and the read cursor only advances after the hub confirms.
- Retries must not double-count. Every event carries a monotonically
  increasing ``seq`` inside an ``epoch`` that identifies this agent's state
  generation, and the hub keeps the high-water mark.
- The sensor holds no secrets beyond its own ingest token, and does no
  enrichment: geolocation, classification, and reporting all happen on the hub.

Only the Python standard library is used, so an old machine needs nothing
installed beyond python3.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import signal
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

AGENT_VERSION = "1.0.0"

DEFAULT_BATCH_SIZE = 200
DEFAULT_FLUSH_SECS = 10
DEFAULT_HEARTBEAT_SECS = 60
DEFAULT_SPOOL_LIMIT = 50_000
POLL_SECS = 1.0
# Cowrie events the hub acts on. Filtering here keeps the uplink small.
WANTED_EVENTS = {
    "cowrie.session.connect",
    "cowrie.session.closed",
    "cowrie.login.failed",
    "cowrie.login.success",
    "cowrie.command.input",
    "cowrie.session.file_download",
    "cowrie.session.file_upload",
}

log = logging.getLogger("sensor-agent")
_running = True


class State:
    """Durable agent state: log cursor, epoch, sequence, and pending spool.

    ``epoch`` changes only when state is created from scratch. The hub treats a
    new epoch as "sequence numbers restarted", which is what lets a rebuilt
    sensor resume without being mistaken for a replay attack.
    """

    def __init__(self, path: Path):
        self.path = path
        self.epoch = uuid.uuid4().hex
        self.seq = 0
        self.offset = 0
        self.inode = 0
        self.spool: list[dict] = []
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text())
            self.epoch = data.get("epoch", self.epoch)
            self.seq = int(data.get("seq", 0))
            self.offset = int(data.get("offset", 0))
            self.inode = int(data.get("inode", 0))
            self.spool = data.get("spool", [])
        except (json.JSONDecodeError, ValueError, OSError) as exc:
            log.warning("Could not read state (%s) — starting fresh", exc)

    def save(self) -> None:
        payload = {
            "epoch": self.epoch,
            "seq": self.seq,
            "offset": self.offset,
            "inode": self.inode,
            "spool": self.spool,
        }
        tmp = self.path.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(payload))
            tmp.replace(self.path)  # atomic: never leave a half-written state
        except OSError as exc:
            log.error("Could not persist state: %s", exc)

    def add(self, event: dict, spool_limit: int) -> None:
        self.seq += 1
        self.spool.append({"seq": self.seq, "event": event})
        if len(self.spool) > spool_limit:
            # Prefer recent intelligence over a complete backlog when the
            # uplink has been down long enough to threaten the disk.
            dropped = len(self.spool) - spool_limit
            self.spool = self.spool[dropped:]
            log.warning("Spool over %d events — dropped %d oldest", spool_limit, dropped)


def post_json(url: str, token: str, payload: dict, timeout: int = 30) -> dict:
    body = json.dumps(payload).encode()
    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-Sensor-Key": token,
            "User-Agent": f"honeypot-sensor-agent/{AGENT_VERSION}",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as resp:
        return json.loads(resp.read().decode() or "{}")


def flush(state: State, hub: str, token: str, batch_size: int) -> bool:
    """Send spooled events oldest-first. Returns False when the uplink fails."""
    while state.spool:
        batch = state.spool[:batch_size]
        try:
            result = post_json(
                f"{hub}/api/ingest",
                token,
                {"epoch": state.epoch, "events": batch},
            )
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode()[:200]
            if exc.code in (401, 403):
                log.error("Hub rejected our token (%s) — check the sensor key", exc.code)
                return False
            if exc.code == 413:
                # Too large for the hub: halve and retry rather than wedge.
                if batch_size > 10:
                    return flush(state, hub, token, batch_size // 2)
                log.error("Hub rejected even a small batch: %s", detail)
                return False
            log.warning("Hub returned %s: %s", exc.code, detail)
            return False
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            log.warning("Uplink unavailable (%s) — keeping %d events spooled",
                        exc, len(state.spool))
            return False

        # Only drop events the hub has acknowledged.
        state.spool = state.spool[len(batch):]
        state.save()
        log.info(
            "Sent %d events (accepted=%s skipped=%s), %d still spooled",
            len(batch), result.get("accepted"), result.get("skipped"), len(state.spool),
        )
    return True


def heartbeat(hub: str, token: str, log_path: Path) -> None:
    """Report liveness and host telemetry so the hub can alert on both."""
    usage = shutil.disk_usage(log_path.parent if log_path.parent.exists() else "/")
    age = None
    try:
        age = max(0.0, time.time() - log_path.stat().st_mtime)
    except OSError:
        pass
    try:
        post_json(
            f"{hub}/api/ingest/heartbeat",
            token,
            {
                "agent_version": AGENT_VERSION,
                "disk_free_bytes": usage.free,
                "disk_total_bytes": usage.total,
                "cowrie_log_age_secs": age,
            },
            timeout=15,
        )
    except Exception as exc:  # never let a failed heartbeat stop tailing
        log.debug("Heartbeat failed: %s", exc)


def read_new_lines(state: State, log_path: Path) -> list[dict]:
    """Read whatever is new since the stored cursor, following rotation."""
    try:
        stat = log_path.stat()
    except FileNotFoundError:
        return []

    # A new inode or a shrunken file means the log rotated; restart at zero.
    if stat.st_ino != state.inode:
        log.info("Log rotated (new inode) — reading from start")
        state.inode = stat.st_ino
        state.offset = 0
    elif stat.st_size < state.offset:
        log.info("Log truncated — reading from start")
        state.offset = 0

    if stat.st_size == state.offset:
        return []

    events: list[dict] = []
    with log_path.open("r", errors="replace") as handle:
        handle.seek(state.offset)
        for line in handle:
            if not line.endswith("\n"):
                # Partial final line: leave the cursor before it so the
                # remainder is read once fully written.
                break
            line = line.strip()
            state.offset = handle.tell()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("eventid") in WANTED_EVENTS:
                events.append(event)
    return events


def _stop(signum, _frame) -> None:
    global _running
    log.info("Signal %s — shutting down", signum)
    _running = False


def main() -> int:
    parser = argparse.ArgumentParser(description="Honeypot sensor agent")
    parser.add_argument("--hub", default=os.environ.get("HUB_URL", ""),
                        help="Hub base URL, e.g. https://honeypottracker.live")
    parser.add_argument("--token", default=os.environ.get("SENSOR_TOKEN", ""),
                        help="Ingest token issued by the hub")
    parser.add_argument("--log", default=os.environ.get(
        "COWRIE_LOG_PATH", "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"))
    parser.add_argument("--state", default=os.environ.get(
        "STATE_PATH", "/var/lib/honeypot-sensor/state.json"))
    parser.add_argument("--batch-size", type=int,
                        default=int(os.environ.get("BATCH_SIZE", DEFAULT_BATCH_SIZE)))
    parser.add_argument("--flush-secs", type=int,
                        default=int(os.environ.get("FLUSH_SECS", DEFAULT_FLUSH_SECS)))
    parser.add_argument("--spool-limit", type=int,
                        default=int(os.environ.get("SPOOL_LIMIT", DEFAULT_SPOOL_LIMIT)))
    parser.add_argument("--from-start", action="store_true",
                        help="On first run, send the whole existing log")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    if not args.hub or not args.token:
        log.error("--hub and --token are required (or set HUB_URL / SENSOR_TOKEN)")
        return 2

    hub = args.hub.rstrip("/")
    log_path = Path(args.log)
    state_path = Path(args.state)
    state_path.parent.mkdir(parents=True, exist_ok=True)

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    state = State(state_path)
    first_run = not state_path.exists()
    if first_run and not args.from_start and log_path.exists():
        # Default to only new activity, so a fresh agent does not replay months
        # of history into the hub.
        stat = log_path.stat()
        state.offset = stat.st_size
        state.inode = stat.st_ino
        state.save()
        log.info("Starting at end of %s (%d bytes)", log_path, stat.st_size)

    log.info("Agent %s reporting to %s", AGENT_VERSION, hub)
    last_flush = 0.0
    last_heartbeat = 0.0

    while _running:
        try:
            events = read_new_lines(state, log_path)
            for event in events:
                state.add(event, args.spool_limit)
            if events:
                state.save()

            now = time.monotonic()
            if state.spool and (now - last_flush) >= args.flush_secs:
                flush(state, hub, args.token, args.batch_size)
                last_flush = now
            if (now - last_heartbeat) >= DEFAULT_HEARTBEAT_SECS:
                heartbeat(hub, args.token, log_path)
                last_heartbeat = now
        except Exception:
            log.exception("Agent loop error — continuing")

        time.sleep(POLL_SECS)

    # Best-effort final drain so a clean restart loses nothing.
    if state.spool:
        flush(state, hub, args.token, args.batch_size)
    state.save()
    log.info("Stopped with %d events spooled", len(state.spool))
    return 0


if __name__ == "__main__":
    sys.exit(main())
