"""Local static analysis of captured payloads.

VirusTotal answers "is this known malware?". This answers "what is it, what
does it target, and who does it talk to?" — from the bytes on disk, with no
network call and no third-party verdict.

Three things are extracted:

- **ELF shape** — class, endianness and machine, parsed straight from the
  header. The architecture is the tell: an MSB MIPS binary is aimed at
  routers, not servers, and a single campaign shipping ARM/MIPS/x86 builds of
  one payload is a botnet covering the consumer-device space.
- **Strings and the IOCs inside them** — embedded addresses, domains and URLs.
  These are C2 infrastructure, which the download URL alone never reveals: the
  attacker's fetch URL is disposable, the hardcoded callback is not.
- **Family attribution** — an ordered table of named signature rules, matched
  literally. Deliberately not YARA: this follows the same reasoning as the
  intent classifier, where being able to point at the exact rule and the exact
  string that fired beats marginal accuracy from an opaque matcher. It also
  avoids compiling libyara on a Raspberry Pi.

Everything here is pure: bytes in, findings out.
"""

from __future__ import annotations

import ipaddress
import json
import re
import struct

# Samples are attacker-supplied. Cap what is read into memory rather than
# trusting the size on disk.
MAX_READ_BYTES = 64 * 1024 * 1024
MIN_STRING_LEN = 6
MAX_STRINGS = 20_000
MAX_IOCS_PER_KIND = 64

ELF_MAGIC = b"\x7fELF"
PT_INTERP = 3

# e_machine → human name. Only values plausible for this corpus are named; the
# rest are reported numerically rather than guessed at.
ELF_MACHINES = {
    2: "SPARC", 3: "i386", 4: "m68k", 8: "MIPS", 15: "PA-RISC",
    18: "SPARC32PLUS", 20: "PowerPC", 21: "PowerPC64", 22: "S390",
    40: "ARM", 42: "SuperH", 43: "SPARCv9", 50: "IA-64",
    62: "x86-64", 183: "AArch64", 243: "RISC-V",
}

ELF_TYPES = {1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}


def parse_elf(data: bytes) -> dict | None:
    """Parse an ELF header. Returns None if this is not an ELF file.

    Hand-rolled rather than pulling in a parsing library: the header is a fixed
    layout, and a malformed one must degrade to None instead of raising into
    the analysis worker.
    """
    if len(data) < 20 or not data.startswith(ELF_MAGIC):
        return None

    ei_class, ei_data = data[4], data[5]
    if ei_class not in (1, 2) or ei_data not in (1, 2):
        return None

    bits = 32 if ei_class == 1 else 64
    endian = "little" if ei_data == 1 else "big"
    e = "<" if ei_data == 1 else ">"

    try:
        e_type, e_machine = struct.unpack_from(f"{e}HH", data, 16)
        if bits == 32:
            (e_phoff,) = struct.unpack_from(f"{e}I", data, 28)
            e_phentsize, e_phnum = struct.unpack_from(f"{e}HH", data, 42)
        else:
            (e_phoff,) = struct.unpack_from(f"{e}Q", data, 32)
            e_phentsize, e_phnum = struct.unpack_from(f"{e}HH", data, 54)
    except struct.error:
        return None

    return {
        "bits": bits,
        "endian": endian,
        "machine": ELF_MACHINES.get(e_machine, f"unknown({e_machine})"),
        "type": ELF_TYPES.get(e_type, str(e_type)),
        "static": _is_static(data, e, bits, e_phoff, e_phentsize, e_phnum),
    }


def _is_static(data, e, bits, e_phoff, e_phentsize, e_phnum) -> bool | None:
    """True when no PT_INTERP segment is present, i.e. statically linked.

    None when the program headers are unreadable — truncated and corrupted
    samples are normal here, and "unknown" is more honest than "static".
    """
    if not e_phoff or not e_phnum or e_phentsize < 4 or e_phnum > 1000:
        return None
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if off + 4 > len(data):
            return None
        try:
            (p_type,) = struct.unpack_from(f"{e}I", data, off)
        except struct.error:
            return None
        if p_type == PT_INTERP:
            return False
    return True


_STRING_RE = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_STRING_LEN)


def extract_strings(data: bytes, limit: int = MAX_STRINGS) -> list[str]:
    """Printable ASCII runs, in file order, capped."""
    out = []
    for m in _STRING_RE.finditer(data):
        out.append(m.group().decode("ascii", "replace"))
        if len(out) >= limit:
            break
    return out


# The surrounding lookarounds matter more than they appear: a bare \b does not
# stop the match, because "." is already a non-word character, so without them
# a Go version table like "1.5.4.32.5.4.52" yields a dozen phantom addresses.
_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_URL_RE = re.compile(r"\b(?:https?|ftp|tftp)://[^\s\"'<>\\|]{3,200}")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,24})\b"
)

# A domain is accepted only when its last label is a real TLD. Blacklisting
# file extensions cannot work: stripped Go binaries are full of symbol names
# like "time.Date", "net.IP" and "os.File" that are indistinguishable from
# domains by shape alone, and the set of such suffixes is unbounded. This is
# the common TLDs plus those favoured for disposable C2 registration.
_TLDS = {
    "com", "net", "org", "info", "biz", "co", "io", "me", "tv", "cc", "us",
    "uk", "de", "fr", "nl", "ru", "su", "ua", "pl", "it", "es", "se", "no",
    "fi", "dk", "ch", "at", "be", "cz", "ro", "gr", "pt", "hu", "bg", "lt",
    "cn", "jp", "kr", "in", "id", "vn", "th", "tw", "hk", "sg", "my", "ph",
    "br", "mx", "ar", "cl", "ca", "au", "nz", "za", "ng", "ke", "eg", "ir",
    "tr", "il", "sa", "ae", "pk", "bd", "kz", "by", "md", "ge", "am", "az",
    "top", "xyz", "site", "online", "club", "icu", "shop", "store", "fun",
    "space", "website", "tech", "live", "life", "world", "today", "link",
    "click", "pw", "tk", "ml", "ga", "cf", "gq", "cyou", "rest", "monster",
    "buzz", "bar", "cam", "casa", "surf", "quest", "sbs", "lol", "wtf",
    "dev", "app", "cloud", "host", "network", "systems", "digital", "email",
    "run", "gg", "to", "ws", "nu", "at", "st", "is", "im", "li", "la",
    "edu", "gov", "mil", "pro", "name", "mobi", "asia", "xxx",
}
# Even with a real TLD, these are toolchain and vendor strings, not infra.
_DOMAIN_NOISE = ("glibc", "gnu.org", "golang.org", "gcc.gnu", "sourceware",
                 "libc.so", "ld-linux", "musl", "openssl.org", "python.org",
                 "github.com", "gopkg.in", "kernel.org", "debian.org", "upx.sf.net",
                 "ubuntu.com", "schemas.xmlsoap", "w3.org", "example.com")


def _keep_ipv4(value: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(value)
    except ValueError:
        return False
    # Never a callback: loopback, unspecified, broadcast, multicast, reserved,
    # link-local and RFC1918. Note that version tables in Go binaries can still
    # yield plausible-looking public addresses, so these stay candidates.
    return not (
        ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_reserved
        or ip.is_private or ip.is_link_local or value == "255.255.255.255"
    )


# Leading labels of Go and C standard-library symbols. These reach here as
# "errors.Is", "unicode.To", "reflect.flag.ro" — shaped like domains, ending in
# real ccTLDs. Rejecting on the first label costs a C2 literally named e.g.
# "net.evil.com", which is a trade worth making against this volume of noise.
_STDLIB_PREFIXES = {
    "runtime", "reflect", "reflectlite", "errors", "unicode", "syscall",
    "atomic", "exec", "os", "net", "io", "fmt", "sync", "time", "sort",
    "strconv", "strings", "bytes", "crypto", "encoding", "math", "hash",
    "bufio", "context", "unsafe", "internal", "abi", "pkix", "asn1",
    "dnsmessage", "godebugs", "exithook", "ascii", "hpke", "poll", "url",
    "big", "ecdsa", "sftp", "ssh", "tls", "x509", "json", "xml", "http",
}


def _keep_domain(value: str) -> bool:
    low = value.lower()
    if any(n in low for n in _DOMAIN_NOISE):
        return False

    return _valid_host(value) and value.split(".")[0].lower() not in _STDLIB_PREFIXES


def _valid_host(value: str) -> bool:
    """Shape checks shared by bare domains and URL hosts."""
    labels = value.split(".")
    tld = labels[-1]

    # Real TLDs, and lowercase as written: "errors.Is" and "abi.Name" are
    # symbols, while a hostname embedded in a binary is written lowercase.
    if tld != tld.lower() or tld.lower() not in _TLDS:
        return False

    # Single- and two-character second-level labels are overwhelmingly symbol
    # fragments ("eq.io", "d.ng", "H.US") rather than registrable names.
    return len(labels) >= 2 and len(labels[-2]) >= 3


def _keep_url(value: str) -> bool:
    """Reject URLs with no real host, e.g. Go's "http://invalidlookup"."""
    rest = value.split("://", 1)[1]
    host = re.split(r"[/?#:]", rest, 1)[0]
    if not host:
        return False
    if _IPV4_RE.fullmatch(host):
        return True
    # Host shape only, without the domain noise list: a payload hosted on
    # github.com is a genuine indicator even though the bare domain is not.
    return _valid_host(host)


def extract_iocs(strings: list[str]) -> dict[str, list[str]]:
    """Mine embedded network indicators out of extracted strings.

    Candidates, not confirmed C2: a hardcoded address in a botnet binary is
    usually its callback, but version numbers also look like IPv4. The rules
    are conservative and the raw string stays available for an analyst.
    """
    ipv4: dict[str, None] = {}
    domains: dict[str, None] = {}
    urls: dict[str, None] = {}

    for s in strings:
        for m in _URL_RE.findall(s):
            m = m.rstrip(".,;")
            if _keep_url(m):
                urls.setdefault(m, None)
        for m in _IPV4_RE.findall(s):
            if _keep_ipv4(m):
                ipv4.setdefault(m, None)
        for m in _DOMAIN_RE.findall(s):
            if _keep_domain(m):
                domains.setdefault(m, None)

    return {
        "ipv4": list(ipv4)[:MAX_IOCS_PER_KIND],
        "domains": list(domains)[:MAX_IOCS_PER_KIND],
        "urls": list(urls)[:MAX_IOCS_PER_KIND],
    }


# Ordered family rules. Each entry is (family, rule_name, signatures) and fires
# when any signature is present. Order matters only for choosing the reported
# family — every rule that matches is recorded, so overlapping families stay
# visible instead of being hidden by the first hit.
FAMILY_RULES: list[tuple[str, str, tuple[bytes, ...]]] = [
    ("mirai", "mirai.busybox_banner", (b"/bin/busybox MIRAI",)),
    ("mirai", "mirai.marker", (b"MIRAI", b"mirai")),
    ("mirai", "mirai.watchdog_kill", (b"/dev/misc/watchdog", b"/dev/watchdog")),
    ("gafgyt", "gafgyt.killattk", (b"KILLATTK", b"LOLNOGTFO")),
    ("gafgyt", "gafgyt.marker", (b"gayfgt", b"GAYFGT")),
    ("tsunami", "tsunami.irc_commands", (b"NOTICE %s :", b"PRIVMSG %s :")),
    ("tsunami", "tsunami.marker", (b"KAITEN", b"Kaiten")),
    ("xorddos", "xorddos.build_marker", (b"BB2FA36AAA9541F0",)),
    ("xorddos", "xorddos.cron_persistence", (b"/etc/cron.hourly/gcc.sh",)),
    ("mozi", "mozi.payload_name", (b"Mozi.m", b"Mozi.a")),
    ("hajime", "hajime.marker", (b"hajime", b"atk.i")),
    ("dofloo", "dofloo.marker", (b"aes.ddos", b"AES.DDoS")),
]

# Not families, but worth recording about a sample.
TRAIT_RULES: list[tuple[str, tuple[bytes, ...]]] = [
    ("trait.go_binary", (b"Go build ID", b"go.buildid")),
    ("trait.upx_packed", (b"UPX!",)),
    ("trait.busybox_shell", (b"/bin/busybox",)),
    ("trait.wget_dropper", (b"wget ", b"tftp -")),
    ("trait.ssh_bruteforce", (b"/etc/ssh/", b"authorized_keys")),
]


def match_rules(data: bytes) -> tuple[str | None, list[str]]:
    """Return (family, matched rule names) for a sample.

    Matching is on raw bytes rather than decoded strings so signatures survive
    binaries that are not valid ASCII anywhere near the marker.
    """
    matched: list[str] = []
    family: str | None = None

    for fam, rule, signatures in FAMILY_RULES:
        if any(sig in data for sig in signatures):
            matched.append(rule)
            if family is None:
                family = fam

    for rule, signatures in TRAIT_RULES:
        if any(sig in data for sig in signatures):
            matched.append(rule)

    return family, matched


def analyze(data: bytes) -> dict:
    """Analyze one sample's bytes. Never raises on malformed input."""
    elf = parse_elf(data)
    strings = extract_strings(data)
    family, matched = match_rules(data)
    return {
        "elf": elf,
        "arch": elf["machine"] if elf else None,
        "family": family,
        "matched_rules": matched,
        "iocs": extract_iocs(strings),
        "string_count": len(strings),
        "size": len(data),
    }


def analyze_path(path) -> dict | None:
    """Analyze a file on disk, or None if it cannot be read.

    The caller is responsible for having confined ``path`` to the downloads
    directory — see services/vt_reporter._resolve_file_path.
    """
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_READ_BYTES)
    except (OSError, ValueError):
        return None
    if not data:
        return None
    return analyze(data)


def to_columns(result: dict) -> dict:
    """Map an analysis result onto CapturedFile columns."""
    elf = result.get("elf") or {}
    return {
        "arch": result.get("arch"),
        "elf_bits": elf.get("bits"),
        "elf_endian": elf.get("endian"),
        "elf_static": elf.get("static"),
        "malware_family": result.get("family"),
        "yara_matches": json.dumps(result.get("matched_rules") or []),
        "static_iocs": json.dumps(result.get("iocs") or {}),
    }


# --- persistence ------------------------------------------------------------
#
# Kept below the pure analysis functions above, which know nothing about the
# database and are tested without one.

import asyncio  # noqa: E402
import logging  # noqa: E402
from datetime import datetime  # noqa: E402

from sqlalchemy import func  # noqa: E402

from app.database import SessionLocal  # noqa: E402
from app.models import CapturedFile  # noqa: E402

logger = logging.getLogger(__name__)

SCAN_INTERVAL = 300  # seconds between passes
BATCH = 25


def analyze_captured_file(file_id: int) -> bool:
    """Analyze one captured file and store the result. Returns True if stored.

    Resolution goes through the VirusTotal reporter's path logic so that the
    confinement rules live in exactly one place: a remote sensor must never be
    able to point analysis at an arbitrary file on this host.
    """
    from app.services.vt_reporter import _resolve_file_path

    db = SessionLocal()
    try:
        captured = db.get(CapturedFile, file_id)
        if captured is None:
            return False

        path = _resolve_file_path(captured.local_path or "", captured.sha256 or "")
        result = analyze_path(path) if path else None
        if result is None:
            # The sample is gone or unreadable. Mark it examined so the worker
            # does not retry it forever, but leave yara_matches NULL so the
            # cleanup script still treats it as un-analyzed.
            captured.static_analyzed_at = datetime.utcnow()
            db.commit()
            return False

        for column, value in to_columns(result).items():
            setattr(captured, column, value)
        captured.static_analyzed_at = datetime.utcnow()
        db.commit()
        logger.info(
            "Analyzed %s: arch=%s family=%s rules=%s",
            (captured.sha256 or "")[:12], result["arch"], result["family"],
            ",".join(result["matched_rules"]) or "-",
        )
        return True
    except Exception:
        logger.exception("Static analysis failed for captured file %s", file_id)
        return False
    finally:
        db.close()


def pending_file_ids(db, limit: int = BATCH) -> list[int]:
    """Distinct captured files that have not been through static analysis.

    Grouped by sha256: the same sample is captured thousands of times, and the
    bytes are identical, so analysing one row per hash is enough.
    """
    rows = (
        db.query(func.min(CapturedFile.id))
        .filter(
            CapturedFile.static_analyzed_at.is_(None),
            CapturedFile.sha256.isnot(None),
            CapturedFile.sha256 != "",
        )
        .group_by(CapturedFile.sha256)
        .limit(limit)
        .all()
    )
    return [r[0] for r in rows]


def propagate_to_duplicates(db, file_id: int) -> int:
    """Copy one analysed row's findings onto every other row with that hash."""
    src = db.get(CapturedFile, file_id)
    if src is None or src.static_analyzed_at is None:
        return 0
    values = {
        "arch": src.arch,
        "elf_bits": src.elf_bits,
        "elf_endian": src.elf_endian,
        "elf_static": src.elf_static,
        "malware_family": src.malware_family,
        "yara_matches": src.yara_matches,
        "static_iocs": src.static_iocs,
        "static_analyzed_at": src.static_analyzed_at,
    }
    updated = (
        db.query(CapturedFile)
        .filter(
            CapturedFile.sha256 == src.sha256,
            CapturedFile.id != src.id,
            CapturedFile.static_analyzed_at.is_(None),
        )
        .update(values, synchronize_session=False)
    )
    db.commit()
    return updated


async def static_analysis_worker():
    """Analyze captured samples in the background.

    Reads bytes from disk only; unlike the other enrichment workers there is no
    third-party API and therefore no rate limit to respect. It still yields
    between files so a large backlog cannot monopolise the event loop.
    """
    while True:
        try:
            db = SessionLocal()
            try:
                file_ids = pending_file_ids(db)
            finally:
                db.close()

            for file_id in file_ids:
                if analyze_captured_file(file_id):
                    db = SessionLocal()
                    try:
                        propagate_to_duplicates(db, file_id)
                    finally:
                        db.close()
                await asyncio.sleep(0)

            if file_ids:
                logger.info("Static analysis: processed %d samples", len(file_ids))
        except Exception:
            logger.exception("Static analysis worker error")

        await asyncio.sleep(SCAN_INTERVAL)
