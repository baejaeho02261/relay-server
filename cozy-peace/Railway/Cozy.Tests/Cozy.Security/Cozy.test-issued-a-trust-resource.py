#!/usr/bin/env python3
"""Check the public issuer resource independently; no Delphi execution claim.

With --original and --packed, also report the exact file-backed PE locations
of valid public anchors. This diagnoses old .data builds without accepting a
writable trust anchor or changing either executable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


MAGIC = b"COZYAISSUERKEY1!"
SETUP_REQUIRED = "COZY_ISSUED_A_PUBLIC_KEY_SETUP_REQUIRED"
ANCHOR_BYTES = 331
RESOURCE_TYPE = 10  # Windows RT_RCDATA
RESOURCE_ID = 311
POWERSHELL = None
MAX_FILE_BYTES = 64 * 1024 * 1024
ROOT = next(p for p in Path(__file__).resolve().parents if (p / "Cozy.Source").is_dir())


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def align4(value: int) -> int:
    return (value + 3) & ~3


def public_anchor(data: bytes) -> str:
    """Validate the exact CNG public format, independently of the server code."""
    require(len(data) == ANCHOR_BYTES, "PUBLIC_ANCHOR_LENGTH")
    require(data[:16] == MAGIC, "PUBLIC_ANCHOR_MAGIC")
    blob = data[48:]
    require(struct.unpack_from("<6I", blob) == (0x31415352, 2048, 3, 256, 0, 0),
            "PUBLIC_RSA_HEADER")
    require(blob[24:27] == b"\x01\x00\x01", "PUBLIC_RSA_EXPONENT")
    require(bool(blob[27] & 0x80) and bool(blob[-1] & 1), "PUBLIC_RSA_MODULUS")
    identity = hashlib.sha256(blob).digest()
    require(data[16:48] == identity, "PUBLIC_ANCHOR_KEY_ID")
    return identity.hex()


def include_anchor(text: str) -> bytes:
    """Read only the canonical Pascal public byte array, never evaluate Pascal."""
    require(SETUP_REQUIRED not in text, SETUP_REQUIRED)
    # Comments cannot contribute byte tokens or fake extra declarations.
    text = re.sub(r"\(\*.*?\*\)|\{.*?\}|//[^\r\n]*", "", text, flags=re.S)
    require(len(re.findall(r"\bCozyIssuedATrustAnchor\b", text, flags=re.I)) == 1,
            "PUBLIC_INCLUDE_IDENTIFIER_COUNT")
    declarations = re.findall(
        r"\bCozyIssuedATrustAnchor\s*:\s*array\s*\[\s*0\s*\.\.\s*330\s*\]"
        r"\s*of\s+Byte\s*=\s*\((.*?)\)\s*;", text, flags=re.I | re.S)
    require(len(declarations) == 1, "PUBLIC_INCLUDE_DECLARATION")
    body = declarations[0]
    require(re.fullmatch(r"\s*\$[0-9A-Fa-f]{2}(?:\s*,\s*\$[0-9A-Fa-f]{2})*\s*", body)
            is not None, "PUBLIC_INCLUDE_BYTE_SYNTAX")
    data = bytes(int(value, 16) for value in re.findall(r"\$([0-9A-Fa-f]{2})", body))
    public_anchor(data)
    return data


def resource_identifier(data: bytes, offset: int, limit: int) -> tuple[int | str, int]:
    require(offset + 2 <= limit, "RESOURCE_IDENTIFIER_TRUNCATED")
    first = struct.unpack_from("<H", data, offset)[0]
    if first == 0xFFFF:
        require(offset + 4 <= limit, "RESOURCE_ORDINAL_TRUNCATED")
        return struct.unpack_from("<H", data, offset + 2)[0], offset + 4
    end = offset
    while end + 2 <= limit:
        if data[end:end + 2] == b"\0\0":
            try:
                return data[offset:end].decode("utf-16-le"), end + 2
            except UnicodeDecodeError as error:
                raise ValueError("RESOURCE_IDENTIFIER_ENCODING") from error
        end += 2
    raise ValueError("RESOURCE_IDENTIFIER_UNTERMINATED")


def resources(data: bytes) -> list[dict]:
    """Parse standard Win32 .res headers, bounds and alignment."""
    require(0 < len(data) <= MAX_FILE_BYTES, "RESOURCE_FILE_LENGTH")
    records = []
    cursor = 0
    while cursor < len(data):
        require(cursor % 4 == 0 and cursor + 8 <= len(data), "RESOURCE_RECORD_TRUNCATED")
        size, header_size = struct.unpack_from("<II", data, cursor)
        require(header_size >= 32 and header_size % 4 == 0,
                "RESOURCE_HEADER_LENGTH")
        payload = cursor + header_size
        require(payload <= len(data) and size <= len(data) - payload,
                "RESOURCE_PAYLOAD_TRUNCATED")
        resource_type, position = resource_identifier(data, cursor + 8, payload)
        name, position = resource_identifier(data, position, payload)
        position = align4(position)
        require(position + 16 == payload, "RESOURCE_HEADER_LAYOUT")
        version, flags, language, resource_version, characteristics = struct.unpack_from(
            "<IHHII", data, position)
        end = payload + size
        next_record = align4(end)
        require(next_record <= len(data), "RESOURCE_PADDING_TRUNCATED")
        require(not any(data[end:next_record]), "RESOURCE_PADDING_NONZERO")
        records.append({"type": resource_type, "name": name, "language": language,
                        "flags": flags, "dataVersion": version,
                        "version": resource_version, "characteristics": characteristics,
                        "data": data[payload:end]})
        cursor = next_record
    return records


def resource_anchor(data: bytes) -> bytes:
    matches = [record for record in resources(data)
               if record["type"] == RESOURCE_TYPE and record["name"] == RESOURCE_ID]
    require(len(matches) == 1, "PUBLIC_RESOURCE_COUNT")
    anchor = matches[0]["data"]
    public_anchor(anchor)
    return anchor


def pe_anchor_report(path: Path, expected: bytes) -> dict:
    data = path.read_bytes()
    require(512 <= len(data) <= MAX_FILE_BYTES and data[:2] == b"MZ", "PE_DOS_HEADER")
    pe = struct.unpack_from("<I", data, 60)[0]
    require(64 <= pe <= len(data) - 24 and data[pe:pe + 4] == b"PE\0\0", "PE_HEADER")
    machine, count = struct.unpack_from("<HH", data, pe + 4)
    optional_size = struct.unpack_from("<H", data, pe + 20)[0]
    optional, table = pe + 24, pe + 24 + optional_size
    require(machine == 0x8664 and 1 <= count <= 96 and optional_size >= 112 and
            table + 40 * count <= len(data), "PE_SECTION_TABLE")
    require(struct.unpack_from("<H", data, optional)[0] == 0x20B, "PE_OPTIONAL_HEADER")
    sections = []
    for index in range(count):
        at = table + 40 * index
        size, offset = struct.unpack_from("<II", data, at + 16)
        flags = struct.unpack_from("<I", data, at + 36)[0]
        require(not size or offset + size <= len(data), "PE_SECTION_BOUNDS")
        sections.append({"name": data[at:at + 8].split(b"\0", 1)[0].decode("ascii", "replace"),
                         "offset": offset, "size": size, "flags": flags})
    hits, cursor = [], 0
    while True:
        cursor = data.find(MAGIC, cursor)
        if cursor < 0:
            break
        hit = {"offset": cursor, "valid": False}
        section = next((section for section in sections
                        if section["offset"] <= cursor and
                        cursor + ANCHOR_BYTES <= section["offset"] + section["size"]), None)
        if section:
            hit.update(section=section["name"], flags=f"0x{section['flags']:08X}",
                       readonly=bool(section["flags"] & 0x40000000) and
                       not bool(section["flags"] & 0x82000000))
        try:
            candidate = data[cursor:cursor + ANCHOR_BYTES]
            hit.update(keyId=public_anchor(candidate), valid=True,
                       matchesSource=candidate == expected)
        except ValueError as error:
            hit["reason"] = str(error)
        hits.append(hit)
        cursor += 1
    eligible = [hit for hit in hits if hit["valid"] and hit.get("readonly")]
    valid = [hit for hit in hits if hit["valid"]]
    diagnosis = ("READONLY_PUBLIC_ANCHOR" if len(eligible) == 1 else
                 "AMBIGUOUS_READONLY_PUBLIC_ANCHORS" if len(eligible) > 1 else
                 "VALID_ANCHOR_IN_WRITABLE_OR_UNMAPPED_SECTION" if valid else
                 "VALID_PUBLIC_ANCHOR_MISSING")
    return {"file": path.name, "size": len(data), "sha512": hashlib.sha512(data).hexdigest(),
            "diagnosis": diagnosis, "eligibleAnchorCount": len(eligible), "hits": hits}


def fixture_record(data: bytes, resource_type: int = RESOURCE_TYPE,
                   name: int = RESOURCE_ID) -> bytes:
    header = struct.pack("<IIHHHHIHHII", len(data), 32, 0xFFFF, resource_type,
                         0xFFFF, name, 0, 0x30, 0, 0, 0)
    return header + data + bytes((-len(data)) % 4)


def synthetic_anchor() -> bytes:
    """Public parser vector only: no operational issuer or private signing key."""
    modulus = b"\x80" + bytes(254) + b"\x01"
    blob = struct.pack("<6I", 0x31415352, 2048, 3, 256, 0, 0) + b"\x01\x00\x01" + modulus
    return MAGIC + hashlib.sha256(blob).digest() + blob


def configured_source_anchor() -> bytes | None:
    text = (ROOT / "Cozy.Source/Cozy.Configuration/Cozy.IssuedA.Trust.inc").read_text(
        encoding="utf-8-sig")
    return None if SETUP_REQUIRED in text else include_anchor(text)


class TrustResourceChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.configuration = ROOT / "Cozy.Source/Cozy.Configuration"
        cls.project = ROOT / "Cozy.Projects/Cozy.Launcher"
        cls.anchor = synthetic_anchor()
        cls.configured = configured_source_anchor()

    def test_public_anchor_integrity_and_structural_mutations(self):
        self.assertEqual(len(public_anchor(self.anchor)), 64)
        for label, mutated in [
            ("truncated", self.anchor[:-1]),
            ("magic", b"X" + self.anchor[1:]),
            ("key identity", self.anchor[:16] + bytes(32) + self.anchor[48:]),
            ("RSA header", self.anchor[:48] + bytes(24) + self.anchor[72:]),
            ("RSA exponent", self.anchor[:72] + b"\x01\x00\x03" + self.anchor[75:]),
            ("modulus width", self.anchor[:75] + bytes([self.anchor[75] & 0x7F]) + self.anchor[76:]),
            ("even modulus", self.anchor[:-1] + bytes([self.anchor[-1] & 0xFE])),
        ]:
            with self.subTest(label=label), self.assertRaises(ValueError):
                public_anchor(mutated)

    def test_include_parser_ignores_comments_but_rejects_ambiguous_or_invalid_data(self):
        declaration = ("const CozyIssuedATrustAnchor: array[0..330] of Byte = (" +
                       ",".join(f"${value:02X}" for value in self.anchor) + ");")
        self.assertEqual(include_anchor("{ $FF }\n" + declaration + "\n// $AA"), self.anchor)
        for value in [declaration + declaration, declaration.replace("$43,", "0x43,", 1),
                      declaration.replace("0..330", "0..331", 1),
                      declaration.replace("$43,", "$143,", 1)]:
            with self.subTest(value=value[:70]), self.assertRaises(ValueError):
                include_anchor(value)

    def test_resource_parser_rejects_truncation_duplicates_and_wrong_resource_identity(self):
        valid = fixture_record(self.anchor)
        self.assertEqual(resource_anchor(valid), self.anchor)
        bad_header = bytearray(valid)
        struct.pack_into("<I", bad_header, 4, 0)
        for value in [valid[:-1], bytes(bad_header), valid + valid,
                      fixture_record(self.anchor, name=312),
                      fixture_record(self.anchor, resource_type=24)]:
            with self.subTest(size=len(value)), self.assertRaises(ValueError):
                resource_anchor(value)

    def test_unconfigured_source_contains_no_bundled_operational_anchor_or_resource(self):
        if self.configured is not None:
            return  # Explicit operator setup is validated separately below.
        text = (self.configuration / "Cozy.IssuedA.Trust.inc").read_text(encoding="utf-8-sig")
        self.assertIn(SETUP_REQUIRED, text)
        self.assertNotIn("CozyIssuedATrustAnchor", text)
        self.assertNotIn(MAGIC.decode("ascii"), text)
        self.assertFalse((self.configuration / "Cozy.IssuedA.Trust.bin").exists(),
                         "Remove stale generated trust.bin before distributing an unconfigured source")
        self.assertFalse((self.project / "Cozy.LauncherResources.res").exists(),
                         "Remove stale generated launcher resources before distributing an unconfigured source")
        with self.assertRaisesRegex(ValueError, SETUP_REQUIRED):
            include_anchor(text)

    def test_configured_binary_and_compiled_resource_match_source_when_present(self):
        if self.configured is None:
            return  # Parser fixtures never stand in for an operational public key.
        binary = self.configuration / "Cozy.IssuedA.Trust.bin"
        if binary.exists():
            self.assertEqual(binary.read_bytes(), self.configured)
        compiled_path = self.project / "Cozy.LauncherResources.res"
        if not compiled_path.exists():
            return  # A configured include may precede its first actual build.
        compiled = compiled_path.read_bytes()
        self.assertEqual(resource_anchor(compiled), self.configured)
        self.assertEqual(compiled.count(self.configured), 1)
        records = resources(compiled)
        self.assertTrue(any(record["type"] == 24 and record["name"] == 1 for record in records),
                        "Application manifest resource was lost")
        self.assertTrue(any(record["type"] == 16 and record["name"] == 1 for record in records),
                        "Application version resource was lost")

    def test_powershell_preparation_creates_replaces_and_reuses_public_resource(self):
        if not POWERSHELL:
            self.skipTest("Actual public resource preparation requires PowerShell; no Windows execution claim")
        with tempfile.TemporaryDirectory(prefix="cozy-public-trust-") as temp:
            native = Path(temp) / "source with spaces 한글"
            build = native / "Cozy.Build"
            config = native / "Cozy.Source/Cozy.Configuration"
            build.mkdir(parents=True)
            config.mkdir(parents=True)
            script = build / "Cozy.Prepare-IssuedATrust.ps1"
            script.write_bytes((ROOT / "Cozy.Build/Cozy.Prepare-IssuedATrust.ps1").read_bytes())
            include = config / "Cozy.IssuedA.Trust.inc"
            resource = config / "Cozy.IssuedA.Trust.bin"

            def write_include(anchor):
                include.write_text("const CozyIssuedATrustAnchor: array[0..330] of Byte = (" +
                                   ",".join(f"${value:02X}" for value in anchor) + ");\n",
                                   encoding="utf-8-sig")

            def run(explicit_root, expected_code=0):
                command = [POWERSHELL, "-NoLogo", "-NoProfile", "-NonInteractive",
                           "-ExecutionPolicy", "Bypass", "-File", str(script)]
                if explicit_root:
                    command.extend(["-SourceRoot", str(native)])
                result = subprocess.run(command, capture_output=True, encoding="utf-8",
                                        errors="replace", timeout=30)
                self.assertEqual(result.returncode, expected_code, result.stderr or result.stdout)
                return result

            include.write_text("{$MESSAGE ERROR '" + SETUP_REQUIRED + "'}\n", encoding="utf-8-sig")
            failed = run(True, 1)
            self.assertIn(SETUP_REQUIRED, failed.stderr or failed.stdout)
            self.assertFalse(resource.exists())
            write_include(self.anchor)
            run(False)  # Standalone -File resolves its own source root in the body.
            self.assertEqual(resource.read_bytes(), self.anchor)
            changed = bytearray(self.anchor)
            changed[100] ^= 1
            changed[16:48] = hashlib.sha256(changed[48:]).digest()
            changed = bytes(changed)
            self.assertNotEqual(public_anchor(changed), public_anchor(self.anchor))
            write_include(changed)
            run(True)  # Existing output forces the atomic replacement branch.
            self.assertEqual(resource.read_bytes(), changed)
            self.assertEqual({file.name for file in config.iterdir()}, {include.name, resource.name})
            before = resource.stat().st_mtime_ns
            run(True)
            self.assertEqual(resource.read_bytes(), changed)
            self.assertEqual(resource.stat().st_mtime_ns, before)
            include.write_text("{$MESSAGE ERROR '" + SETUP_REQUIRED + "'}\n", encoding="utf-8-sig")
            failed = run(True, 1)
            self.assertIn(SETUP_REQUIRED, failed.stderr or failed.stdout)
            self.assertEqual(resource.read_bytes(), changed,
                             "Setup failure must not mistake an older generated output for configuration")

    def test_resource_script_and_runtime_use_resource_not_writable_typed_array(self):
        script = (self.project / "Cozy.Launcher.rc").read_text(encoding="utf-8-sig")
        paths = re.findall(r'^\s*311\s+RCDATA\s+"([^"\r\n]+)"\s*$', script,
                           flags=re.I | re.M)
        self.assertEqual(len(paths), 1, "Issuer RCDATA 311 must be declared exactly once")
        resource_path = (self.project / paths[0].replace("\\", "/")).resolve()
        self.assertEqual(resource_path, (self.configuration / "Cozy.IssuedA.Trust.bin").resolve())
        unit = (ROOT / "Cozy.Source/Cozy.Application/Cozy.IssuedA.pas").read_text(encoding="utf-8-sig")
        self.assertRegex(unit, r"\bTResourceStream\.CreateFromID\s*\(")
        self.assertRegex(unit, r"\bRT_RCDATA\b")
        self.assertRegex(unit, r"\b311\b")
        self.assertNotRegex(unit, r"(?i)\{\$I(?:NCLUDE)?\s+[^}]*Cozy\.IssuedA\.Trust\.inc")
        self.assertNotIn("CozyIssuedATrustAnchor", unit,
                         "Runtime must not compile the writable public byte array")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--powershell", help="Existing pwsh/powershell.exe for actual public resource generation")
    parser.add_argument("--original", type=Path)
    parser.add_argument("--packed", type=Path)
    parser.add_argument("--require-readonly", action="store_true",
                        help="Fail if either supplied executable lacks exactly one readonly anchor")
    args = parser.parse_args()
    global ROOT, POWERSHELL
    POWERSHELL = args.powershell or shutil.which("pwsh") or shutil.which("powershell.exe")
    if args.source_root:
        ROOT = args.source_root.resolve()
    if bool(args.original) != bool(args.packed):
        parser.error("--original and --packed must be supplied together")
    if args.require_readonly and not args.original:
        parser.error("--require-readonly needs --original and --packed")
    result = unittest.TextTestRunner(verbosity=1).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(TrustResourceChecks))
    if not result.wasSuccessful():
        return 1
    if args.original:
        anchor = configured_source_anchor()
        require(anchor is not None, SETUP_REQUIRED + ": configure the server issuer public key before comparing EXEs")
        reports = [pe_anchor_report(path, anchor) for path in [args.original, args.packed]]
        original, packed = args.original.read_bytes(), args.packed.read_bytes()
        changed, first, last = 0, None, None
        for index, (left, right) in enumerate(zip(original, packed)):
            if left != right:
                changed += 1
                if first is None:
                    first = index
                last = index
        comparison = {"sameLength": len(original) == len(packed), "changedSharedBytes": changed,
                      "firstChangedOffset": first, "lastChangedOffset": last}
        print(json.dumps({"windowsExecution": "NOT_RUN", "executables": reports,
                          "comparison": comparison}, ensure_ascii=False, indent=2))
        if args.require_readonly and any(report["eligibleAnchorCount"] != 1 or
                                        not all(hit.get("matchesSource") for hit in report["hits"]
                                                if hit["valid"] and hit.get("readonly"))
                                        for report in reports):
            return 1
    print("PASS: public issuer resource contracts; public key setup " +
          ("REQUIRED" if configured_source_anchor() is None else "CONFIGURED") +
          "; Delphi/Windows execution NOT_RUN")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, struct.error) as error:
        print("FAIL: " + str(error), file=sys.stderr)
        sys.exit(1)
