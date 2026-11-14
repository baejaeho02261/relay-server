#!/usr/bin/env python3
"""Check release metadata and optionally execute the actual PowerShell generator.

Usage: python Cozy.test-release-metadata.py --powershell <pwsh-or-powershell.exe>
PowerShell execution is not a Delphi/MSBuild/Windows runtime test.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
import re
import shutil
import struct
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = next(p for p in Path(__file__).resolve().parents if (p / "Cozy.Source").is_dir())
_string_spec = importlib.util.spec_from_file_location('cozy_source_strings', ROOT / 'Cozy.Build/Cozy.SourceStrings.py')
_strings = importlib.util.module_from_spec(_string_spec)
_string_spec.loader.exec_module(_strings)
CONFIG = Path("Cozy.Source/Cozy.Configuration")
SPEC = CONFIG / "Cozy.ReleaseMetadata.json"
SCRIPT = ROOT / "Cozy.Build/Cozy.Prepare-ReleaseMetadata.ps1"
PROJECTS = {"A": "Cozy.Launcher", "B": "Cozy.Client", "O": "Cozy.Overlay"}
POWERSHELL = None
MSBUILD = "{http://schemas.microsoft.com/developer/msbuild/2003}"
ASM = "{urn:schemas-microsoft-com:asm.v1}"
module_spec = importlib.util.spec_from_file_location(
    "cozy_resource_parser", ROOT / "Cozy.Tests/Cozy.Security/Cozy.test-issued-a-trust-resource.py")
resources = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(resources)


def string_value(data, key):
    marker = (key + "\0").encode("utf-16-le")
    assert data.count(marker) == 1, key
    at = data.index(marker)
    _, value_length, kind = struct.unpack_from("<HHH", data, at - 6)
    assert kind == 1
    start = (at + len(marker) + 3) & ~3
    return data[start:start + value_length * 2].decode("utf-16-le").rstrip("\0")


class MetadataSourceChecks(unittest.TestCase):
    def test_obsolete_relay_application_version_is_absent_protocol_is_unchanged(self):
        for path in (ROOT / "Cozy.Source").rglob("*"):
            if path.suffix.lower() in (".pas", ".inc"):
                self.assertNotRegex(path.read_text(encoding="utf-8-sig"), r"(?i)\bAPP_VERSION\b", str(path))
        config = (ROOT / "Cozy.Source/Cozy.Network/Cozy.Relay.Config.pas").read_text(encoding="utf-8-sig")
        self.assertRegex(config, r"\bPROTOCOL_VERSION\s*=\s*2\s*;")

    def test_all_project_units_opt_into_existing_release_metadata_policy(self):
        mapping = json.loads((ROOT / CONFIG / "Cozy.StringUnits.map.json").read_text(encoding="utf-8"))
        constant_units = {unit["path"] for unit in mapping["units"]}
        for path in (ROOT / "Cozy.Source").rglob("*.pas"):
            with self.subTest(unit=path.name):
                text = path.read_text(encoding="utf-8-sig")
                if path.relative_to(ROOT).as_posix() in constant_units:
                    # Strict pure-constant parsing permits no types, routines,
                    # imports or initialization; these units cannot emit RTTI.
                    self.assertEqual(_strings.read_source(path), text)
                    continue
                directive = "{$I ..\\Cozy.Configuration\\Cozy.Metadata.inc}"
                self.assertEqual(text.count(directive), 1)
                self.assertLess(text.index(directive), text.lower().index("\ninterface"))
        policy = (ROOT / CONFIG / "Cozy.Metadata.inc").read_text(encoding="utf-8-sig")
        self.assertIn("{$RTTI EXPLICIT METHODS([]) PROPERTIES([]) FIELDS([])}", policy)
        self.assertIn("{$WEAKLINKRTTI ON}", policy)

    def test_resources_manifests_and_runtime_include_match_one_version(self):
        spec = json.loads((ROOT / SPEC).read_text())
        parts = tuple(map(int, spec["version"].split(".")))
        inc = (ROOT / CONFIG / "Cozy.Version.inc").read_text()
        self.assertEqual(re.findall(r"AppVersion\s*=\s*'([^']+)'", inc), [spec["version"]])
        api = (ROOT / "Cozy.Source/Cozy.Platform/Cozy.Api.pas").read_text(encoding="utf-8-sig")
        self.assertIn("{$I ..\\Cozy.Configuration\\Cozy.Version.inc}", api)
        self.assertNotRegex(api, r"AppVersion\s*=\s*'")
        configured_anchor = resources.configured_source_anchor()
        for role, name in PROJECTS.items():
            with self.subTest(role=role):
                directory = ROOT / "Cozy.Projects" / name
                rc = (directory / (name + ".rc")).read_bytes().decode("ascii")
                for kind in ("FILEVERSION", "PRODUCTVERSION"):
                    value = re.findall(r"(?m)^\s*" + kind + r"\s+([0-9,]+)", rc)
                    self.assertEqual(value, [",".join(map(str, parts))])
                manifest_bytes = (directory / (name + ".manifest")).read_bytes()
                manifest = ET.fromstring(manifest_bytes)
                self.assertEqual(manifest.find(ASM + "assemblyIdentity").get("version"), spec["version"])
                self.assertEqual(manifest.find(ASM + "description").text, spec["descriptions"][role])
                self.assertEqual(manifest.find(".//{urn:schemas-microsoft-com:asm.v3}requestedExecutionLevel").attrib,
                                 {"level": "asInvoker", "uiAccess": "false"})
                if role == "O":
                    self.assertIn(b"PerMonitorV2, PerMonitor", manifest_bytes)
                compiled_resource = directory / (name + "Resources.res")
                if role == "A":
                    self.assertEqual(re.findall(r'(?m)^\s*311\s+RCDATA\s+"([^"]+)"\s*$', rc),
                                     [r"..\..\Cozy.Source\Cozy.Configuration\Cozy.IssuedA.Trust.bin"])
                    if configured_anchor is None:
                        # A source delivery has no default operational issuer.
                        # Keep build metadata, but never ship stale compiled trust.
                        self.assertFalse((ROOT / CONFIG / "Cozy.IssuedA.Trust.bin").exists())
                        self.assertFalse(compiled_resource.exists())
                        for field, expected in {"FileVersion": spec["version"], "ProductVersion": spec["version"],
                                                "CompanyName": spec["companyName"], "ProductName": spec["productName"],
                                                "FileDescription": spec["descriptions"][role]}.items():
                            self.assertEqual(re.findall(r'(?m)^\s*VALUE\s+"' + field + r'",\s*"([^"]+)"\s*$', rc),
                                             [expected + r"\0"])
                        continue
                records = resources.resources(compiled_resource.read_bytes())
                versions = [r["data"] for r in records if r["type"] == 16 and r["name"] == 1]
                self.assertEqual(len(versions), 1)
                v = versions[0]
                root_name = "VS_VERSION_INFO\0".encode("utf-16-le")
                self.assertEqual(v[6:6 + len(root_name)], root_name)
                value_at = (6 + len(root_name) + 3) & ~3
                fixed = struct.unpack_from("<6I", v, value_at)
                self.assertEqual(fixed[:2], (0xFEEF04BD, 0x10000))
                self.assertEqual(fixed[2:], (parts[0] << 16 | parts[1], parts[2] << 16 | parts[3]) * 2)
                for field, expected in {"FileVersion": spec["version"], "ProductVersion": spec["version"],
                                        "CompanyName": spec["companyName"], "ProductName": spec["productName"],
                                        "FileDescription": spec["descriptions"][role]}.items():
                    self.assertEqual(string_value(v, field), expected)
                self.assertEqual([r["data"] for r in records if r["type"] == 24 and r["name"] == 1],
                                 [manifest_bytes])
                if role == "A":
                    self.assertEqual((ROOT / CONFIG / "Cozy.IssuedA.Trust.bin").read_bytes(), configured_anchor)
                    self.assertEqual(resources.resource_anchor(compiled_resource.read_bytes()), configured_anchor)
                if role == "O":
                    self.assertEqual([r["data"] for r in records if r["type"] == 10 and r["name"] == 310],
                                     [(ROOT / "Cozy.ImGui/Cozy.Vendor/Cozy.Legal/Cozy.LICENSE.txt").read_bytes()])

    def test_normal_build_prepares_metadata_before_resource_and_delphi_compilation(self):
        target = ET.parse(ROOT / "Cozy.Build/Cozy.ReleaseMetadata.targets").getroot().find(MSBUILD + "Target")
        self.assertEqual(target.get("DependsOnTargets"), "ValidateProductionIsolation")
        self.assertEqual(set(target.get("BeforeTargets").split(";")),
                         {"BeforeBuild", "PreBuildEvent", "_PasCoreCompile", "PrepareOverlayNative"})
        commands = target.findall(MSBUILD + "Exec")
        self.assertEqual(len(commands), 3)
        self.assertIn("Cozy.Prepare-ReleaseMetadata.ps1", commands[0].get("Command"))
        self.assertIn("Cozy.Prepare-IssuedATrust.ps1", commands[1].get("Command"))
        self.assertIn("brcc32.exe", commands[2].get("Command"))
        self.assertTrue(all("ContinueOnError" not in x.attrib and "IgnoreExitCode" not in x.attrib for x in commands))
        for name in PROJECTS.values():
            doc = ET.parse(ROOT / "Cozy.Projects" / name / (name + ".dproj")).getroot()
            imports = [x.get("Project") for x in doc.findall(MSBUILD + "Import")]
            self.assertEqual(imports.count("..\\..\\Cozy.Build\\Cozy.ReleaseMetadata.targets"), 1)
            self.assertGreater(imports.index("..\\..\\Cozy.Build\\Cozy.ReleaseMetadata.targets"),
                               imports.index("..\\..\\Cozy.Build\\Cozy.BuildIsolation.targets"))

    def test_existing_output_replacement_never_uses_a_null_backup_path(self):
        script = SCRIPT.read_text(encoding="utf-8-sig")
        writer = script.split("function Write-MetadataText", 1)[1].split("\ntry {", 1)[0]
        self.assertNotIn("[NullString]", writer)
        self.assertNotRegex(writer, r"\[IO\.File\]::Replace\([^\r\n]*,\s*\$null\s*\)")
        self.assertRegex(writer, r"\$replacementBackup\s*=\s*Join-Path\s+\(\[IO\.Path\]::GetDirectoryName\(\$Path\)\)")
        self.assertIn("[guid]::NewGuid().ToString('N')", writer)
        self.assertIn("Test-Path -LiteralPath $replacementBackup", writer)
        replace = "[IO.File]::Replace($temporary, $Path, $replacementBackup)"
        delete = "[IO.File]::Delete($replacementBackup)"
        self.assertIn(replace, writer)
        self.assertGreater(writer.index(delete), writer.index(replace))
        failure = writer.split("} catch {", 1)[1]
        self.assertIn("[IO.File]::Exists($replacementBackup)", failure)
        self.assertIn("Previous release metadata backup retained:", failure)
        self.assertNotIn(delete, failure)


class GeneratorExecutionChecks(unittest.TestCase):
    def setUp(self):
        if POWERSHELL is None:
            self.skipTest("Actual generator execution requires --powershell; this is not a Windows build")
        self.temp = tempfile.TemporaryDirectory(prefix="Cozy-ReleaseMetadata-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "Railway source with spaces"
        (self.root / CONFIG).mkdir(parents=True)
        shutil.copy2(ROOT / SPEC, self.root / SPEC)
        for name in PROJECTS.values():
            directory = self.root / "Cozy.Projects" / name
            directory.mkdir(parents=True)
            for ext in ("rc", "manifest"):
                shutil.copy2(ROOT / "Cozy.Projects" / name / (name + "." + ext), directory)

    def run_generator(self, role="All", succeeds=True):
        result = subprocess.run([POWERSHELL, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(SCRIPT),
                                 "-SourceRoot", str(self.root), "-Role", role], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode == 0, succeeds, result.stdout + result.stderr)
        return result

    def change_spec(self, **changes):
        doc = json.loads((self.root / SPEC).read_text())
        doc.update(changes)
        (self.root / SPEC).write_text(json.dumps(doc))

    def test_real_generator_round_trip_is_idempotent(self):
        self.run_generator()
        paths = [p for p in self.root.rglob("*") if p.is_file()]
        before = {str(p): (p.read_bytes(), p.stat().st_mtime_ns) for p in paths}
        self.run_generator()
        self.assertEqual(before, {str(p): (p.read_bytes(), p.stat().st_mtime_ns) for p in paths})

    def test_four_part_version_update_reaches_every_output(self):
        self.change_spec(version="65535.14.22.65535")
        self.run_generator()
        for name in PROJECTS.values():
            directory = self.root / "Cozy.Projects" / name
            self.assertIn("FILEVERSION 65535,14,22,65535", (directory / (name + ".rc")).read_text())
            self.assertIn('version="65535.14.22.65535"', (directory / (name + ".manifest")).read_text())
        self.assertIn("'65535.14.22.65535'", (self.root / CONFIG / "Cozy.Version.inc").read_text())
        self.assertEqual(list(self.root.rglob("Cozy.ReleaseMetadata.*.backup")), [])

    def test_role_update_does_not_mutate_other_project_metadata(self):
        before = {p: p.read_bytes() for p in (self.root / "Cozy.Projects/Cozy.Client").iterdir()}
        self.change_spec(version="89.0.0.1")
        self.run_generator(role="A")
        self.assertEqual(before, {p: p.read_bytes() for p in before})
        self.assertIn("FILEVERSION 89,0,0,1", (self.root / "Cozy.Projects/Cozy.Launcher/Cozy.Launcher.rc").read_text())

    def test_invalid_schema_and_version_are_rejected_before_writes(self):
        baseline = (self.root / SPEC).read_text()
        before = {p: p.read_bytes() for p in (self.root / "Cozy.Projects").rglob("*") if p.is_file()}
        for changes in ({"version": "65536.0.0.0"}, {"version": "1.2.3"}, {"version": "01.2.3.4"},
                        {"schemaVersion": "1"}, {"schemaVersion": True}, {"unexpected": "value"},
                        {"productName": 'Cozy"\\0\nINJECT'}, {"descriptions": {"A": "a", "B": "b"}}):
            with self.subTest(changes=changes):
                (self.root / SPEC).write_text(baseline)
                self.change_spec(**changes)
                self.run_generator(succeeds=False)
                self.assertEqual(before, {p: p.read_bytes() for p in before})
                self.assertFalse((self.root / CONFIG / "Cozy.Version.inc").exists())

    def test_bad_later_template_cannot_partially_update_earlier_role(self):
        path = self.root / "Cozy.Projects/Cozy.Overlay/Cozy.Overlay.manifest"
        path.write_text(path.read_text().replace("<description>", "<bad>"))
        before = {p: p.read_bytes() for p in (self.root / "Cozy.Projects").rglob("*") if p.is_file()}
        self.change_spec(version="89.1.2.3")
        self.run_generator(succeeds=False)
        self.assertEqual(before, {p: p.read_bytes() for p in before})

    def test_output_symlink_is_refused_without_touching_target(self):
        target = Path(self.temp.name) / "unrelated.txt"
        target.write_text("DO NOT CHANGE")
        output = self.root / CONFIG / "Cozy.Version.inc"
        try:
            output.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("Platform does not allow a temporary symlink")
        self.run_generator(succeeds=False)
        self.assertEqual(target.read_text(), "DO NOT CHANGE")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--powershell")
    args, remaining = parser.parse_known_args()
    POWERSHELL = args.powershell
    unittest.main(argv=[__file__, *remaining], verbosity=2)
