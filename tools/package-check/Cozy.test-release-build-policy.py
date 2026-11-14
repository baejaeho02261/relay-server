#!/usr/bin/env python3
"""Evaluate the production XML property/condition subset and Release guards.

This is an independent configuration test, not an MSBuild/Delphi compilation.
It evaluates ordered project properties and case-insensitive string conditions,
including immutable command-line properties, then exercises the actual Error
conditions with unsafe XML fixtures and late property overrides. Unsupported
condition syntax fails the test rather than being treated as a passing check.
"""

from copy import deepcopy
from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET


NAMESPACE = "{http://schemas.microsoft.com/developer/msbuild/2003}"
WORK = Path(__file__).resolve().parents[2]
NATIVE = WORK / "cozy-peace" / "Railway"
PROJECT_NAMES = ("Cozy.Launcher", "Cozy.Client", "Cozy.Overlay")
EXPECTED = {
    "DCC_DebugInformation": "0",
    "DCC_LocalDebugSymbols": "false",
    "DCC_DebugInfoInExe": "false",
    "DCC_MapFile": "0",
    "DCC_Optimize": "true",
    "DCC_RemoteDebug": "false",
    "DCC_DebugDCUs": "false",
    "DCC_SymbolReferenceInfo": "0",
}
PROPERTY = re.compile(r"\$\(([A-Za-z_][A-Za-z_0-9]*)\)")
TOKEN = re.compile(r"\s*('[^']*'|==|!=|\(|\)|and\b|or\b)", re.IGNORECASE)


def expand(text, properties):
    return PROPERTY.sub(lambda m: properties.get(m.group(1).lower(), ""), text)


def condition(text, properties):
    if not text:
        return True
    text = expand(text, properties)
    tokens = []
    cursor = 0
    while cursor < len(text):
        match = TOKEN.match(text, cursor)
        if match is None:
            if not text[cursor:].strip():
                break
            raise ValueError(f"Unsupported condition syntax: {text!r}")
        tokens.append(match.group(1))
        cursor = match.end()
    at = 0

    def consume():
        nonlocal at
        if at >= len(tokens):
            raise ValueError("Unexpected end of condition")
        result = tokens[at]
        at += 1
        return result

    def atom():
        left = consume()
        if left == "(":
            result = either()
            if consume() != ")":
                raise ValueError("Unclosed condition")
            return result
        op, right = consume(), consume()
        if not left.startswith("'") or not right.startswith("'") or op not in ("==", "!="):
            raise ValueError("Only string comparisons are supported")
        equal = left[1:-1].casefold() == right[1:-1].casefold()
        return equal if op == "==" else not equal

    def both():
        result = atom()
        while at < len(tokens) and tokens[at].lower() == "and":
            consume()
            other = atom()
            result = result and other
        return result

    def either():
        result = both()
        while at < len(tokens) and tokens[at].lower() == "or":
            consume()
            other = both()
            result = result or other
        return result

    result = either()
    if at != len(tokens):
        raise ValueError("Unexpected remaining condition tokens")
    return result


def evaluate_project(root, name, globals_=None):
    properties = {
        "msbuildprojectname": name,
        "msbuildprojectdirectory": "C:\\Cozy\\Cozy.Projects\\" + name,
    }
    globals_ = {k.lower(): v for k, v in (globals_ or {}).items()}
    properties.update(globals_)
    local = {p.lower() for p in root.get("TreatAsLocalProperty", "").split(";")}
    for group in root.findall(NAMESPACE + "PropertyGroup"):
        if not condition(group.get("Condition"), properties):
            continue
        for item in group:
            key = item.tag.removeprefix(NAMESPACE).lower()
            if key in globals_ and key not in local:
                continue
            if condition(item.get("Condition"), properties):
                properties[key] = expand(item.text or "", properties)
    return properties


class ReleaseBuildPolicy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.projects = {
            name: ET.parse(NATIVE / "Cozy.Projects" / name / (name + ".dproj")).getroot()
            for name in PROJECT_NAMES
        }
        targets = ET.parse(NATIVE / "Cozy.Build" / "Cozy.BuildIsolation.targets").getroot()
        cls.guard = targets.find(NAMESPACE + "Target[@Name='ValidateProductionIsolation']")
        if cls.guard is None:
            raise AssertionError("Production build guard is missing")
        cls.errors = [
            e for e in cls.guard.findall(NAMESPACE + "Error")
            if e.get("Text", "").startswith("COZY_BUILD_RELEASE_")
        ]

    def failures(self, properties):
        return [e.get("Text") for e in self.errors if condition(e.get("Condition"), properties)]

    def test_guard_runs_on_build_and_compile_before_output_mutation(self):
        before = set(self.guard.get("BeforeTargets", "").split(";"))
        self.assertTrue({"Build", "Rebuild", "_PasCoreCompile"}.issubset(before))
        self.assertTrue({"CoreCompile", "BeforeRebuild"}.isdisjoint(before))
        children = list(self.guard)
        first_delete = min(i for i, child in enumerate(children)
                           if child.tag in (NAMESPACE + "Delete", NAMESPACE + "RemoveDir"))
        self.assertTrue(all(children.index(e) < first_delete for e in self.errors))
        self.assertEqual(len(self.errors), len(EXPECTED))

    def test_imgui_post_build_has_exact_early_output_and_fail_closed_order(self):
        for project, failure in (("Cozy.Client", "GAME_CLIENT_COMPILED_OUTPUT_MISSING"),
                                 ("Cozy.Overlay", "GAME_OVERLAY_COMPILED_OUTPUT_MISSING")):
            root = self.projects[project]
            for config in ("Debug", "Release"):
                with self.subTest(configuration=config):
                    # OUTPUTPATH may be absent in command-line MSBuild. Neither it
                    # nor a global CompiledArtifact may redirect finalization.
                    p = evaluate_project(root, project, {
                        "Config": config,
                        "OUTPUTPATH": "C:\\unrelated\\old.exe",
                        "CompiledArtifact": "C:\\unrelated\\old.exe",
                    })
                    expected = p["msbuildprojectdirectory"] + "\\" + project + ".exe"
                    self.assertEqual(p["compiledartifact"], expected)
                    event = expand(p["postbuildevent"], p)
                    commands = event.splitlines()
                    self.assertEqual(len(commands), 4)
                    self.assertEqual(commands[0], 'if not exist "' + expected +
                                     '" (echo ' + failure + ' & exit /b 1)')
                    self.assertIn("Cozy.Normalize-PE-Unwind.ps1", commands[1])
                    self.assertIn('-ImagePath "' + expected + '"', commands[1])
                    self.assertEqual(commands[2], "if errorlevel 1 exit /b 1")
                    self.assertIn("Cozy.Assert-OverlayManifest.ps1", commands[3])
                    self.assertIn('-ImagePath "' + expected + '"', commands[3])
                    self.assertNotIn("unrelated", event)
                    self.assertEqual(p["postbuildeventignoreexitcode"], "false")
            final = root.find(NAMESPACE + "Target[@Name='FinalizeProjectExecutable']")
            self.assertIsNotNone(final)
            self.assertEqual(final.findall(NAMESPACE + "Exec"), [])
            self.assertIsNotNone(final.find(NAMESPACE + "Error[@Text='" + failure + "']"))

    def test_overlay_and_observation_hook_actual_delphi_compile_target(self):
        root = self.projects["Cozy.Overlay"]
        prepare = root.find(NAMESPACE + "Target[@Name='PrepareOverlayNative']")
        self.assertEqual(set(prepare.get("BeforeTargets").split(";")),
                         {"PreBuildEvent", "_PasCoreCompile"})
        self.assertEqual(prepare.get("DependsOnTargets"), "ValidateProductionIsolation")
        observation = ET.parse(NATIVE / "Cozy.Build" / "Cozy.BuildObservation.targets").getroot()
        for name in ("GameObserveCompilerReady", "GameObserveBeforeBuild"):
            target = observation.find(NAMESPACE + "Target[@Name='" + name + "']")
            hooks = set(target.get("BeforeTargets").split(";"))
            self.assertIn("_PasCoreCompile", hooks)
            self.assertTrue({"CoreCompile", "BeforeRebuild"}.isdisjoint(hooks))

    def test_manual_probe_configuration_and_fault_audits_hook_actual_compiler(self):
        for relative, name in (
            ("Cozy.Tests/Cozy.Build/Cozy.ManualProbe.props", "ManualProbeConfiguration"),
            ("Cozy.Tests/Cozy.FaultInjection/Cozy.OverlayFaultTest.dproj", "AuditProductFaultObject"),
            ("Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dproj", "AuditManualFaultObject"),
        ):
            with self.subTest(project=relative):
                root = ET.parse(NATIVE / relative).getroot()
                target = root.find(NAMESPACE + "Target[@Name='" + name + "']")
                self.assertIsNotNone(target)
                self.assertEqual(target.get("BeforeTargets"), "_PasCoreCompile")
                # These targets enforce test configuration/object provenance;
                # a hook correction must not replace them with empty stubs.
                self.assertTrue(list(target))
                if name != "ManualProbeConfiguration":
                    self.assertTrue(target.findall(NAMESPACE + "Exec"))

    def test_projects_import_guard_after_compiler_targets(self):
        for name, root in self.projects.items():
            with self.subTest(project=name):
                imports = root.findall(NAMESPACE + "Import")
                guard = next(i for i in imports if i.get("Project", "").endswith("Cozy.BuildIsolation.targets"))
                compiler = next(i for i in imports if i.get("Project", "").endswith("CodeGear.Delphi.Targets"))
                self.assertFalse(guard.get("Condition"))
                self.assertGreater(imports.index(guard), imports.index(compiler))

    def test_resource_scripts_are_legacy_brcc32_ascii_and_keep_manifests(self):
        for name in PROJECT_NAMES:
            with self.subTest(project=name):
                resource = NATIVE / "Cozy.Projects" / name / (name + ".rc")
                text = resource.read_bytes().decode("ascii")
                self.assertNotIn("\x00", text)
                self.assertIn('1 24 "' + name + '.manifest"', text)
                self.assertIn("1 VERSIONINFO", text)

    def test_isolation_removes_only_expected_exe_before_any_compiler_target(self):
        # A refused compiler may return zero. A stale PE must have been removed
        # before either a direct compile target or the normal build can run.
        expected = "$(_GameExpectedExe)\\$(_GameProjectName).exe"
        deletes = [e for e in self.guard.findall(NAMESPACE + "Delete")
                   if e.get("Files") == expected]
        self.assertEqual(len(deletes), 1)
        self.assertNotIn("ContinueOnError", deletes[0].attrib)
        self.assertNotIn("Condition", deletes[0].attrib)
        self.assertNotIn("Inputs", self.guard.attrib)
        self.assertNotIn("Outputs", self.guard.attrib)
        before = set(self.guard.get("BeforeTargets").split(";"))
        self.assertTrue({"Build", "Rebuild", "_PasCoreCompile"}.issubset(before))

    def test_default_and_explicit_release_are_safe(self):
        for name, root in self.projects.items():
            for globals_ in ({}, {"Config": "Release"}, {"Config": "release"}):
                with self.subTest(project=name, globals=globals_):
                    p = evaluate_project(root, name, globals_)
                    self.assertEqual(p["config"].lower(), "release")
                    self.assertEqual(p["platform"], "Win64")
                    self.assertEqual(self.failures(p), [])
                    for key, value in EXPECTED.items():
                        self.assertEqual(p[key.lower()], value)
                    self.assertEqual(p["dcc_exeoutput"], p["msbuildprojectdirectory"])
                    self.assertEqual(p["dcc_dcuoutput"], p["msbuildprojectdirectory"] + "\\dcu")

    def test_explicit_debug_stays_available(self):
        for name, root in self.projects.items():
            with self.subTest(project=name):
                p = evaluate_project(root, name, {"Config": "Debug"})
                self.assertEqual(p["config"], "Debug")
                self.assertEqual(p["dcc_debuginformation"], "2")
                self.assertEqual(p["dcc_localdebugsymbols"], "true")
                self.assertEqual(p["dcc_debuginfoinexe"], "true")
                self.assertEqual(p["dcc_optimize"], "false")
                self.assertEqual(self.failures(p), [])

    def test_global_and_late_unsafe_overrides_fail_closed(self):
        for name, root in self.projects.items():
            for key, expected in EXPECTED.items():
                bad_values = ("", "unexpected", "1" if expected == "0" else
                              "false" if expected == "true" else "true")
                for value in bad_values:
                    for origin in ("global", "late-target"):
                        with self.subTest(project=name, property=key, value=value, origin=origin):
                            overrides = {"Config": "Release"}
                            if origin == "global":
                                overrides[key] = value
                            p = evaluate_project(root, name, overrides)
                            if origin == "late-target":
                                p[key.lower()] = value
                            failures = self.failures(p)
                            self.assertEqual(len(failures), 1)
                            self.assertIn(key, failures[0])

    def test_mutated_release_xml_is_rejected(self):
        for name, root in self.projects.items():
            for key in EXPECTED:
                with self.subTest(project=name, property=key):
                    changed = deepcopy(root)
                    release = next(g for g in changed.findall(NAMESPACE + "PropertyGroup")
                                   if g.get("Condition") == "'$(Cfg_2)'!=''")
                    node = release.find(NAMESPACE + key)
                    self.assertIsNotNone(node)
                    node.text = "invalid-release-setting"
                    failures = self.failures(evaluate_project(changed, name))
                    self.assertEqual(len(failures), 1)
                    self.assertIn(key, failures[0])

    def test_missing_effective_settings_fail_closed(self):
        for name, root in self.projects.items():
            for key in EXPECTED:
                with self.subTest(project=name, property=key):
                    changed = deepcopy(root)
                    for group in changed.findall(NAMESPACE + "PropertyGroup"):
                        for node in list(group):
                            if node.tag == NAMESPACE + key:
                                group.remove(node)
                    failures = self.failures(evaluate_project(changed, name))
                    self.assertEqual(len(failures), 1)
                    self.assertIn(key, failures[0])

    def test_msbuild_case_insensitive_boolean_values(self):
        for name, root in self.projects.items():
            p = evaluate_project(root, name, {k: v.upper() for k, v in EXPECTED.items()})
            self.assertEqual(self.failures(p), [])

    def test_pointer_mutation_probe_is_forbidden_by_production_guard(self):
        error = next(e for e in self.guard.findall(NAMESPACE + "Error")
                     if e.get("Text") == "GAME_BUILD_TEST_DEFINE_FORBIDDEN")
        pattern = re.search(r"IsMatch\('\$\(DCC_Define\)', '([^']+)'\)", error.get("Condition"))
        self.assertIsNotNone(pattern)
        for flags in ("RELEASE;GAME_APPLICATION_BUILD;COZY_POINTER_GRAPH_PROBE",
                      "DEBUG;game_application_build;cozy_pointer_graph_probe",
                      "RELEASE;GAME_NATIVE_ABI_TESTS"):
            self.assertIsNotNone(re.search(pattern.group(1), flags))
        self.assertIsNone(re.search(pattern.group(1), "RELEASE;GAME_APPLICATION_BUILD"))
        metadata = (NATIVE / "Cozy.Source/Cozy.Configuration/Cozy.Metadata.inc").read_text(encoding="utf-8-sig")
        self.assertRegex(metadata, r"(?s)IFDEF GAME_APPLICATION_BUILD.*?IFDEF COZY_POINTER_GRAPH_PROBE.*?MESSAGE FATAL")

    def test_condition_parser_rejects_unmodelled_semantics(self):
        with self.assertRaises(ValueError):
            condition("Exists('compiler.exe')", {})


if __name__ == "__main__":
    print("Configuration checks only: Windows/MSBuild/Delphi execution is not performed.", flush=True)
    unittest.main(verbosity=2)
