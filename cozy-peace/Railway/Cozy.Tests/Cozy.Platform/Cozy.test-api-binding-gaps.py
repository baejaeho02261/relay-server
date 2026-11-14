#!/usr/bin/env python3
"""Source binding/contract checks; never compiles or executes a Windows EXE."""
from pathlib import Path
import ast
import importlib.util
import re
import tempfile
import unittest

ROOT = next(p for p in Path(__file__).resolve().parents if (p / 'Cozy.Source').is_dir())
# Mutation tests operate on the current literal values from the separate units;
# source syntax checks below still read their original files directly.
_string_spec = importlib.util.spec_from_file_location('cozy_source_strings', ROOT / 'Cozy.Build/Cozy.SourceStrings.py')
_strings = importlib.util.module_from_spec(_string_spec)
_string_spec.loader.exec_module(_strings)
SOURCE = ROOT / 'Cozy.Source'
GENERATOR = ROOT / 'Cozy.Tests/Cozy.Startup/Cozy.generate-startup-contracts.py'
MITIGATION = SOURCE / 'Cozy.Integrity/Cozy.ProcessMitigations.pas'
IDENTITY = SOURCE / 'Cozy.Identity/Cozy.DeviceIdentity.pas'
CLOCK = SOURCE / 'Cozy.Platform/Cozy.Clock.pas'
STARTUP = SOURCE / 'Cozy.Application/Cozy.Startup.pas'


def binding_parser():
    # Import only the production binding parser definitions. The generator's
    # project traversal/output writer must not execute as part of this test.
    parsed = ast.parse(GENERATOR.read_text(encoding='utf-8'))
    functions = {'production_source', 'clean', 'source', 'hashvalue', 'calls', 'bindings'}
    constants = {'PRODUCTION_DEFINED', 'PRODUCTION_DISABLED'}
    selected = []
    for node in parsed.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            selected.append(node)
        elif isinstance(node, ast.FunctionDef) and node.name in functions:
            selected.append(node)
        elif isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id in constants for target in node.targets
        ):
            selected.append(node)
    namespace = {'__name__': 'cozy_binding_parser_test', '_strings': _strings}
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(GENERATOR), 'exec'), namespace)
    hashes = re.findall(r'(HASH_\w+)\s*:\s*Cardinal\s*=\s*\$([0-9A-Fa-f]+)',
                        (SOURCE / 'Cozy.Platform/Cozy.Api.ROR13.pas').read_text('utf-8-sig'))
    namespace['hashes'] = {name: int(value, 16) for name, value in hashes}
    return namespace['bindings']


class ApiBindingGapChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parse = staticmethod(binding_parser())
        cls.original = _strings.read_source(MITIGATION)

    def parse_variant(self, text, filename=MITIGATION.name):
        with tempfile.TemporaryDirectory(prefix='cozy-api-binding-') as folder:
            file = Path(folder) / filename
            file.write_text(text, encoding='utf-8')
            return self.parse(file)

    def test_current_optional_slots_have_exact_api_and_module_identity(self):
        entries = {row['slot']: row for row in self.parse(MITIGATION)}
        expected = {
            'ApiSlot_GetMitigation': ('kernel32.dll', 'GetProcessMitigationPolicy'),
            'ApiSlot_SetMitigation': ('kernel32.dll', 'SetProcessMitigationPolicy'),
            'ApiSlot_RtlGetVersion': ('ntdll.dll', 'RtlGetVersion'),
        }
        for slot, (module, api) in expected.items():
            self.assertEqual((entries[slot]['module'], entries[slot]['api']), (module, api))
            self.assertIs(entries[slot]['optional'], True)
        self.assertFalse(entries['ApiSlot_Error']['optional'])

    def test_unknown_slot_is_not_misclassified_as_set_mitigation(self):
        text = self.original.replace('BindApiPointer(ApiSlot_RtlGetVersion, Address)',
                                     'BindApiPointer(ApiSlot_Unknown, Address)')
        with self.assertRaisesRegex(ValueError, 'Unmapped optional mitigation binding'):
            self.parse_variant(text)

    def test_wrong_api_target_and_module_are_rejected(self):
        variants = [
            self.original.replace("GetModuleBase64('ntdll.dll'), HASH_RtlGetVersion",
                                  "GetModuleBase64('kernel32.dll'), HASH_RtlGetVersion"),
            self.original.replace("GetModuleBase64('ntdll.dll'), HASH_RtlGetVersion",
                                  "GetModuleBase64('ntdll.dll'), HASH_SetProcessMitigationPolicy"),
            self.original.replace("ModuleBase := GetModuleBase64('kernel32.dll')",
                                  "ModuleBase := GetModuleBase64('ntdll.dll')"),
            self.original.replace('BindApiPointer(ApiSlot_RtlGetVersion, Address)',
                                  'BindApiPointer(ApiSlot_RtlGetVersion, OtherAddress)'),
            self.original.replace('BindApiPointer(ApiSlot_GetMitigation, Address)',
                                  'BindApiPointer(ApiSlot_TEMP, Address)')
                         .replace('BindApiPointer(ApiSlot_SetMitigation, Address)',
                                  'BindApiPointer(ApiSlot_GetMitigation, Address)')
                         .replace('BindApiPointer(ApiSlot_TEMP, Address)',
                                  'BindApiPointer(ApiSlot_SetMitigation, Address)'),
        ]
        for text in variants:
            with self.subTest(variant=text):
                with self.assertRaises(ValueError):
                    self.parse_variant(text)

    def test_runtime_version_query_uses_prebound_optional_slot(self):
        text = self.original.split('function CollectMitigationEnvironment(const Stage: string): TJSONObject;', 2)[2]
        body = text.split('procedure CollectProcessMitigationsProfile', 1)[0]
        self.assertIn('if not ApiSlot_RtlGetVersion.IsBound then Exit;', body)
        self.assertIn('TRtlGetVersion(DecodeApiPointer(ApiSlot_RtlGetVersion))', body)
        self.assertNotRegex(body, r'\b(?:GetProcAddressHash64|GetModuleBase64)\s*\(')
        self.assertIn('(Target(Info) < 0) or (Info.Build < 10240)', body)
        self.assertIn('Size, Major, Minor, Build, Platform: Cardinal;', body)
        self.assertIn('ServicePack: array[0..127] of WideChar;', body)

    def test_identity_reuses_guid_wrapper_and_retains_hresult_failure_check(self):
        text = IDENTITY.read_text('utf-8-sig')
        self.assertRegex(text, r'\bCozy\.Api\.Guid\b')
        self.assertRegex(text, r'if\s+WindowsApiCreateGUID\(G\)\s*<>\s*0\s+then\s+raise')
        self.assertNotRegex(text, r'(?<!\w)CreateGUID\s*\(')
        wrapper = (SOURCE / 'Cozy.Platform/Cozy.Api.Guid.pas').read_text('utf-8-sig')
        self.assertIn('function WindowsApiCreateGUID(out Guid: TGUID): LongInt;', wrapper)
        self.assertIn('if Result = 0 then Guid := Candidate;', wrapper)

    def test_clock_contract_uses_exact_named_canonical_exports(self):
        entries = self.parse(CLOCK)
        names = {'QueryPerformanceCounter', 'QueryPerformanceFrequency', 'CreateEventW',
                 'WaitForSingleObject', 'CloseHandle', 'GetLastError', 'SetLastError'}
        self.assertEqual(len(entries), len(names))
        self.assertEqual({row['procName'] for row in entries}, names)
        for row in entries:
            self.assertEqual(row['module'], 'kernel32.dll')
            self.assertEqual(row['lookup'], 'name')
            self.assertEqual(row['hash'], 0)
            self.assertEqual(row['slot'], 'ClockSlot_' + row['procName'])
            self.assertFalse(row['optional'])

    def test_clock_contract_rejects_changed_or_incomplete_exports(self):
        original = _strings.read_source(CLOCK)
        variants = [
            original.replace("RequireClockApi('CreateEventW')", "RequireClockApi('OpenProcess')"),
            original.replace("BindApiPointer(ClockSlot_CloseHandle,", "BindApiPointer(ClockSlot_SetLastError,"),
            original.replace("  BindApiPointer(ClockSlot_CloseHandle, RequireClockApi('CloseHandle'));", ''),
            original.replace("RequireClockApi('CloseHandle')", 'RequireClockApi(DynamicName)'),
            original.replace("GetModuleHandleW('kernel32.dll')", "GetModuleHandleW('user32.dll')"),
            original.replace('GetProcAddress(Module, Name)', 'GetProcAddress(Module, OtherName)'),
            original.replace("  BindApiPointer(ClockSlot_CloseHandle, RequireClockApi('CloseHandle'));",
                             "  BindApiPointer(ClockSlot_CloseHandle, RequireClockApi('CloseHandle'));\n"
                             "  BindApiPointer(ClockSlot_CloseHandle, RequireClockApi('CloseHandle'));"),
        ]
        for text in variants:
            with self.subTest(variant=text):
                with self.assertRaises(ValueError):
                    self.parse_variant(text, CLOCK.name)

    def test_runtime_gate_keeps_named_and_hash_contracts_exclusive(self):
        text = STARTUP.read_text('utf-8-sig')
        body = text.split('procedure ValidateRoleApis(', 1)[1].split('procedure RequireResource', 1)[0]
        self.assertIn("if Items[I].ProcName <> '' then", body)
        self.assertIn('(Items[I].ProcHash <> 0) or Items[I].Optional', body)
        self.assertIn('not NamedClockApiAllowed(Items[I].ProcName)', body)
        self.assertIn('if Items[I].ProcHash = 0 then', body)
        self.assertIn('Winapi.Windows.GetModuleHandleW(PWideChar(Items[I].ModuleName))', body)
        self.assertIn('Winapi.Windows.GetProcAddress(Module, PAnsiChar(Items[I].ProcName))', body)
        self.assertIn('ApiPointerTargetsMatch(Targets)', body)
        self.assertNotIn('DecodeApiPointer(', body)


if __name__ == '__main__':
    unittest.main(verbosity=2)
