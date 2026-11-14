#!/usr/bin/env python3
"""Exercise the real source catalogue tool with isolated owned fixtures only."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
TOOL = Path(__file__).resolve().parents[2] / 'Cozy.Build/Cozy.Manage-Strings.py'
spec = importlib.util.spec_from_file_location('cozy_string_catalog', TOOL)
catalog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(catalog)

SOURCE = """unit Cozy.Sample;
interface
const Protocol = 'SESSION_STARTED';
type ITest = interface ['{12345678-1234-1234-1234-123456789abc}'] end;
implementation
procedure Test;
begin
  { 'Comment is not a runtime string.' }
  raise EInvalidOpException.Create('Original diagnostic message.');
end;
{$MESSAGE WARN 'Compiler diagnostic stays here'}
end.
"""

class CatalogueTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cozy-strings-')
        self.root = Path(self.temp.name)
        self.source = self.root / 'Cozy.Source/Cozy.Application/Cozy.Sample.pas'
        self.source.parent.mkdir(parents=True)
        self.source.write_bytes(b'\xef\xbb\xbf' + SOURCE.replace('\n', '\r\n').encode())
        (self.root / 'Cozy.Source/Cozy.Configuration').mkdir()
        self.file = self.root / catalog.CATALOG

    def tearDown(self):
        self.temp.cleanup()

    def init(self):
        return catalog.run(self.root, 'init')

    def read(self):
        return json.loads(self.file.read_text())

    def write(self, data):
        self.file.write_text(json.dumps(data, ensure_ascii=False), encoding='utf-8')

    def edit(self, value='Updated diagnostic message.'):
        data = self.read()
        entries = data['files'][0]['literals']
        row = next(x for x in entries if x['mode'] == 'editable_text')
        row['value'] = value
        self.write(data)
        return data

    def test_default_check_is_read_only_and_indexes_exceptions(self):
        before = self.source.read_bytes()
        summary = self.init()
        self.assertEqual(summary['editableTextOccurrences'], 1)
        data = self.read()
        self.assertEqual(len(data['files'][0]['literals']), 3)
        self.assertEqual(data['files'][0]['readOnlySyntax'][0]['kind'], 'compiler_directive')
        catalogue_before = self.file.read_bytes()
        self.assertEqual(catalog.run(self.root, 'check')['sourceFilesChanged'], 0)
        self.assertEqual(self.source.read_bytes(), before)
        self.assertEqual(self.file.read_bytes(), catalogue_before)
        with self.assertRaises((catalog.CatalogError, FileExistsError)):
            self.init()

    def test_quoted_text_apply_preserves_every_other_byte_and_encoding(self):
        self.init(); before = self.source.read_bytes()
        self.edit("New diagnostic: it's 한글.")
        with self.assertRaisesRegex(catalog.CatalogError, 'PENDING_EDITS'):
            catalog.run(self.root, 'check')
        result = catalog.run(self.root, 'apply')
        self.assertEqual(result['sourceFilesChanged'], 1)
        expected = before.replace(b"'Original diagnostic message.'", "'New diagnostic: it''s 한글.'".encode())
        self.assertEqual(self.source.read_bytes(), expected)
        self.assertEqual(catalog.run(self.root, 'check')['status'], 'PASS')
        after = self.file.read_bytes()
        self.assertEqual(catalog.run(self.root, 'apply')['sourceFilesChanged'], 0)
        self.assertEqual(self.file.read_bytes(), after)
        self.assertFalse(list(self.root.rglob('*.tmp')))

    def test_protocol_guid_and_compiler_values_are_read_only(self):
        self.init(); before = self.source.read_bytes()
        original = self.read()
        for index in (0, 1):
            data = json.loads(json.dumps(original)); data['files'][0]['literals'][index]['value'] = 'Changed forbidden value.'
            self.write(data)
            with self.assertRaisesRegex(catalog.CatalogError, 'READ_ONLY_LITERAL_CHANGED'):
                catalog.run(self.root, 'apply')
            self.assertEqual(self.source.read_bytes(), before)
        data = json.loads(json.dumps(original)); data['files'][0]['readOnlySyntax'][0]['spelling'] = '{$R other.res}'
        self.write(data)
        with self.assertRaisesRegex(catalog.CatalogError, 'READ_ONLY_METADATA_CHANGED'):
            catalog.run(self.root, 'apply')

    def test_late_invalid_file_is_rejected_before_any_source_write(self):
        other = self.source.with_name('Cozy.ZOther.pas'); other.write_bytes(self.source.read_bytes())
        self.init(); original = {p: p.read_bytes() for p in (self.source, other)}
        data = self.edit()
        next(x for x in data['files'][1]['literals'] if x['mode'] == 'editable_text')['value'] = 'Invalid\ntext'
        self.write(data)
        with self.assertRaisesRegex(catalog.CatalogError, 'TEXT_INVALID'):
            catalog.run(self.root, 'apply')
        for file, before in original.items(): self.assertEqual(file.read_bytes(), before)
        self.assertFalse(list(self.root.rglob('*.tmp')))

    def test_stale_file_unknown_field_and_path_escape_are_rejected(self):
        self.init(); original = self.read()
        self.source.write_bytes(self.source.read_bytes() + b'\r\n')
        with self.assertRaisesRegex(catalog.CatalogError, 'SOURCE_STALE'):
            catalog.run(self.root, 'apply')
        self.source.write_bytes(b'\xef\xbb\xbf' + SOURCE.replace('\n', '\r\n').encode())
        for mutate in ('field', 'path'):
            data = json.loads(json.dumps(original))
            if mutate == 'field': data['unexpected'] = True
            else: data['files'][0]['path'] = '../outside.pas'
            self.write(data)
            with self.assertRaises(catalog.CatalogError): catalog.run(self.root, 'apply')
        self.assertFalse((self.root.parent / 'outside.pas').exists())

    def test_duplicate_json_keys_and_non_finite_values_are_rejected(self):
        self.init()
        for bad in ('{"schemaVersion":1,"schemaVersion":1}', '{"schemaVersion":NaN}'):
            self.file.write_text(bad)
            with self.assertRaises(catalog.CatalogError): catalog.run(self.root, 'check')

    def test_added_source_file_requires_explicit_refresh(self):
        self.init()
        self.source.with_name('Cozy.New.pas').write_bytes(self.source.read_bytes())
        with self.assertRaisesRegex(catalog.CatalogError, 'FILE_SET_CHANGED'):
            catalog.run(self.root, 'check')
        self.assertEqual(catalog.run(self.root, 'refresh')['pascalFiles'], 2)
        self.assertEqual(catalog.run(self.root, 'check')['status'], 'PASS')

    def test_refresh_does_not_discard_pending_edits(self):
        self.init(); self.edit(); before = self.file.read_bytes()
        with self.assertRaisesRegex(catalog.CatalogError, 'PENDING_EDITS'):
            catalog.run(self.root, 'refresh')
        self.assertEqual(self.file.read_bytes(), before)

    def test_invalid_characters_are_rejected(self):
        self.init()
        for value in ('Bad\x00 text', 'Bad\ntext', 'Bad\ud800text', 'x' * 5000 + ' text'):
            data = self.read(); next(x for x in data['files'][0]['literals'] if x['mode'] == 'editable_text')['value'] = value
            self.file.write_text(json.dumps(data), encoding='utf-8')
            with self.assertRaises(catalog.CatalogError): catalog.run(self.root, 'apply')

    def formatted_source(self, format_text):
        data = SOURCE.replace("EInvalidOpException.Create('Original diagnostic message.')", "EInvalidOpException.CreateFmt('" + format_text + "', [1, 2])")
        self.source.write_bytes(b'\xef\xbb\xbf' + data.replace('\n', '\r\n').encode())

    def test_formatted_text_rejects_every_unmatched_percent(self):
        self.formatted_source('Number %d and %s.'); self.init(); original = self.read()
        before = self.source.read_bytes()
        for suffix in (' %', ' %q', ' %1:', ' %12', ' %lls', ' %*', ' %%%'):
            data = json.loads(json.dumps(original))
            next(x for x in data['files'][0]['literals'] if x['mode'] == 'editable_text')['value'] = 'Number %d and %s.' + suffix
            self.write(data)
            with self.assertRaisesRegex(catalog.CatalogError, 'FORMAT_SYNTAX_INVALID'):
                catalog.run(self.root, 'apply')
            self.assertEqual(self.source.read_bytes(), before)

    def test_formatted_text_preserves_exact_argument_and_escape_tokens(self):
        self.formatted_source('Values %1:-8.2s and %*.*f at 100%%.'); self.init()
        self.edit('새 값 %1:-8.2s 그리고 %*.*f 완료 100%%.')
        self.assertEqual(catalog.run(self.root, 'apply')['sourceFilesChanged'], 1)
        self.assertEqual(catalog.run(self.root, 'check')['status'], 'PASS')
        original = self.read(); before = self.source.read_bytes()
        for replacement in ('새 값 %1:-8.2d 그리고 %*.*f 완료 100%%.',
                            '새 값 %1:-8.2s 그리고 %*.*f 완료 100%%. %s',
                            '새 값 %1:-8.2s 그리고 %*.*f 완료 100.'):
            data = json.loads(json.dumps(original))
            next(x for x in data['files'][0]['literals'] if x['mode'] == 'editable_text')['value'] = replacement
            self.write(data)
            with self.assertRaisesRegex(catalog.CatalogError, 'FORMAT_PLACEHOLDER_CHANGED'):
                catalog.run(self.root, 'apply')
            self.assertEqual(self.source.read_bytes(), before)

    def test_plain_diagnostic_and_ui_text_allow_literal_percent(self):
        data = SOURCE.replace("raise EInvalidOpException.Create('Original diagnostic message.');", "SetWindowTextW(0, 'Progress 10%');")
        self.source.write_bytes(b'\xef\xbb\xbf' + data.replace('\n', '\r\n').encode())
        self.init(); self.edit('Progress 50% and literal %s ends with %')
        self.assertEqual(catalog.run(self.root, 'apply')['sourceFilesChanged'], 1)
        self.assertIn(b"'Progress 50% and literal %s ends with %'", self.source.read_bytes())

    def test_format_data_argument_is_not_a_format_template(self):
        data = SOURCE.replace("EInvalidOpException.Create('Original diagnostic message.')", "EInvalidOpException.CreateFmt('Failure: %s', ['Original diagnostic message.'])")
        self.source.write_bytes(b'\xef\xbb\xbf' + data.replace('\n', '\r\n').encode())
        self.init(); data = self.read()
        next(x for x in data['files'][0]['literals'] if x['sourceValue'] == 'Original diagnostic message.')['value'] = 'Plain data 50%'
        self.write(data)
        self.assertEqual(catalog.run(self.root, 'apply')['sourceFilesChanged'], 1)
        self.assertIn(b"CreateFmt('Failure: %s', ['Plain data 50%'])", self.source.read_bytes())

    def test_commit_failure_rolls_back_only_files_written_by_this_apply(self):
        other = self.source.with_name('Cozy.ZOther.pas'); other.write_bytes(self.source.read_bytes())
        self.init(); original = {p: p.read_bytes() for p in (self.source, other)}
        data = self.read()
        for entry in data['files']:
            next(x for x in entry['literals'] if x['mode'] == 'editable_text')['value'] = 'Changed diagnostic message.'
        self.write(data); original_catalog = self.file.read_bytes()
        replace = catalog.os.replace; count = 0
        def injected(src, dst):
            nonlocal count
            count += 1
            if count == 2: raise OSError('Injected publish failure')
            return replace(src, dst)
        with mock.patch.object(catalog.os, 'replace', injected):
            with self.assertRaises(OSError): catalog.run(self.root, 'apply')
        for file, before in original.items(): self.assertEqual(file.read_bytes(), before)
        self.assertEqual(self.file.read_bytes(), original_catalog)
        self.assertFalse(list(self.root.rglob('*.tmp')))

    def test_staging_write_failure_removes_own_temporary_files(self):
        self.init(); self.edit(); before = self.source.read_bytes()
        with mock.patch.object(catalog.os, 'fsync', side_effect=OSError('Injected staging failure')):
            with self.assertRaises(OSError): catalog.run(self.root, 'apply')
        self.assertEqual(self.source.read_bytes(), before)
        self.assertFalse(list(self.root.rglob('*.tmp')))

    def test_refresh_rejects_unknown_schema_instead_of_discarding_it(self):
        self.init(); data = self.read(); data['files'][0]['unexpected'] = True; self.write(data)
        before = self.file.read_bytes()
        with self.assertRaisesRegex(catalog.CatalogError, 'SCHEMA_INVALID'):
            catalog.run(self.root, 'refresh')
        self.assertEqual(self.file.read_bytes(), before)

    def test_unmarked_utf8_source_cannot_gain_implicit_unicode_encoding(self):
        self.source.write_bytes(SOURCE.encode('ascii')); self.init(); self.edit('새 진단 문구입니다.')
        with self.assertRaisesRegex(catalog.CatalogError, 'UNICODE_SOURCE_MARKER_REQUIRED'):
            catalog.run(self.root, 'apply')
        self.assertEqual(self.source.read_bytes(), SOURCE.encode('ascii'))

    def test_hardlinked_source_is_refused(self):
        target = self.root / 'same-source.pas'
        try: os.link(self.source, target)
        except OSError: self.skipTest('Hardlinks unavailable on this filesystem')
        with self.assertRaisesRegex(catalog.CatalogError, 'REGULAR_OWNED_FILE_REQUIRED'):
            self.init()

    def test_cpp_vendor_and_metadata_are_read_only(self):
        vendor = self.root / 'Cozy.ImGui/Cozy.Vendor/Cozy.Core/Cozy.sample.cpp'
        vendor.parent.mkdir(parents=True)
        vendor.write_text('/* "not literal" */ const char *s = R"tag(hello "world")tag"; const char *t = "a\\"b";')
        meta = self.root / 'Cozy.Source/Cozy.Configuration/Cozy.ReleaseMetadata.json'; meta.write_text('{"version":"88.0.0.0"}')
        self.init(); data = self.read()
        self.assertEqual(len(data['readOnlyCpp'][0]['literals']), 2)
        self.assertEqual(data['readOnlyCpp'][0]['kind'], 'cpp_vendor')
        data['readOnlyCpp'][0]['literals'][0]['spelling'] = '"changed"'; self.write(data)
        with self.assertRaisesRegex(catalog.CatalogError, 'READ_ONLY_METADATA_CHANGED'):
            catalog.run(self.root, 'apply')
        self.assertIn('hello', vendor.read_text())

    @unittest.skipIf(os.name == 'nt', 'Windows link creation can require platform privileges')
    def test_symlinked_sources_and_catalogue_are_rejected(self):
        before = self.source.read_bytes(); target = self.root / 'outside.pas'; target.write_bytes(before)
        self.source.unlink(); self.source.symlink_to(target)
        with self.assertRaisesRegex(catalog.CatalogError, 'LINK_FORBIDDEN'): self.init()
        self.source.unlink(); self.source.write_bytes(before); self.init()
        payload = self.file.read_bytes(); self.file.unlink(); target.write_bytes(payload); self.file.symlink_to(target)
        with self.assertRaisesRegex(catalog.CatalogError, 'LINK_FORBIDDEN'): catalog.run(self.root, 'apply')
        self.assertEqual(target.read_bytes(), payload)

if __name__ == '__main__':
    unittest.main(verbosity=2)
