#!/usr/bin/env python3
"""Portable language/round-trip tests for editable native string units."""
import importlib.util,json,shutil,subprocess,tempfile,unittest,sys
from pathlib import Path
sys.dont_write_bytecode=True
spec=importlib.util.spec_from_file_location('native_strings',Path(__file__).with_name('Cozy.Extract-NativeStrings.py'))
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)

class NativeStringUnits(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.file=self.root/'Cozy.ImGui/Cozy.Bridge/Cozy.Core/sample.cpp';self.file.parent.mkdir(parents=True)
        self.original=("#include <cstring>\r\n"
            "#define INCLUDE_CONFIG \"config.h\"\r\n"
            "#define SPELL(x) #x\r\n"
            "extern \"C\" int contract(void);\r\n"
            "static const char adjacent[] = \"ab\" \"cd\";\r\n"
            "static const wchar_t wide[] = L\"hello\";\r\n"
            "static const char utf8[] = u8\"한글\";\r\n"
            'static const char raw[] = R"xx(a\\b)xx";\r\n'
            "static const char* spelled = SPELL(\"must stay\");\r\n"
            "static_assert(__LINE__ == 10, \"source line\");\r\n"
            "static_assert(sizeof(adjacent) == 5, \"adjacent bytes\");\r\n"
            "static_assert(sizeof(wide) / sizeof(wchar_t) == 6, \"wide count\");\r\n"
            "int main() { return std::strcmp(adjacent, \"abcd\") || sizeof(utf8) != 7 || raw[1] != '\\\\' || spelled[0] != '\"'; }\r\n").encode('utf8')
        self.original=b'\xef\xbb\xbf'+self.original;self.file.write_bytes(self.original)
        self.result=mod.extract(self.root);self.map=json.loads((self.root/mod.MAP).read_text())
        self.header=self.root/self.map['units'][0]['path']
    def tearDown(self):self.tmp.cleanup()
    def test_exact_roundtrip_and_language_semantics(self):
        self.assertTrue(mod.check(self.root,verify=True)['byteExactRoundTrip'])
        self.assertTrue(self.file.read_bytes().startswith(b'\xef\xbb\xbf'))
        self.assertEqual(self.file.read_bytes().count(b'\n'),self.file.read_bytes().count(b'\r\n'))
        if shutil.which('g++'):
            exe=self.root/'probe';subprocess.run(['g++','-std=c++11',str(self.file),'-o',str(exe)],check=True,capture_output=True)
            subprocess.run([str(exe)],check=True,capture_output=True)
    def test_headers_are_editable_and_refresh_does_not_revert(self):
        text=self.header.read_text().replace('L"hello"','L"world"');self.header.write_text(text)
        with self.assertRaisesRegex(ValueError,'CONSTANT_CHANGED_RUN_REFRESH'):mod.check(self.root)
        mod.refresh(self.root);self.assertEqual(text,self.header.read_text())
        self.assertTrue(any(c['expression']=='L"world"' for c in json.loads((self.root/mod.MAP).read_text())['units'][0]['constants']))
        with self.assertRaisesRegex(ValueError,'ROUNDTRIP_MISMATCH'):mod.check(self.root,verify=True)
    def test_hidden_executable_header_code_cannot_be_refreshed(self):
        before=(self.root/mod.MAP).read_bytes();self.header.write_text(self.header.read_text().replace('#endif','int unexpected_runtime_state = 1;\n#endif'))
        with self.assertRaisesRegex(ValueError,'HEADER_SCAFFOLD'):mod.refresh(self.root)
        self.assertEqual(before,(self.root/mod.MAP).read_bytes())
    def test_new_scattered_literal_is_rejected_without_map_mutation(self):
        before=(self.root/mod.MAP).read_bytes();self.file.write_bytes(self.file.read_bytes()+b'const char* extra = "scattered";\r\n')
        with self.assertRaisesRegex(ValueError,'UNCENTRALIZED_LITERAL'):mod.refresh(self.root)
        self.assertEqual(before,(self.root/mod.MAP).read_bytes())
    def test_missing_include_is_rejected(self):
        self.file.write_bytes(self.file.read_bytes().replace(self.map['sources'][0]['includeText'].encode(),b''))
        with self.assertRaisesRegex(ValueError,'INCLUDE_MISSING'):mod.refresh(self.root)
    def test_undeclared_reference_is_rejected(self):
        self.file.write_bytes(self.file.read_bytes()+b'const char* bad = COZY_TEXT_UNKNOWN;\r\n')
        with self.assertRaisesRegex(ValueError,'UNDECLARED_CONSTANT'):mod.refresh(self.root)
    def test_macro_stringification_and_linkage_are_structural(self):
        reasons={e['reason'] for e in self.map['exceptions']}
        self.assertTrue({'extern_linkage_syntax','macro_stringification_contract','preprocessor_include_configuration'}<=reasons)
        self.assertIn('SPELL("must stay")',self.file.read_text())

if __name__=='__main__':unittest.main()
