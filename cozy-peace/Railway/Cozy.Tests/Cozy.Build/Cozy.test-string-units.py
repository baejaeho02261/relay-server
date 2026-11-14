#!/usr/bin/env python3
"""Isolated source migration tests; no native executable or server is run."""
import importlib.util,json,tempfile,unittest,sys
sys.dont_write_bytecode=True
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('string_units',ROOT/'Cozy.Build/Cozy.Extract-StringUnits.py')
M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)

class StringUnits(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
  for p in [M.CONFIG,'Cozy.Source/Cozy.Platform','Cozy.Tests/Cozy.Platform','Cozy.Projects/Cozy.Sample']:(self.root/p).mkdir(parents=True,exist_ok=True)
 def tearDown(self):self.tmp.cleanup()
 def put(self,p,text):
  q=self.root/p;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(b'\xef\xbb\xbf'+text.replace('\n','\r\n').encode('utf8'));return q
 def sample(self):
  self.put('Cozy.Source/Cozy.Platform/Cozy.Sample.pas',"unit Cozy.Sample;\ninterface\nconst ErrorText = '한글 오류';\nfunction X: string;\nimplementation\nuses System.SysUtils;\nfunction X: string;\nbegin Result := 'first'#0'last'; if Result = '' then raise Exception.Create('SAMPLE_FAILURE'); end;\nend.\n")
  self.put('Cozy.Projects/Cozy.Sample/Cozy.Sample.dpr',"program Sample;\nuses Cozy.Sample in '..\\..\\Cozy.Source\\Cozy.Platform\\Cozy.Sample.pas';\nbegin WriteLn(X); end.\n")
 def mapping(self):return json.loads((self.root/M.MAP).read_text())
 def test_exact_roundtrip_unicode_and_joined_char_codes(self):
  self.sample();before={p:p.read_bytes() for p in self.root.rglob('*') if p.is_file()};result=M.extract(self.root)
  self.assertTrue(result['byteExactRoundTrip']);self.assertEqual(result['movedOccurrences'],3)
  vals=[c['value'] for u in self.mapping()['units'] for c in u['constants']]
  self.assertIn('first\0last',vals);self.assertIn('한글 오류',vals)
  self.assertTrue(M.check(self.root,verify=True)['byteExactRoundTrip'])
  for u in self.mapping()['units']:
   raw=(self.root/u['path']).read_bytes();self.assertTrue(raw.startswith(b'\xef\xbb\xbf'))
   self.assertIn(b'{$IFDEF FPC}{$MODE DELPHI}{$CODEPAGE UTF8}{$ENDIF}',raw)
   self.assertNotIn(b'{$ENDIF}\r\n{$CODEPAGE',raw)
  self.assertTrue(all(p.read_bytes().startswith(b'\xef\xbb\xbf') for p in before))
 def test_interface_import_precedes_constant_even_with_implementation_uses(self):
  self.sample();M.extract(self.root);s=M.decode((self.root/'Cozy.Source/Cozy.Platform/Cozy.Sample.pas').read_bytes())
  self.assertLess(s.index('uses'),s.index('const ErrorText'));self.assertEqual(s.count('uses'),2)
 def test_project_has_explicit_exact_constant_unit_path(self):
  self.sample();M.extract(self.root);s=M.decode((self.root/'Cozy.Projects/Cozy.Sample/Cozy.Sample.dpr').read_bytes())
  self.assertIn("Cozy.Strings.Platform in '..\\..\\Cozy.Source\\Cozy.Configuration\\Cozy.Strings.Platform.pas'",s)
 def test_project_file_references_added_without_new_search_path(self):
  self.sample();p=self.put('Cozy.Projects/Cozy.Sample/Cozy.Sample.dproj','<Project>\n</Project>\n')
  M.extract(self.root);s=M.decode(p.read_bytes());self.assertIn('Cozy.Strings.Platform.pas',s)
  self.assertNotIn('DCC_UnitSearchPath',s);self.assertEqual(M.sync_projects(self.root)['projectsUpdated'],0)
 def test_case_insensitive_duplicate_constants_are_rejected(self):
  self.sample();M.extract(self.root);u=self.mapping()['units'][0];p=self.root/u['path'];raw=p.read_bytes();name=u['constants'][0]['name'];duplicate=name.replace('Sample','SAMPLE')
  p.write_bytes(raw.replace(b'implementation',(duplicate+" = 'new';\nimplementation").encode()))
  with self.assertRaisesRegex(ValueError,'DUPLICATE_CONSTANT'):M.refresh(self.root)
 def test_probe_only_include_keeps_conditional_import(self):
  self.sample();q=self.root/'Cozy.Source/Cozy.Platform/Cozy.Sample.pas';s=M.decode(q.read_bytes());s=s.replace('end.','{$IFDEF SAMPLE_PROBE}\n{$I ..\\..\\Cozy.Tests\\Cozy.Platform\\Cozy.Sample.inc}\n{$ENDIF}\nend.');q.write_bytes(b'\xef\xbb\xbf'+s.encode())
  self.put('Cozy.Tests/Cozy.Platform/Cozy.Sample.inc',"procedure Probe; begin WriteLn('TEST_ONLY_VALUE'); end;\n")
  M.extract(self.root);s=M.decode(q.read_bytes());self.assertIn('{$IF (Defined(SAMPLE_PROBE))}',s)
  entry=next(e for e in self.mapping()['sources'] if e['path'].endswith('.inc'));self.assertEqual(entry['owners'],['Cozy.Source/Cozy.Platform/Cozy.Sample.pas'])
 def test_empty_chars_guid_and_generated_blobs_stay_explicit(self):
  self.sample();self.put('Cozy.Tests/Cozy.Platform/Cozy.Generated.inc',"{ Generated; generator-owned. }\nconst Fixture = 'wire-fixture';\n")
  M.extract(self.root);reasons={x['reason'] for x in self.mapping()['exceptions']};self.assertIn('empty_literal_type_context',reasons);self.assertIn('generator_owned_contract',reasons)
 def test_editable_constants_refresh_without_reverting_source(self):
  self.sample();M.extract(self.root);u=next(u for u in self.mapping()['units'] if u['unit']=='Cozy.Strings.Platform');p=self.root/u['path'];raw=p.read_bytes();p.write_bytes(raw.replace('한글 오류'.encode(),'변경 문구'.encode()))
  with self.assertRaisesRegex(ValueError,'RUN_REFRESH'):M.check(self.root)
  M.refresh(self.root);self.assertIn('변경 문구'.encode(),p.read_bytes());self.assertEqual(M.check(self.root)['status'],'PASS')
  with self.assertRaisesRegex(ValueError,'ROUNDTRIP_MISMATCH'):M.check(self.root,verify=True)
 def test_hidden_initialization_is_not_a_constant_unit(self):
  self.sample();M.extract(self.root);u=self.mapping()['units'][0];p=self.root/u['path'];p.write_bytes(p.read_bytes().replace(b'implementation',b'implementation\ninitialization Halt(1);'))
  before=(self.root/M.MAP).read_bytes()
  with self.assertRaisesRegex(ValueError,'RUNTIME_CODE'):M.refresh(self.root)
  self.assertEqual(before,(self.root/M.MAP).read_bytes())
 def test_include_directive_cannot_hide_code_in_constant_unit(self):
  self.sample();M.extract(self.root);u=self.mapping()['units'][0];p=self.root/u['path'];p.write_bytes(p.read_bytes().replace(b'interface',b'{$I unknown.inc}\ninterface'))
  with self.assertRaisesRegex(ValueError,'DIRECTIVES'):M.check(self.root)
 def test_moving_preprocessor_directives_into_constants_is_rejected(self):
  self.sample();M.extract(self.root);p=self.root/self.mapping()['units'][0]['path'];raw=p.read_bytes()
  prefix=b'{$IFDEF FPC}{$MODE DELPHI}{$CODEPAGE UTF8}{$ENDIF}';p.write_bytes(raw.replace(prefix,b'').replace(b'\r\nconst\r\n',b'\r\nconst\r\n'+prefix,1))
  with self.assertRaisesRegex(ValueError,'DIRECTIVE_POSITION'):M.check(self.root)
 def test_new_inline_literal_is_rejected_not_silently_catalogued(self):
  self.sample();M.extract(self.root);p=self.root/'Cozy.Source/Cozy.Platform/Cozy.Sample.pas';p.write_bytes(p.read_bytes().replace(b'begin Result :=',b"begin WriteLn('UNMANAGED_NEW_TEXT'); Result :="))
  before=(self.root/M.MAP).read_bytes()
  with self.assertRaisesRegex(ValueError,'UNMANAGED_LITERAL'):M.refresh(self.root)
  self.assertEqual(before,(self.root/M.MAP).read_bytes())
 def test_symlink_source_is_refused(self):
  self.sample();(self.root/'Cozy.Source/Cozy.Platform/Cozy.Link.pas').symlink_to(self.root/'Cozy.Source/Cozy.Platform/Cozy.Sample.pas')
  with self.assertRaisesRegex(ValueError,'SYMLINK'):M.extract(self.root)
 def test_constant_reference_inside_comment_is_not_rewritten(self):
  self.sample();M.extract(self.root);self.assertEqual(M.expand_text("{ CozyText_Fake } 'CozyText_Fake'",{}),"{ CozyText_Fake } 'CozyText_Fake'")
 def test_stale_publish_does_not_overwrite_existing_user_edit(self):
  p=self.put('Cozy.Source/Cozy.Platform/Cozy.Sample.pas','original');before=p.read_bytes();p.write_bytes(b'edited')
  with self.assertRaisesRegex(ValueError,'SOURCE_CHANGED'):M.publish(self.root,{'Cozy.Source/Cozy.Platform/Cozy.Sample.pas':(before,b'replacement')})
  self.assertEqual(p.read_bytes(),b'edited');self.assertEqual(list(self.root.rglob('*.pending')),[])

if __name__=='__main__':unittest.main()
