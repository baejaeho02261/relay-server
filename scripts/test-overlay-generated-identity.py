"""Actual manifest-verifier behavior using disposable files; not PowerShell/Delphi execution."""
from pathlib import Path
import importlib.util, hashlib, json, tempfile, unittest
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('flat_verifier',Path(__file__).with_name('verify-source.py'))
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
class GeneratedIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='overlay-identity-verifier-')
        self.root=Path(self.temp.name);self.n=self.root/'GameConnect_Win64';self.n.mkdir()
        self.m=self.root/'GameWeb/maintenance';self.m.mkdir(parents=True)
        self.inc=self.n/'Game.Overlay.Identity.inc';self.exe=self.n/'GameOverlay.exe'
        seed=b"{ Synthetic unprepared fixture, not the current shipped identity. }\r\n{$MESSAGE FATAL 'Build first.'}\r\n";self.inc.write_bytes(seed)
        self.manifest={'files':{},'generatedFiles':{'GameConnect_Win64/Game.Overlay.Identity.inc':{'unpreparedSha256':hashlib.sha256(seed).hexdigest()}}}
        (self.m/'source-manifest.json').write_text(json.dumps(self.manifest))
    def tearDown(self): self.temp.cleanup()
    def generate(self):
        self.exe.write_bytes(b'Synthetic test buffer, not a Windows executable'*32)
        h=hashlib.sha256(self.exe.read_bytes()).hexdigest()
        self.inc.write_bytes(("{ Generated from GameOverlay.exe in this source directory; do not edit. }\r\nconst OverlayExpectedSHA256 = '"+h+"';\r\n").encode())
    def test_unprepared_source_is_intact_not_runtime_proof(self): self.assertEqual(v.verify(self.root),[])
    def test_matching_generated_identity(self):
        self.generate();self.assertEqual(v.verify(self.root),[])
    def test_changed_companion_rejected(self):
        self.generate();self.exe.write_bytes(self.exe.read_bytes()+b'change');self.assertTrue(v.verify(self.root))
    def test_modified_include_rejected(self):
        self.generate();self.inc.write_bytes(self.inc.read_bytes()+b'begin end;');self.assertTrue(v.verify(self.root))
    def test_missing_exe_rejected(self):
        self.generate();self.exe.unlink();self.assertTrue(v.verify(self.root))
    def test_include_symlink_rejected(self):
        self.generate();data=self.inc.read_bytes();self.inc.unlink();p=self.n/'other.inc';p.write_bytes(data);self.inc.symlink_to(p);self.assertTrue(v.verify(self.root))
    def test_unknown_generated_source_rejected(self):
        self.manifest['generatedFiles']['../escape']={};(self.m/'source-manifest.json').write_text(json.dumps(self.manifest));self.assertTrue(v.verify(self.root))
    def test_unprepared_guard_tamper_rejected(self):
        self.inc.write_bytes(self.inc.read_bytes().replace(b'FATAL',b'WARN'));self.assertTrue(v.verify(self.root))
    def supplied(self):
        self.generate()
        h=hashlib.sha256(self.exe.read_bytes()).hexdigest()
        self.manifest['generatedFiles']['GameConnect_Win64/Game.Overlay.Identity.inc']['userSuppliedIdentity']={
            'includeSha256':hashlib.sha256(self.inc.read_bytes()).hexdigest(),
            'overlaySha256':h,'verifiedAgainstExecutableHere':False}
        (self.m/'source-manifest.json').write_text(json.dumps(self.manifest))
    def test_supplied_source_only_digest_is_not_binary_verification(self):
        self.supplied();self.exe.unlink();self.assertEqual(v.verify(self.root),[])
        self.assertTrue(v.verify(self.root,require_overlay=True))
    def test_supplied_identity_checks_binary_when_present(self):
        self.supplied();self.assertEqual(v.verify(self.root,require_overlay=True),[])
    def test_supplied_identity_does_not_accept_changed_binary(self):
        self.supplied();self.exe.write_bytes(b'wrong binary');self.assertTrue(v.verify(self.root))
    def test_supplied_identity_does_not_accept_missing_binary_after_edit(self):
        self.supplied();self.exe.unlink()
        self.inc.write_bytes(self.inc.read_bytes().replace(b'const Overlay',b'const  Overlay'))
        self.assertTrue(v.verify(self.root))
    def test_supplied_identity_does_not_accept_a_symlink(self):
        self.supplied();raw=self.exe.read_bytes();self.exe.unlink()
        other=self.n/'other.exe';other.write_bytes(raw);self.exe.symlink_to(other)
        self.assertTrue(v.verify(self.root))
    def test_strict_check_rejects_unprepared_source(self):
        self.assertTrue(v.verify(self.root,require_overlay=True))
if __name__=='__main__': unittest.main(verbosity=2)
