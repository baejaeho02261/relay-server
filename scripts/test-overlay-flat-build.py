"""IDE-only build wiring checks. These are NOT a Windows/Delphi execution test.
The external compiler used by the previous runner explicitly rejected CLI use.
"""
from pathlib import Path
import hashlib
import re
import unittest
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[2]
N=ROOT/'GameConnect_Win64'
NS={'m':'http://schemas.microsoft.com/developer/msbuild/2003'}
def text(name):return (N/name).read_text(encoding='utf-8-sig')
def project(name):return ET.fromstring(text(name+'.dproj'))
def prop(p,name):return p.find('.//m:'+name,NS).text or ''
B,C=project('GameConnect'),project('GameOverlay')
R=text('build-game.ps1')
W=text('write-overlay-identity.ps1')

class IdeOnlyBuildContracts(unittest.TestCase):
    def test_no_commandline_compiler_in_runner(self):
        self.assertNotRegex(R,r'(?i)\b(?:dcc32|dcc64|msbuild)\.exe\b')
        self.assertNotIn('Invoke-Tool',R)
        self.assertNotIn('Invoke-Project',R)
        self.assertNotIn('Find-RadStudio',R)
    def test_no_compiler_invocation_in_project_events(self):
        for p in (B,C):
            for event in ('PreBuildEvent','PostBuildEvent'):
                for node in p.findall('.//m:'+event,NS):
                    s=node.text or ''
                    self.assertNotRegex(s,r'(?i)(?:dcc64|dcc32|MSBuild)\.exe|Run_GameBuild|build-game|Build_Win64|PrepareClient')
    def test_initialtarget_removed(self):
        self.assertNotIn('InitialTargets',B.attrib)
        self.assertIsNone(B.find("m:Target[@Name='PrepareOverlayBeforeBuild']",NS))
    def test_no_duplicate_overlay_aftertarget(self):
        self.assertIsNone(C.find("m:Target[@Name='WriteFlatOverlayIdentity']",NS))
    def test_b_only_verifies_existing_identity(self):
        pre=prop(B,'PreBuildEvent')
        self.assertIn('Update_Overlay_Identity.bat" verify --no-pause',pre)
        self.assertNotIn('invalidate',pre)
        self.assertNotIn('generate',pre)
        self.assertNotIn('GameOverlay.dproj',pre)
    def test_b_resource_is_still_built(self):
        pre=prop(B,'PreBuildEvent')
        self.assertIn('brcc32.exe" -fo"GameConnectResources.res" "GameConnect.rc"',pre)
        self.assertLess(pre.index(' verify '),pre.index('brcc32.exe'))
        self.assertIn('&amp;&amp;',text('GameConnect.dproj'))
    def test_c_resources_and_invalidation_order(self):
        pre=prop(C,'PreBuildEvent')
        self.assertIn('invalidate --no-pause',pre)
        self.assertIn('brcc32.exe" -fo"GameOverlayResources.res" "GameOverlay.rc"',pre)
        self.assertLess(pre.index('invalidate'),pre.index('brcc32'))
    def test_c_success_event_generates_real_hash(self):
        self.assertIn('generate --no-pause',prop(C,'PostBuildEvent'))
        for field in ['PreBuildEventIgnoreErrors','PostBuildEventIgnoreErrors']:
            self.assertEqual(prop(C,field),'false')
        self.assertEqual(prop(B,'PreBuildEventIgnoreErrors'),'false')
    def test_hash_verify_does_not_rewrite_or_invalidate(self):
        self.assertIn("if ($Mode -eq 'Generate')",W)
        self.assertIn("if ($Mode -eq 'Invalidate')",W)
        self.assertEqual(W.count('Write-IdentityVerified $seed'),1)
        self.assertEqual(W.count('Write-IdentityVerified $text'),1)
        self.assertIn('if ($actual -cne $text)',W)
    def test_locked_executable_read(self):
        self.assertIn('[IO.FileShare]::Read)',W)
        self.assertIn('$sha.ComputeHash($stream)',W)
        self.assertIn('0x8664',W);self.assertIn('0x20B',W)
    def test_verified_identity_write_no_replace(self):
        for s in ('[IO.FileShare]::None','$file.Flush($true)','$file.Read(','$utf8.GetString($readback) -cne $Text'):
            self.assertIn(s,W)
        self.assertNotIn('[IO.File]::Replace(',W)
        self.assertNotIn('NullString',W)
    def test_verify_names_missing_and_unprepared_steps(self):
        self.assertIn('GameOverlay.exe is missing',W)
        self.assertIn("$saved.Contains('{$MESSAGE FATAL')",W)
        self.assertIn('Overlay identity is unprepared',W)
        self.assertIn('RAD Studio IDE',W)
    def test_current_identity_is_user_supplied_not_a_guard(self):
        import json
        source=text('Game.Overlay.Identity.inc')
        rule=json.loads((ROOT/'GameWeb/maintenance/source-manifest.json').read_text())['generatedFiles']['GameConnect_Win64/Game.Overlay.Identity.inc']['userSuppliedIdentity']
        match=re.fullmatch(r"\{ Generated from GameOverlay.exe in this source directory; do not edit\. \}\nconst OverlayExpectedSHA256 = '([0-9a-f]{64})';\n",source)
        self.assertIsNotNone(match)
        self.assertEqual(match[1],rule['overlaySha256'])
        self.assertNotIn('{$MESSAGE FATAL ',source)
        self.assertNotIn('{$I',source)
        # Missing-executable and hash-mismatch build guards remain in the helper.
        self.assertIn('GameOverlay.exe is missing',W)
    def test_old_runner_prepareclient_is_readonly(self):
        self.assertIn("$Target -eq 'PrepareClient' -or $Target -eq 'VerifyIdentity'",R)
        self.assertIn("-Mode 'Verify'",R)
        self.assertNotIn("-Mode 'Generate'",R)
        self.assertNotIn("-Mode 'Invalidate'",R)
    def test_legacy_builds_do_not_fake_success(self):
        self.assertIn('[IDE BUILD REQUIRED] No command-line build was attempted.',R)
        self.assertIn('exit 2',R)
        self.assertNotIn('Start-Process',R)
        bat=text('Run_GameBuild.bat')
        self.assertIn('if "%_GC_RESULT%"=="2"',bat)
        self.assertNotIn('[OK] Requested build steps completed.',bat)
    def test_bat_preserves_result_and_pause(self):
        for name,var,quiet in [('Run_GameBuild.bat','_GC_RESULT','GC_GAME_BUILD_QUIET'),('Update_Overlay_Identity.bat','GC_IDENTITY_RESULT','GC_IDENTITY_NOPAUSE')]:
            s=text(name)
            self.assertIn('set "'+var+'=%ERRORLEVEL%"',s)
            self.assertIn('exit /b %'+var+'%',s)
            self.assertIn('pause',s)
            self.assertIn('--no-pause',s)
            self.assertIn(quiet,s)
    def test_no_bat_infinite_recursion(self):
        bat=text('Update_Overlay_Identity.bat')
        self.assertNotIn('Run_GameBuild',bat)
        self.assertNotIn('Build_Win64',bat)
        self.assertIn('write-overlay-identity.ps1',bat)
    def test_same_folder(self):
        self.assertEqual(prop(C,'DCC_ExeOutput'),'.')
        self.assertEqual(prop(B,'DCC_IncludePath'),'$(MSBuildProjectDirectory);$(DCC_IncludePath)')
        self.assertIn("Join-Path $root 'Game.Overlay.Identity.inc'",W)
        self.assertIn("Join-Path $root 'GameOverlay.exe'",W)
    def test_old_nested_include_paths_absent(self):
        for p in N.rglob('*'):
            if p.is_file() and p.suffix.lower() in {'.bat','.ps1','.inc','.pas','.dpr','.dproj'}:
                self.assertNotRegex(p.read_text(encoding='utf-8-sig'),r'build[\\/]+overlay-identity',str(p))
    def test_output_and_publish_paths_unchanged(self):
        self.assertEqual(prop(B,'DCC_ExeOutput'),r'.\build\stage\client\$(Platform)\$(Config)')
        self.assertIsNotNone(B.find("m:Target[@Name='PublishRandomExecutable']",NS))
        self.assertIn('DestinationFiles="$(RandomArtifactDirectory)\\$(RandomArtifactName)"',text('GameConnect.dproj'))
    def test_script_has_no_download_or_program_start(self):
        source=R+W
        self.assertNotRegex(source,r'(?i)\b(?:Invoke-WebRequest|Invoke-RestMethod|Start-Process|New-Service|Register-ScheduledTask)\b')
        self.assertNotRegex(source,r'(?i)\b(?:VirtualAlloc|WriteProcessMemory|CreateProcessW)\b')
    def test_native_bat_ascii_crlf_and_valid_labels(self):
        for name in ['Build_Win64.bat','Build_Overlay_Win64.bat','Rebuild_Overlay_Client_Win64.bat','Prepare_Overlay_IDE.bat','Run_GameBuild.bat','Update_Overlay_Identity.bat']:
            raw=(N/name).read_bytes();raw.decode('ascii')
            self.assertNotIn(b'\n',raw.replace(b'\r\n',b''),name)
            s=text(name);labels=set(re.findall(r'^:(\w+)',s,re.M));jumps=set(re.findall(r'\bgoto (\w+)',s,re.I))
            self.assertFalse(jumps-labels,name)
    def test_project_sources_exist(self):
        for p in (B,C):
            for name in ('DCCReference','DelphiCompile','None'):
                for item in p.findall('.//m:'+name,NS):
                    self.assertTrue((N/item.attrib['Include']).is_file(),item.attrib)
    def test_runtime_still_requires_exact_digest(self):
        self.assertIn('SameText(Digest.SHA256, OverlayExpectedSHA256)',text('Game.Overlay.Client.pas'))
        self.assertNotIn('write-overlay-identity',text('Game.Overlay.Client.pas'))
        self.assertIn("{$I Game.Overlay.Identity.inc}",text('Game.Overlay.Client.pas'))

if __name__=='__main__':unittest.main(verbosity=2)
