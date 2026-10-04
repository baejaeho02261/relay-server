"""Source/packaging contracts only, NOT a Delphi compile or Windows UI test."""
from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
N = ROOT / 'GameConnect_Win64'
def text(name): return (N / name).read_text(encoding='utf-8-sig')
CONSOLE=text('Game.Console.pas')
CLIENT=text('Game.Overlay.Client.pas')
WINDOW=text('Game.Overlay.Window.pas')
HANDOFF=text('Game.Handoff.pas')
NS={'m':'http://schemas.microsoft.com/developer/msbuild/2003'}

def body(source, start, end): return source.split(start,1)[1].split(end,1)[0]
class OverlaySourceContract(unittest.TestCase):
    def test_b_does_not_render(self):
        for source in (CONSOLE, CLIENT, text('GameConnect.dpr')):
            self.assertNotRegex(source,r'\b(?:CreateWindowExW?|RegisterClassExW?|BeginPaint|SetLayeredWindowAttributes)\s*\(')
            self.assertNotRegex(source,r'\b(?:Vcl|FMX)\.')
    def test_only_separate_exe_draws(self):
        self.assertIn("Game.Overlay.Window in 'Game.Overlay.Window.pas'",text('GameOverlay.dpr'))
        for symbol in ['CreateWindowExW(', 'BeginPaint(', 'SetLayeredWindowAttributes(']: self.assertIn(symbol,WINDOW)
        self.assertNotIn('Game.Overlay.Window',CONSOLE+CLIENT+text('GameConnect.dpr'))
    def test_live_authentication_gate(self):
        tick=body(CONSOLE,'procedure TConsoleSession.Tick;','function TConsoleSession.ReadKey(')
        self.assertLess(tick.index('if WorkerState = WorkerActive then'),tick.index('FOverlay.Pulse('))
        self.assertLess(tick.index('GetTickCount64 >= FWorker.LeaseDeadline'),tick.index('FOverlay.Pulse('))
        self.assertIn('FApi.Redeem(Key)',CONSOLE)
        self.assertIn('LicenseState := FApi.Verify;',CONSOLE)
        self.assertNotIn('SERVER_ASSIGNED_V1',CONSOLE)
    def test_image_cleanup_is_still_license_gated(self):
        redeem=body(CONSOLE,'procedure TIntegrityWorker.RedeemPending(', 'procedure TIntegrityWorker.Execute;')
        self.assertLess(redeem.index('if not LicenseState.IsActive then'),redeem.index('FHandoff.CleanupBinaryAfterLicense'))
        self.assertIn('if FBinaryCleanupAttempted then Exit;',HANDOFF)
    def test_stop_before_worker_join(self):
        dtor=body(CONSOLE,'destructor TConsoleSession.Destroy;', 'procedure TConsoleSession.WriteText(')
        self.assertLess(dtor.index('FOverlay.Stop'),dtor.index('FWorker.Free'))
        self.assertLess(dtor.index('FWorker.Free'),dtor.index('FOverlay.Free'))
    def test_explicit_absolute_image_no_shell(self):
        self.assertIn('CreateProcessW(PWideChar(FileName), PWideChar(CommandLine)',CLIENT)
        self.assertIn('UniqueString(CommandLine);',CLIENT)
        self.assertNotRegex(CLIENT,r'\b(?:ShellExecute|ShellExecuteW|WinExec)\s*\(')
    def test_explicit_three_handle_inheritance(self):
        self.assertIn('InheritedHandles: array[0..2] of THandle;',CLIENT)
        self.assertIn('AttributeHandleList,\n        @InheritedHandles[0], SizeOf(InheritedHandles)',CLIENT)
        self.assertIn('True, ExtendedStartupInfoPresent or CREATE_NO_WINDOW',CLIENT)
        self.assertIn('SYNCHRONIZE or QueryLimitedProcess',CLIENT)
    def test_no_credentials_in_child_command(self):
        argv=body(CLIENT,"      CommandLine := '", '      UniqueString(')
        self.assertNotRegex(argv,r'(?:SessionToken|LicenseID|PrivateKey|HandoffToken|FPendingKey)')
        self.assertEqual(argv.count('UIntToStr(UInt64(InheritedHandles['),3)
    def test_verified_separate_file_before_start(self):
        self.assertIn("OverlayFileName = 'GameOverlay.exe'",CLIENT)
        self.assertIn('IntegrityHashHandle(FImage)',CLIENT)
        self.assertIn('SameText(Digest.SHA256, OverlayExpectedSHA256)',CLIENT)
        self.assertLess(CLIENT.index('SameText(Digest.SHA256, OverlayExpectedSHA256)'),CLIENT.index('if not CreateProcessW('))
        self.assertIn('FILE_SHARE_READ, nil, OPEN_EXISTING, OpenReparsePointFlag',CLIENT)
    def test_no_exe_resource_embedding_or_runtime_write(self):
        self.assertNotRegex(CLIENT,r'\b(?:WriteFile|DeleteFile|CreateDirectory|FindResource|LoadResource)\s*\(')
        self.assertNotIn('RCDATA',text('GameConnect.rc'))
        self.assertNotIn('GameOverlay',text('GameConnect.rc'))
    def test_rechecks_expiry_after_launch_work(self):
        pulse=body(CLIENT,'procedure TOverlayCompanion.Pulse(', 'procedure TOverlayCompanion.Stop;')
        self.assertEqual(pulse.count('GetTickCount64 >= LeaseDeadline'),2)
        self.assertLess(pulse.rindex('GetTickCount64 >= LeaseDeadline'),pulse.index('SetEvent(FPulseEvent)'))
    def test_start_once_and_no_forced_process_kill(self):
        self.assertIn('if FAttempted or FStopped then Exit;',CLIENT)
        self.assertNotRegex(CLIENT+WINDOW,r'\b(?:TerminateProcess|TerminateThread|WriteProcessMemory|CreateRemoteThread|SetWindowsHookExW?)\s*\(')
        stop=body(CLIENT,'procedure TOverlayCompanion.Stop;', 'destructor TOverlayCompanion.Destroy;')
        self.assertIn('SetEvent(FStopEvent)',stop)
    def test_no_standalone_window_on_doubleclick(self):
        self.assertIn("(ParamCount <> 4) or (ParamStr(1) <> '--game-overlay-v1')",WINDOW)
        self.assertLess(WINDOW.index('if not ReadHandles(Handles) then Exit;'),WINDOW.index('Window := CreateWindowExW('))
        self.assertLess(WINDOW.index('if WaitResult <> WAIT_OBJECT_0 + 2 then Exit;'),WINDOW.index('Window := CreateWindowExW('))
    def test_pointer_inheritance_cleared(self):
        self.assertIn('SetHandleInformation(Handles[I], HANDLE_FLAG_INHERIT, 0)',WINDOW)
    def test_clickthrough_noactivation_noform(self):
        self.assertIn('WS_EX_LAYERED or WS_EX_TRANSPARENT',WINDOW)
        self.assertIn('WS_EX_TOOLWINDOW or WS_EX_TOPMOST or ExNoActivate',WINDOW)
        self.assertIn('SW_SHOWNOACTIVATE',WINDOW)
        self.assertNotRegex(WINDOW,r'\b(?:Vcl|FMX)\.')
    def test_pulse_stale_hides_no_ban(self):
        self.assertIn('GetTickCount64 - LastPulse >= HeartbeatGraceMS',WINDOW)
        self.assertIn('ShowWindow(Window, SW_HIDE)',WINDOW)
        self.assertIn('LastPulse := GetTickCount64',WINDOW)
        self.assertNotIn('TGameApi',WINDOW)
    def test_child_exit_is_parent_or_stop_signalled(self):
        self.assertIn('(WaitResult = WAIT_OBJECT_0) or (WaitResult = WAIT_OBJECT_0 + 1)',WINDOW)
        self.assertIn('MsgWaitForMultipleObjects(',WINDOW)
    def test_build_order_and_include(self):
        p=ET.fromstring(text('GameConnect.dproj'))
        pre=p.find('.//m:PreBuildEvent',NS).text
        self.assertIn('Update_Overlay_Identity.bat" verify --no-pause',pre)
        self.assertNotIn('Run_GameBuild',pre)
        self.assertNotIn('InitialTargets',p.attrib)
        self.assertEqual(p.find('.//m:DCC_IncludePath',NS).text,'$(MSBuildProjectDirectory);$(DCC_IncludePath)')
        c=ET.fromstring(text('GameOverlay.dproj'))
        self.assertIn('invalidate --no-pause',c.find('.//m:PreBuildEvent',NS).text)
        self.assertIn('generate --no-pause',c.find('.//m:PostBuildEvent',NS).text)
        self.assertNotRegex(text('build-game.ps1'),r'(?i)(?:dcc64|MSBuild)\.exe')
    def test_overlay_project_no_packages_and_as_invoker(self):
        p=ET.fromstring(text('GameOverlay.dproj'))
        self.assertEqual(p.find('.//m:MainSource',NS).text,'GameOverlay.dpr')
        self.assertIsNone(p.find('.//m:DCC_UsePackage',NS).text)
        self.assertIn('level="asInvoker"',text('GameOverlay.manifest'))
    def test_new_b_apis_preserve_existing_binding_convention(self):
        self.assertNotRegex(CLIENT,r'\bexternal\b')
        self.assertEqual(len(re.findall(r'^  BindApiPointer\(OverlaySlot_',CLIENT,re.M)),16)
        self.assertIn("RequireProcAddressHash64('kernel32.dll', HASH_CreateProcessW)",CLIENT)
        self.assertIn('DecodeApiPointer(OverlaySlot_CreateProcessW)',CLIENT)
    def test_all_api_hash_values(self):
        values=re.findall(r'HASH_(\w+): Cardinal = \$([0-9A-F]+)',text('Game.Api.ROR13.pas'))
        self.assertEqual(len(values),127)
        self.assertEqual(len({v for _,v in values}),127)
        for name,h in values:
            actual=0
            for byte in name.encode('ascii'):
                actual=(((actual>>13)|(actual<<19))+byte)&0xffffffff
            self.assertEqual(actual,int(h,16),name)
    def test_inherited_is_not_a_local_identifier(self):
        self.assertNotRegex(CLIENT, r'(?im)^\s*Inherited\s*:')
        self.assertNotRegex(CLIENT, r'\bInherited\s*\[')
        self.assertIn('inherited Create;',CLIENT)
        self.assertIn('inherited Destroy;',CLIENT)
    def test_window_message_unit_and_var_argument(self):
        self.assertIn('uses Winapi.Windows, Winapi.Messages, System.SysUtils;',WINDOW)
        self.assertIn('MsgWaitForMultipleObjects(Length(Handles), Handles[0],',WINDOW)
        self.assertNotIn('MsgWaitForMultipleObjects(Length(Handles), @Handles[0],',WINDOW)
        self.assertIn('WaitForMultipleObjects(Length(Handles), @Handles[0],',WINDOW)
    def test_overlay_resource_is_shipped(self):
        self.assertIn("{$R 'GameOverlayResources.res'}",text('GameOverlay.dpr'))
        raw=(N/'GameOverlayResources.res').read_bytes()
        self.assertGreater(len(raw),32)
        self.assertEqual(raw[:8],bytes([0,0,0,0,32,0,0,0]))
    def test_pascal_encoding_and_delimiters(self):
        for rel in ['Game.Overlay.Client.pas','GameOverlay.dpr','Game.Overlay.Window.pas','tests/OverlayLifecycleProbe.dpr']:
            raw=(N/rel).read_bytes()
            self.assertTrue(raw.startswith(b'\xef\xbb\xbf'),rel)
            self.assertNotIn(b'\n',raw.replace(b'\r\n',b''),rel)
            self.assertTrue(raw.rstrip().endswith(b'end.'),rel)

if __name__=='__main__':unittest.main(verbosity=2)
