"""Source-level sequencing/ownership checks; NOT a Delphi compile or Windows test."""
from pathlib import Path
import re
import subprocess
root=Path(__file__).resolve().parents[3]
def read(relative):
    # Reuse the strict semantic source loader used by the JS contract tests;
    # it reads actual current constants and verifies map/import ownership.
    loader=root/'Relay Server/tests/fixtures/source/peace.native-string-contract.js'
    code="process.stdout.write(require(process.argv[1]).ReadContractFile(process.argv[2], 'utf8'))"
    return subprocess.check_output(['node','-e',code,str(loader),str(root/relative)],text=True).replace('\r','')
handoff=read('Railway/Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas')
license_session=read('Railway/Cozy.Source/Cozy.License/Cozy.License.Session.pas')
window=read('Railway/Cozy.Source/Cozy.License/Cozy.License.Window.pas')
commands=read('Railway/Cozy.Source/Cozy.License/Cozy.License.Commands.pas')
api=read('Railway/Cozy.Source/Cozy.Platform/Cozy.Api.pas')
overlay=read('Railway/Cozy.Source/Cozy.Overlay/Cozy.Overlay.pas')
module_inventory=read('Railway/Cozy.Source/Cozy.Integrity/Cozy.ModuleInventory.pas')
count=0

def check(name,condition):
    global count
    assert condition,name
    count+=1
    print('PASS',name)

claim=handoff.split('procedure THandoffContext.CompleteClaimAndCleanupCore(',1)[1].split('procedure THandoffContext.CleanupBinaryAfterLicenseCore;',1)[0]
cleanup=handoff.split('procedure THandoffContext.CleanupBinaryAfterLicenseCore;',1)[1].split('function THandoffContext.TakeImageIntegrityCore:',1)[0]
redeem=license_session.split('procedure TLicenseWorker.RedeemPending(',1)[1].split('procedure TLicenseWorker.ScheduleLicenseRenewal(',1)[0]
schedule=license_session.split('procedure TLicenseWorker.ScheduleLicenseRenewal(',1)[1].split('function TLicenseWorker.RenewActivatedLicense:',1)[0]
renew_activated=license_session.split('function TLicenseWorker.RenewActivatedLicense: Boolean;',1)[1].split('procedure TLicenseWorker.LaunchOverlay;',1)[0]
launch=license_session.split('procedure TLicenseWorker.LaunchOverlay;',1)[1].split('procedure TLicenseWorker.Execute;',1)[0]
execute=license_session.split('procedure TLicenseWorker.Execute;',1)[1].split('function RunLicenseClient(',1)[0]
request_launch=commands.split('function TLicenseCommandMailbox.RequestLaunch: Boolean;',1)[1].split('function TLicenseCommandMailbox.TakeLaunch:',1)[0]
take_launch=commands.split('function TLicenseCommandMailbox.TakeLaunch: Boolean;',1)[1].split('procedure TLicenseCommandMailbox.Complete(',1)[0]
main=license_session.split('function RunLicenseClient(const Monitor: ICozyProtectionSession;')[-1].split('\ninitialization')[0]
check('A deletion stays in authenticated handoff', re.search(r'SetFileInfo\(LauncherFile,\s*FileDispositionInfoClass', claim) is not None)
check('B is not unlinked at claim time', 'UnlinkVerifiedOwnImage(' not in claim)
check('The verified B handle is transferred rather than reopened after license', 'FBinaryCleanupFile := BinaryFile;\n    BinaryFile := 0;' in claim and 'OpenSafeImage(' not in cleanup)
check('Activation verifies a live license without starting O',
      redeem.index('LicenseState := FApi.Redeem(BoundaryKey);') < redeem.index('if not LicenseState.IsActive then') < redeem.index('FCommands.Complete(WorkerLicensed);')
      and 'StartOverlay(' not in redeem and 'Terminate;' not in redeem)
check('Only a verified worker grant and queued handoff starts O',
      'FState <> WorkerLicensed' in request_launch
      and request_launch.index('FLock.Acquire;') < request_launch.index('FLaunchPending := True;') < request_launch.index('FState := WorkerBusy;') < request_launch.index('finally FLock.Release;')
      and 'if FStopping or (FState <> WorkerBusy) or not FLaunchPending then Exit;' in take_launch
      and take_launch.index('FLaunchPending := False;') < take_launch.index('Result := True;')
      and execute.index('if FCommands.TakeLaunch then') < execute.index('LaunchOverlay;')
      and launch.index('if Terminated or FCommands.Stopping then Exit;') < launch.index('if not FApi.StartOverlay(False,'))
check('An authenticated grant remains monitored while waiting for deliberate launch',
      'WorkerLicensed = 2;' in commands
      and 'if Outcome = WorkerLicensed then FProgress := 40 else FProgress := 0;' in commands
      and 'if Outcome = WorkerFailed then FStopping := True;' in commands
      and 'while not Terminated and not FCommands.Stopping do' in execute
      and 'FApi.CheckIntegrity;' in execute and 'FApi.ContinueModuleInventory' in execute
      and 'begin Result := Worker.RequestLaunch; end,' in main)
check('The authenticated session renews inside its last signed license window',
      'LicenseState.LeaseDeadlineTick <= NowTick' in schedule
      and 'Delay := (LicenseState.LeaseDeadlineTick - NowTick) div 3;' in schedule
      and 'if Delay > HeartbeatMilliseconds then Delay := HeartbeatMilliseconds;' in schedule
      and 'FNextLicenseCheck := NowTick + Delay;' in schedule
      and redeem.index('ScheduleLicenseRenewal(LicenseState);') < redeem.index('FCommands.Complete(WorkerLicensed);')
      and 'if (State = WorkerLicensed) and (NowTick >= FNextLicenseCheck) then' in execute
      and 'if not RenewActivatedLicense then Break;' in execute)
check('License renewal cannot revive an expired or stopped gallery permission',
      renew_activated.index('Previous := FApi.Current;') < renew_activated.index('if not Previous.IsActive then')
      < renew_activated.index('Renewed := FApi.Verify;')
      < renew_activated.index('if Terminated or FCommands.Stopping then Exit;', renew_activated.index('Renewed := FApi.Verify;'))
      < renew_activated.index('(CozyTick >= Previous.LeaseDeadlineTick) or not Renewed.IsActive')
      < renew_activated.index('ScheduleLicenseRenewal(Renewed);')
      and 'FCommands.Complete(WorkerFailed); Exit;' in renew_activated)
check('The requested handoff rechecks the live license and observes renewal time',
      launch.index('if not RenewActivatedLicense then Exit;') < launch.index('if not FApi.StartOverlay(False,')
      and execute.index('if (State = WorkerLicensed) and (FNextLicenseCheck < WaitUntil) then')
      < execute.index('WaitUntil := FNextLicenseCheck;') < execute.index('WaitForMultipleObjects('))
check('A stopped or duplicate launch cannot reopen work or retain a key',
      'FStopping or (FState <> WorkerLicensed) or FLaunchPending or' in request_launch
      and '(FPending <> nil) then Exit;' in request_launch
      and 'FStopping := True; FLaunchPending := False;' in commands
      and '((FState <> WorkerBusy) or (FPending <> nil) or FLaunchPending) then Exit;' in commands)
check('Submit has no artificial minimum wait or time-based completion',
      all(token not in license_session+window+commands for token in
          ['WaitForSubmitPresentation', 'LicenseSubmitMinimumMilliseconds', 'AttemptStartedAt', 'FSubmitAt', 'CompletedWaveHoldSeconds', 'TransferCloseFallbackMs']))
progress=commands.split('procedure TLicenseCommandMailbox.ReportProgress(Value: Integer);',1)[1].split('function TLicenseCommandMailbox.Progress:',1)[0]
completion=commands.split('procedure TLicenseCommandMailbox.Complete(Outcome: Integer);',1)[1].split('procedure TLicenseCommandMailbox.Stop;',1)[0]
check('Worker milestones are monotonic and cannot publish transfer completion',
      'if Value > 99 then Value := 99;' in progress
      and 'if not FStopping and (FState = WorkerBusy) and (Value > FProgress) then' in progress
      and 'FProgress := Value;' in progress
      and 'if Outcome = WorkerTransferred then' in completion
      and 'FState := WorkerTransferred; FProgress := 100; FStopping := True;' in completion)
check('B maps handoff loading bar milestones from 0 and reserves 100 for transfer',
      'FCommands.ReportProgress(40);' in redeem
      and 'procedure(Value: Integer) begin FCommands.ReportProgress(Value); end)' in launch
      and 'LicenseHandoffBaseline = 40;' in window
      and 'Percent := FProgress() - LicenseHandoffBaseline;' in window
      and 'if Percent < 0 then Percent := 0;' in window
      and 'if Percent > 99 - LicenseHandoffBaseline then Percent := 99 - LicenseHandoffBaseline;' in window
      and 'Progress := Percent / (100 - LicenseHandoffBaseline);' in window
      and 'ImGuiLicenseSceneReveal(FContext, ScenePhase, KeyCharacters, Progress, nil, 0)' in window)
check('Only definitive key rejection silently reopens the same B without a timer',
      all("E.Code = '"+code+"'" in redeem for code in ['LICENSE_KEY_INVALID','DESKTOP_KEY_INVALID','DESKTOP_KEY_USED','DESKTOP_EXPIRED','DESKTOP_REVOKED','DESKTOP_RELEASED'])
      and 'if not Terminated and not FCommands.Stopping then\n            FCommands.Complete(WorkerIdle);' in redeem
      and 'else\n          FCommands.Complete(WorkerFailed);' in redeem)
check('Confirmed transfer terminates B worker without another proof or active unlink', launch.index('if not FApi.StartOverlay(False,') < launch.index('FCommands.Complete(WorkerTransferred)') < launch.index('Terminate;') and 'CleanupBinaryAfterLicense' not in license_session and 'WorkerActive' not in license_session)
check('B window exits on transfer and joins worker before destroying resources', 'State = WorkerTransferred' in window and main.index('Worker.Free;') < main.index('Api.Free;') < main.index('Context.Free;'))
paint=window.split('procedure TLicenseWindow.Paint;',1)[1].split('function TLicenseWindow.Message(',1)[0]
window_run=window.split('function TLicenseWindow.Run(const BeforeShow: TProc): Integer;',1)[1].split('function RunLicenseWindow(',1)[0]
selected=window.split('procedure TLicenseWindow.LaunchSelected;',1)[1].split('procedure TLicenseWindow.ObserveRedemption(',1)[0]
rocket_input=window.split('function TLicenseWindow.RocketInputEnabled:',1)[1].split('function TLicenseWindow.ControlInputEnabled(',1)[0]
submit=window.split('procedure TLicenseWindow.Submit;',1)[1].split('procedure TLicenseWindow.LaunchSelected;',1)[0]
window_cancel=window.split('procedure TLicenseWindow.CancelInput;',1)[1].split('procedure TLicenseWindow.Close;',1)[0]
paste=window.split('procedure TLicenseWindow.PasteKey;',1)[1].split('procedure TLicenseWindow.Submit;',1)[0]
check('The Earth borrows a protected key only for focused clipboard, redemption or outcome frames',
      'else\n    Actions := ImGuiLicenseSceneReveal(FContext, ScenePhase, KeyCharacters, Progress, nil, 0);' in paint
      and paint.count('FKey.CopyText') == 1
      and re.search(r'if not FResetKeySequence and\s*\(Phase in \[0, 1, 2, LicensePhaseRejectScan, LicensePhaseAcceptScan,\s*LicensePhaseRejected, LicensePhaseAccepted\]\) then KeyCharacters := FKey.Count;\s*if \(KeyCharacters > 0\) and WindowInputEnabled then', paint) is not None)
check('The copied key is wiped from temporary text before presenting the synchronous draw',
      paint.index('RevealedKey := FKey.CopyText;')
      < paint.index('PWideChar(RevealedKey), Length(RevealedKey)')
      < paint.index('WipeBoundaryText(RevealedKey);')
      < paint.index('ImGuiEndCanvas(FContext);') < paint.index('Presented := ImGuiPresent(FContext);')
      and 'finally\n      WipeBoundaryText(RevealedKey);' in paint)
check('Only the visible Earth action imports the clipboard and its revealed key submits once',
      len(re.findall(r'\bPasteKey\b',window)) == 3
      and len(re.findall(r'\bSubmit;',window)) == 3
      and paint.index('Presented := ImGuiPresent(FContext);')
      < paint.index('if not FVisibleFrame then')
      < paint.index('if ((Phase = 0) or (Phase = 2)) and SceneInputEnabled then')
      < paint.index('if (Actions and LicenseSceneReadClipboard) <> 0 then PasteKey')
      < paint.index('else if (Actions and LicenseSceneAutoSubmit) <> 0 then Submit;')
      and 'WM_CHAR: Exit;' in window
      and not any(token in window for token in ['ApiSetClipboardData', 'ApiEmptyClipboard', 'WM_CLIPBOARDUPDATE', 'WM_PASTE', 'LicenseSceneConfirm']))
check('A validated clipboard snapshot replaces the prior key only after a fresh focus check',
      paste.index('if not SceneInputEnabled then Exit;') < paste.index('ApiOpenClipboard(FWindow)')
      < paste.index('if not ClipboardKeySpan(') < paste.index('Value := TCozySensitiveText.Create(')
      < paste.index('ApiCloseClipboard;') < paste.rindex('if not SceneInputEnabled then Exit;')
      < paste.index('Previous := FKey;') < paste.index('FKey := Value;')
      < paste.index('FResetKeySequence := True;') < paste.index('FAutoSubmitPending := True;')
      < paste.index('FreeAndNil(Value);')
      and 'if Last = Limit then Exit;' in window
      and 'if Count = 75 then' in window and 'else if Count <> 64 then Exit;' in window)
transfer_close=paint.split('if (State = WorkerTransferred) and (Phase = LicensePhaseTransferred) and',1)[1].split('AdvancePresentedSequence(',1)[0]
check('A verified transfer closes directly after the 100 percent frame presents',
      'else if State = WorkerTransferred then Phase := LicensePhaseTransferred' in paint
      and 'if Phase = LicensePhaseTransferred then Progress := 1;' in paint
      and paint.index('Presented := ImGuiPresent(FContext);') < paint.index('if not FVisibleFrame then')
      < paint.index('if (State = WorkerTransferred) and (Phase = LicensePhaseTransferred) and')
      and transfer_close.index('Actions and LicenseSceneComplete') < transfer_close.index('FPresentationComplete := True;')
      < transfer_close.index('Close;') < transfer_close.index('Exit;')
      and 'if FPresentationComplete and (FState() = WorkerTransferred) then Result := 0;' in window_run
      and not re.search(r'License(?:PhaseToast|SceneToastComplete)',window))
unpresented=paint.split('if not FVisibleFrame then',1)[1].split('if (State = WorkerTransferred)',1)[0]
check('A temporarily unavailable surface preserves the result and its timeout exits unsuccessfully',
      window_run.index('if State = WorkerTransferred then') < window_run.index('FTransferVisualDeadline := CozyTick + LicensePresentationTimeoutMs;')
      < window_run.index('if CozyTick >= FTransferVisualDeadline then')
      < window_run.index('begin Close; Break; end;',window_run.index('if CozyTick >= FTransferVisualDeadline then'))
      and window_run.count('Result := 0') == 1
      and paint.index('if not ApiIsWindowVisible(FWindow) then') < paint.index('ImGuiNewFrame(FContext,')
      < paint.index('Presented := ImGuiPresent(FContext);') < paint.index('FShown := ApiIsWindowVisible(FWindow);')
      < paint.index('FVisibleFrame := FShown and (Presented = IMGUI_PRESENT_VISIBLE);')
      < paint.index('if not FVisibleFrame then')
      and all(token in unpresented for token in ['CancelInput;', 'Exit;'])
      and all(token not in unpresented for token in ['Close;', 'FOutcomePhase :=', 'FOutcomeProgress :=', 'AdvancePresentedSequence'])
      and 'if FMinimized or FClosing or not FShown or not FVisibleFrame then' in window_run
      and paint.index('if FResizePending then Resize;') < paint.index('Presented := ImGuiPresent(FContext);'))
check('Only a later present after the full rocket frame can deliver a launch action',
      paint.index('Presented := ImGuiPresent(FContext);') < paint.index('if not FVisibleFrame then')
      < paint.index('if Phase = LicensePhaseRocket then')
      < paint.index('if FRocketReady and ((Actions and LicenseSceneRocketLaunch) <> 0) then')
      < paint.index('begin LaunchSelected; Exit; end;')
      < paint.index('FRocketReady := (Actions and LicenseSceneRocketReady) <> 0;')
      and 'LaunchSelected' not in window_run and 'AdvanceAutomaticLaunch' not in window
      and window.count('LaunchSelected;') == 3)
check('A ready visible rocket may queue one handoff while the authorized worker is still live',
      all(token in rocket_input for token in ['WindowInputEnabled and FRocketReady and not FLaunchRequested',
          'not FRedemptionPending and (FOutcomePhase = 0)', '(FState() = WorkerLicensed)'])
      and selected.index('if not RocketInputEnabled then Exit;') < selected.index('FRocketReady := False;')
      < selected.index('Accepted := FLaunch();') < selected.index('State := FState();')
      < selected.index('if Accepted or (State = WorkerBusy) or (State = WorkerTransferred) then')
      < selected.index('FLaunchRequested := True;')
      and 'else Close;' in selected and 'if not Assigned(FLaunch) then' in selected)
refused=selected.split('else if State = WorkerIdle then',1)[1].split('else Close;',1)[0]
check('A request with a retracted idle grant returns silently to the Earth',
      selected.index('Accepted := FLaunch();') < selected.index('State := FState();')
      < selected.index('else if State = WorkerIdle then') and 'FShowRetryFrame := True' in refused
      and all(token not in refused for token in ['Close;', 'FKey.Clear', 'FFocused := False', 'CancelInput', 'CopyText']))
check('Rocket, in-flight loader and committed loader have distinct phases after the outcome',
      'if FLaunchRequested then Phase := LicensePhaseTransfer else Phase := 1;' in paint
      and 'else if State = WorkerLicensed then Phase := LicensePhaseRocket' in paint
      and paint.index('if FOutcomePhase <> 0 then Phase := FOutcomePhase')
      < paint.index('else if State = WorkerTransferred then Phase := LicensePhaseTransferred')
      and 'ScenePhase := Phase or (FThemeIndex shl 8);' in paint)
check('Automatic submission creates a separate sensitive key owner and consumes its one-shot latch',
      submit.index('if not FAutoSubmitPending or not SceneInputEnabled or (FKey.Count = 0) then Exit;')
      < submit.index('FAutoSubmitPending := False;') < submit.index('Key := TCozySensitiveText.Create(MaximumKeyCharacters);')
      < submit.index('Key.AppendBuffer(FKey);') < submit.index('FRedemptionPending := FSubmit(Key);')
      < submit.index('finally') < submit.index('FreeAndNil(Key);')
      and not any(token in submit for token in ['CopyText', 'Key := FKey', 'FKey := nil', 'FreeAndNil(FKey)', 'ImGuiClearInput', 'FKey.Clear']))
check('Focus loss preserves sealed key ownership while rendering receives only its count',
      paint.index('Progress := FOutcomeProgress;') < paint.index('KeyCharacters := 0;')
      < paint.index('then KeyCharacters := FKey.Count;') < paint.index('if (KeyCharacters > 0) and WindowInputEnabled then')
      and 'ImGuiLicenseSceneReveal(FContext, ScenePhase, KeyCharacters, Progress, nil, 0);' in paint
      and 'FKey' not in window_cancel.split('procedure TLicenseWindow.ClearKey;',1)[0]
      and 'WM_KILLFOCUS: begin FFocused := False; CancelInput; ImGuiFocus(FContext, False); Exit; end;' in window)
advance=window.split('procedure TLicenseWindow.AdvancePresentedSequence(',1)[1].split('procedure TLicenseWindow.Paint;',1)[0]
check('A visibly completed outcome or closing wipes the retained clipboard key',
      paint.index('Presented := ImGuiPresent(FContext);') < paint.index('if not FVisibleFrame then')
      < paint.index('AdvancePresentedSequence(Phase, Actions, PresentedDelta);')
      and advance.index('((Actions and CompletionAction) = 0)') < advance.index('ClearKey;')
      < advance.index('FOutcomePhase := 0;')
      and 'FClosing := True;\n  ClearKey;' in window
      and 'if FKey <> nil then FKey.Clear;' in window
      and 'FreeAndNil(FKey);' in window)
outcome=window.split('procedure TLicenseWindow.ObserveRedemption(State: Integer);',1)[1].split('procedure TLicenseWindow.AdvancePresentedSequence(',1)[0]
check('Only real worker outcomes trigger the full scan and absorption and rejection returns silently to Earth',
      outcome.index('if not FRedemptionPending then Exit;') < outcome.index('case State of')
      and 'WorkerIdle: FOutcomePhase := LicensePhaseRejectScan;' in outcome
      and 'WorkerLicensed: FOutcomePhase := LicensePhaseAcceptScan;' in outcome
      and 'LicensePhaseRejectScan: FOutcomePhase := LicensePhaseRejected;' in advance
      and 'LicensePhaseAcceptScan: FOutcomePhase := LicensePhaseAccepted;' in advance
      and 'FShowRetryFrame := Phase = LicensePhaseRejected;' in advance
      and 'if ((Phase = 0) or (Phase = 2)) and SceneInputEnabled then' in paint
      and not any(token in window for token in ['MessageBeep', 'MessageBox', 'Beep(', 'Shake', 'ErrorPage']))
check('B fits the monitor and uses the scene pixel coordinates for its rounded client window',
      all(token in window for token in ['PanelWidth = 380;', 'PanelHeight = 520;',
          'WM_NCCALCSIZE: Exit(0);', 'Width := Round(PanelWidth * FitScale);', 'Height := Round(PanelHeight * FitScale);',
          'FitWindow(PRect(LParam), LoWord(WParam))', 'WM_NCHITTEST:', 'then Exit(HTTRANSPARENT);',
          'Hit := ImGuiLicenseHit(FContext, X, Y);', 'WM_CLOSE: begin Close; Exit; end;', 'WParam = VK_F4'])
      and window.index('ApiSetWindowPos(FWindow, 0, Suggested.Left, Suggested.Top,')
      < window.index('Monitor := ApiMonitorFromWindow(FWindow, LicenseMonitorDefaultToNearest);') < window.index('FitScale := FScale;')
      and all(token not in window for token in ['HeaderContains', 'InputContains', 'WS_CAPTION', 'WS_THICKFRAME', 'SetWindowRgn']))
check('B uses a taskbar-free tool window and retains normal OS close handling',
      'ApiCreateWindowExW(WS_EX_TOOLWINDOW or NoRedirectionBitmap,' in window
      and 'WS_EX_APPWINDOW' not in window and 'LicenseClass,' in window and 'WS_POPUP' in window
      and 'WM_CLOSE: begin Close; Exit; end;' in window and 'WParam = VK_F4' in window
      and not any(token in window for token in ['LicenseSceneMinimize', 'LicenseSceneClose', 'ApiShowWindow(FWindow, SW_MINIMIZE)']))
press=window.split('    WM_LBUTTONDOWN:',1)[1].split('    WM_LBUTTONUP:',1)[0]
release=window.split('    WM_LBUTTONUP:',1)[1].split('    WM_MOUSEWHEEL',1)[0]
check('A background drag is thresholded and only native Earth or a ready rocket receive a press',
      press.index('Hit := ImGuiLicenseHit(FContext, X, Y);') < press.index('if Hit = HitBackground then')
      < press.index('FGesture := lgBackground;')
      < press.index('else if ControlInputEnabled(Hit) then')
      < press.index('FGesture := lgControl;') < press.index('ImGuiMouseButton(FContext, 0, True);')
      and 'if DragThresholdReached(Position) then FGesture := lgMoving;' in window
      and 'Threshold := Round(4 * FScale);' in window and 'WM_CANCELMODE, WM_CAPTURECHANGED:' in window
      and 'if ApiGetCapture <> Window then' in press
      and 'if FGesture <> lgMoving then CancelInput;' in window
      and 'FDragOrigin := Bounds.TopLeft;' in press and 'FDragAnchor := Point(Bounds.Left + X, Bounds.Top + Y);' in press
      and release.index('if FGesture = lgControl then') < release.index('ImGuiMouseButton(FContext, 0, False);')
      < release.index('ReleaseOwnCapture;'))
keys=window.split('    WM_KEYDOWN, WM_SYSKEYDOWN:',1)[1].split('    WM_KEYUP, WM_SYSKEYUP:',1)[0]
check('Keys activate controls only through the focused native scene',
      keys.index('if SceneInputEnabled or RocketInputEnabled then') < keys.index('ImGuiKey(FContext, WParam, True);')
      and all(token not in keys for token in ['FKey.', 'PasteKey', 'Submit', 'VK_RETURN'])
      and 'WM_CHAR: Exit;' in window)
cursor=window.split('procedure TLicenseWindow.UpdateCursor(Force: Boolean);',1)[1].split('procedure TLicenseWindow.FitWindow(',1)[0]
check('The hand cursor is limited to the interactive Earth or a ready rocket',
      'FHandCursor := ApiLoadCursorW(0, PWideChar(NativeUInt(32649)))' in window
      and 'FBusyCursor' not in window and 'NativeUInt(32648)' not in window
      and cursor.index('Cursor := FNormalCursor;') < cursor.index('if FVisibleFrame and not FResizePending')
      < cursor.index('Hit := ImGuiLicenseHit(FContext, Position.X - Bounds.Left, Position.Y - Bounds.Top);')
      < cursor.index('ControlInputEnabled(Hit) then') < cursor.index('Cursor := FHandCursor;') < cursor.index('ApiSetCursor(Cursor);')
      and '((Hit = HitClipboardPlanet) and SceneInputEnabled)' in window
      and '((Hit = HitLaunchRocket) and RocketInputEnabled)' in window
      and 'if not WindowInputEnabled or FRedemptionPending or (FOutcomePhase <> 0) or' in window
      and 'WM_MOUSELEAVE: begin PointerLeft; Exit; end;' in window
      and 'then ImGuiMousePos(FContext, -1E30, -1E30);' in window)
check('Pending verification rejects duplicate keyboard and control submissions while releasing mouse capture',
      'if SceneInputEnabled or RocketInputEnabled then' in keys
      and 'Result := State = WorkerIdle;' in window
      and 'not FAutoSubmitPending or not SceneInputEnabled' in submit
      and 'ImGuiMouseButton(FContext, 0, False);' in submit
      and 'ReleaseOwnCapture;' in submit and 'ImGuiClearInput' not in submit)
check('Failure closing remains independent of native presentation',
      paint.index('if (State = WorkerFailed) or (State = WorkerStopped) then') < paint.index('if State = WorkerTransferred then Phase := LicensePhaseTransferred'))
check('Cleanup is guarded once and preserves nonfatal OS refusal', 'if FBinaryCleanupAttempted then Exit;' in cleanup and 'FBinaryCleanupInfo, False);' in cleanup)
check('Cleanup pins the directory but retains the owner after OS refusal', cleanup.index('PinDirectories(') < cleanup.index('UnlinkVerifiedOwnImage(') < cleanup.index('finally') < cleanup.index('CloseAll(Pins)') and 'Close(FBinaryCleanupFile)' not in cleanup)
check('Integrity owns a separate read file object while the cleanup pin remains held', 'IntegrityFile := OpenSafeImage(FBinaryPath, False, IntegrityInfo, False, True);' in claim and 'TImageIntegrity.Create(IntegrityFile, BinarySHA512, ExpectedCRC64);' in claim and 'TImageIntegrity.Create(BinaryFile,' not in claim)
check('Worker is joined before handoff context can be freed', 'FreeAndNil(Context)' not in main and main.index('Worker.Free;') < main.index('Context.Free;'))
destroy=handoff.split('destructor THandoffContext.Destroy;',1)[1].split('end;',1)[0]
check('Destructor releases both B ownership and uncommitted O parent pins', all(s in destroy for s in ['Close(FBinaryCleanupFile);', 'Close(FParentImage);', 'CloseAll(FParentPins);']))
start=api.split('function TGameApi.StartOverlayCore(RestrictedPrivileges: Boolean;',1)[1].split('function TGameApi.RedeemCore(',1)[0]
check('B transfer is committed only after native O ready', start.index('Result := LaunchOverlay(') < start.index('TransferClient.CommitTransfer(') < start.index('FOverlayStarted := True;'))
check('Only a confirmed transfer skips redundant B close after the worker is joined', 'property OverlayTransferred: Boolean read GetOverlayTransferred;' in api and 'try Result := FOverlayStarted; finally TMonitor.Exit(FLock); end;' in api and main.index('Worker.Free;') < main.index('if Api <> nil then Transferred := Api.OverlayTransferred;') < main.index('if (Bootstrap <> nil) and not Transferred then') < main.index('Bootstrap.Close(') < main.index('Api.Free;'))
retire=handoff.split('procedure THandoffContext.CleanupTransferredParentCore;',1)[1].split('procedure THandoffContext.CleanupBinaryAfterLicenseCore;',1)[0]
check('O deletes only an exited process image through matching held and DELETE identities', retire.index('WaitForSingleObject(FParentProcess, 0) = WAIT_OBJECT_0') < retire.index('DeleteFile := OpenSafeImage(') < retire.index('SameIdentity(HeldInfo, DeleteInfo)') < re.search(r'SetFileInfo\(DeleteFile,\s*FileDispositionInfoClass', retire).start())
refresh=overlay.split('procedure TOverlayWorker.Refresh;',1)[1].split('procedure TOverlayWorker.MaintainLease(',1)[0]
renew=overlay.split('procedure TOverlayWorker.RenewLease(',1)[1].split('procedure TOverlayWorker.PrepareTransferBeforeShow;',1)[0]
check('O independently confirms server transfer before B cleanup', renew.index('Lease := FClient.Verify(') < renew.index('TransferConfirmed := FClient.TransferConfirmed;') < renew.index('CleanupParent := ParentExited and FTransferred and not FParentRetirementDone;') < renew.index('if CleanupParent then') < renew.index('FContext.CleanupTransferredParent;'))
check('Full snapshot scheduling remains server-bound and transfer-aware', 'IncludeModules := OverlaySnapshotDue(CozyTick, FLastSnapshotAt, FTransferred,' in refresh and 'FClient.SnapshotDeadlineTick, FLastSnapshotDuration);' in refresh and 'FClient.ReportIntegrity(FContext.Security, FContext.CodeIntegrity, Image,\n    IncludeModules,' in refresh)
ready=overlay.split('procedure TOverlayWorker.FirstFrameReady;',1)[1].split('procedure TOverlayWorker.Refresh;',1)[0]
barrier=overlay.split('procedure TOverlayWorker.PrepareTransferBeforeShow;',1)[1].split('procedure TOverlayWorker.StartAuthorized;',1)[0]
check('Hidden readiness is published under the lock before waiting for B process exit', barrier.index('TMonitor.Enter(FLock)') < barrier.index('FContext.ConfirmOverlayReady;') < barrier.index('FReadyForTransfer := True;') < barrier.index('TMonitor.Exit(FLock)') < barrier.index('while FContext.ParentIsAlive do'))
check('O transition remains bounded by last authenticated lease', '(CozyTick >= FDeadline)' in overlay and "raise EBootstrap.Create('OVERLAY_TRANSFER_NOT_CONFIRMED')" in renew)
check('Window keeps rendering separate from API ownership and has no auto assignment', 'ImGuiCreate(FWindow, True)' in window and not any(x in window for x in ['TGameApi', 'Bootstrap.Claim', 'Redeem(', 'SERVER_ASSIGNED_V1', 'Vcl.Forms', 'FMX.Forms']))
# These inspect the production unit's lock boundaries and cleanup ordering.
# They intentionally do not simulate a worker and do not claim runtime coverage.
cancel=overlay.split('function TOverlayWorker.RequestCancelled: Boolean;',1)[1].split('procedure TOverlayWorker.FirstFrameReady;',1)[0]
stop=overlay.split('procedure TOverlayWorker.Stop;',1)[1].split('function TOverlayWorker.AwaitingTransfer:',1)[0]
close=overlay.split('function TOverlayWorker.ShouldClose: Boolean;',1)[1].split('procedure TOverlayWorker.Execute;',1)[0]
run=overlay.split('function RunOverlay(const Monitor: ICozyProtectionSession): Integer;')[-1].split('\ninitialization')[0]
check('First visible frame requires confirmed transfer and actual parent retirement',
      ready.index('TMonitor.Enter(FLock)') < ready.index('not FTransferred or not FParentRetirementDone') < ready.index('OverlayTransition(FState, osVisible);')
      and '(CozyTick >= FDeadline)' in ready
      and 'ConfirmOverlayReady' not in ready)
check('Repeated successful frame callbacks cannot duplicate visibility publication',
      ready.index('if FFirstFrameShown then Exit;') < ready.index('FFirstFrameShown := True;'))
check('Stop invalidates authorization under the same lock used to publish ready',
      stop.index('Terminate;') < stop.index('TMonitor.Enter(FLock)') < stop.index('FFailed := True;') < stop.index('FDeadline := 0;') < stop.index('TMonitor.Exit(FLock)'))
check('In-flight report and verification callbacks cancel on sticky failure and expired lease',
      'Result := Terminated or FFailed or' in cancel
      and '((FDeadline <> 0) and (CozyTick >= FDeadline))' in cancel
      and cancel.index('TMonitor.Enter(FLock)') < cancel.index('FFailed := True;') < cancel.index('TMonitor.Exit(FLock)')
      and 'function: Boolean begin Result := RequestCancelled; end);' in renew
      and 'function: Boolean begin Result := RequestCancelled; end' in refresh)
publish=renew[renew.rindex('TMonitor.Enter(FLock);'):]
check('Late lease replies cannot reopen stopped or elapsed authorization',
      publish.index('if Terminated or FFailed or (Deadline <= CozyTick)') < publish.index('FDeadline := Deadline;')
      and '((FDeadline <> 0) and (CozyTick >= FDeadline))' in publish
      and publish.index('FFailed := True;') < publish.index('FDeadline := Deadline;') < publish.index('TMonitor.Exit(FLock)'))
check('UI expiry is sticky and snapshots readiness with its deadline under one lock',
      close.index('TMonitor.Enter(FLock)') < close.index('Result := Terminated or FFailed') < close.index('FFailed := True;') < close.index('TMonitor.Exit(FLock)')
      and 'AwaitingTransfer' not in close)
check('Overlay shutdown joins the worker before closing its authenticated client or context',
      run.index('Worker.Stop;') < run.index('Worker.WaitFor;') < run.index('Worker.Free;') < run.index('Client.ShutdownClose(') < run.index('Context.Free;'))
modules=api.split('function TGameApi.ReportModulesIfDue: Boolean;',1)[1].split('function TGameApi.ContinueModuleInventoryCore:',1)[0]
retry=modules.split('if (FModuleGenerationRetries < ModuleGenerationRetryLimit)',1)[1].split('FModuleSnapshotID := RequestID;',1)[0]
predicate=module_inventory.split('function ModuleInventoryGenerationRetryable(Snapshot: TJSONObject): Boolean;')[-1].split('function CollectModuleInventoryJSON(',1)[0]
check('An interrupted loader generation is discarded before any server batch and cannot unblock key redemption',
      modules.index('ModuleInventoryGenerationRetryable(FModuleSnapshot)') < modules.index('FModuleSnapshotID := RequestID;') < modules.index('SendIntegrityReport(Payload);')
      and retry.index('FModuleSnapshotCompleted := False;') < retry.index('ClearModuleSnapshot;') < retry.index('Exit(True);')
      and 'FNextModules := NowTick;' in retry)
check('Generation retry is bounded from the first scan, includes cancellation and resets only after server acceptance',
      'ModuleGenerationRetryLimit = 2;' in api and 'ModuleGenerationRetryMilliseconds = 90000;' in api
      and modules.index('if FModuleGenerationRetries = 0 then FModuleGenerationStarted := NowTick;') < modules.index('CollectModuleInventoryJSON(')
      and '(At < FModuleGenerationStarted)' in modules
      and '(At - FModuleGenerationStarted >= ModuleGenerationRetryMilliseconds)' in modules
      and modules.index('SendIntegrityReport(Payload);') < modules.index('FModuleGenerationRetries := 0;'))
check('Generation-only retry cannot hide read failures, code differences, missing digests or one-shot device evidence',
      all(value in predicate for value in ["'TRACKED_CHANGED'", "'PARTIAL'", "'UNVERIFIED_BASELINE'", "'MATCH_LOCAL_FILE'", "'failurePhase'", "'fileSha512', 128", "'codeSha512', 128", "'MEASURED'", "'NO_EXPORTS'", "'SECTION_HASHED'", "'COMPLETE'", "'unknownStart'", "'unreadable'", "'NOT_REQUESTED'"])
      and not any(value in predicate for value in ['.AddPair(', '.RemovePair(', 'Exit(True)']))
budget=api.split('procedure TGameApi.ApplyModuleSnapshotBudget(',1)[1].split('function TGameApi.ReportModulesIfDue:',1)[0]
send=api.split('procedure TGameApi.SendIntegrityReport(',1)[1].split('procedure TGameApi.ReportMeasurementFailure',1)[0]
maintenance=start.split('      MaintainParent :=',1)[1].split('      CheckIntegrityCore;',1)[0]
check('B only maps a completed matching receipt within the unchanged server freshness bound',
      all(value in budget for value in ["Reply.GetValue('snapshotBudget')", 'SnapshotID <> FModuleSnapshotID',
        'ExpiresAt - ServerTime > MaxLeaseMilliseconds', 'Elapsed >= UInt64(Duration)', 'RequireModuleSnapshotLease;',
        'ServerTime < FModuleReceiptServerTime'])
      and send.index('StartedAt := CozyTick;') < send.index('Challenge := PostJSON(')
      and send.index('Reply := PostJSON(') < send.index('ApplyModuleSnapshotBudget(Reply, StartedAt);')
      and "JsonInteger(Payload, 'batchIndex') + 1 =" in send
      and "JsonInteger(Payload, 'batchCount'))" in send)
check('Cached receipt mapping never extends the first monotonic deadline or revives an elapsed window',
      budget.index('RequireModuleSnapshotLease;') < budget.index('if SnapshotID = FModuleReceiptID then')
      and 'if Deadline < FModuleDeadlineTick then FModuleDeadlineTick := Deadline;' in budget
      and '(ServerTime <> FModuleReceiptServerTime)' in budget
      and '(ExpiresAt <> FModuleReceiptExpiresAt)' in budget
      and '(FModuleDeadlineTick <> 0) and (FModuleDeadlineTick <= CozyTick)' in api)
check('B schedules full refresh using observed collection and all batches plus a chunk/renewal reserve',
      'ModuleSnapshotCheckpointReserve = 30000;' in api
      and 'FModuleCycleMilliseconds := NowTick - FModuleGenerationStarted;' in modules
      and 'Reserved := FModuleCycleMilliseconds + ModuleSnapshotCheckpointReserve;' in modules
      and 'FNextModules := FModuleDeadlineTick - Reserved;' in modules
      and '((FModuleDeadlineTick <> 0) and (At >= FModuleDeadlineTick))' in modules)
check('O download drains due snapshots and child wait yields between batches to observe readiness',
      'if BeforeChild then ParentWaitingForChild := True;' in start
      and maintenance.index('repeat') < maintenance.index('then RenewParent();') < maintenance.index('MoreModules := ReportModulesIfDue;') < maintenance.index('until not MoreModules or ParentWaitingForChild;')
      and 'if BeforeChild and (FModuleSnapshot = nil) then FNextModules := 0;' in maintenance
      and 'RequireParentPending();' in maintenance)
check('B progress cannot signal completion until the actual O transfer is acknowledged',
      start.index('TransferClient.CommitTransfer(') < start.index('FOverlayStarted := True;') < start.index('Progress(100)')
      and 'MaintainParent, Progress);' in start)
readiness=api.split('function TGameApi.GetModuleInventoryReadyCore: Boolean;',1)[1].split('function TGameApi.GetOverlayTransferredCore:',1)[0]
check('A fresh completed snapshot allows queued redemption even when the next scan is already due',
      'FModuleSnapshotCompleted and (FModuleSnapshot = nil)' in readiness
      and 'FModuleDeadlineTick - At > ModuleSnapshotCheckpointReserve' in readiness
      and 'FNextModules' not in readiness)
check('Packing retains every row while respecting both payload and escaped signed-envelope byte limits',
      'MaximumBatchRows = 16;' in module_inventory
      and 'ModuleReportPayloadMaximum = 24576;' in module_inventory
      and 'Payload := CreateModulePayload(255, 256);' in modules
      and 'FModuleBatchSize := ModuleInventoryBatchSize(Payload.ToJSON,' in modules
      and 'TJSONArray(Modules), IntegritySubmitOverheadBytes);' in modules
      and 'Int64(LargestRowBytes + 1) * Result > ModuleReportPayloadMaximum' in module_inventory
      and 'Int64(LargestEncodedRowBytes + 1) * Result > ProtocolRequestMaximumBytes' in module_inventory
      and 'FModuleBatchCount := (Total + FModuleBatchSize - 1) div FModuleBatchSize;' in modules
      and 'Batch.AddElement(TJSONValue(TJSONArray(Modules).Items[FModuleNextIndex].Clone));' in modules
      and 'Inc(FModuleNextIndex);' in modules
      and 'TEncoding.UTF8.GetByteCount(Text) > ModuleReportPayloadMaximum' in send)
print(f'License-success source contracts: {count} passed. Static checks only; no Windows deletion or rendering test.')
