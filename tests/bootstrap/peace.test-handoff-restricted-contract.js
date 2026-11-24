'use strict';
// Semantic native literals resolve from the current separate constant units.
const {ReadContractFile}=require("../fixtures/source/peace.native-string-contract");
// Reviewable source-boundary checks, not a substitute for the actual Windows
// process/token/ACL/CNG contracts in Cozy.HandoffProcessProbe.dproj.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '../../../Railway');
const read = name => ReadContractFile(path.join(root, name), 'utf8').replaceAll('\r', '');
const restricted = read('Cozy.Source/Cozy.Handoff/Cozy.Handoff.Restricted.pas');
const handoff = read('Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas');
const overlay = read('Cozy.Source/Cozy.Overlay/Cozy.Overlay.Client.pas');
const api = read('Cozy.Source/Cozy.Platform/Cozy.Api.pas');
const probe = read('Cozy.Tests/Cozy.Handoff/Cozy.HandoffProcessContracts.inc');
const body = (text, first, last) => {
  const a = text.indexOf(first, text.indexOf('implementation'));
  assert.ok(a >= 0, first);
  const b = text.indexOf(last, a + first.length);
  assert.ok(b > a, last);
  return text.slice(a, b);
};
const order = (text, list) => {
  let last = -1;
  for (const needle of list) {
    const at = text.indexOf(needle, last + 1);
    assert.ok(at > last, needle);
    last = at;
  }
};
let checks = 0;
function check(name, run) { run(); checks++; console.log(`PASS ${name}`); }

check('restricted token handle retains the rights required by both subsequent Windows APIs', () => {
  const token = body(restricted, 'function CreateOverlayRestrictedToken: THandle;', 'procedure RequireOverlayRestrictedProcess(');
  const access = token.match(/SlotOpenToken\)\)\(\s*THandle\(NativeInt\(-1\)\),\s*([\s\S]*?),\s*Original\)/);
  assert.ok(access);
  let flags = 0;
  for (const name of access[1].split(/\s+or\s+/)) {
    const value = restricted.match(new RegExp(`${name.trim()} = \\$([0-9A-F]+);`));
    assert.ok(value, name);
    flags |= parseInt(value[1], 16);
  }
  // QUERY | DUPLICATE | ASSIGN_PRIMARY | ADJUST_DEFAULT. CreateRestrictedToken
  // returns a handle with the original handle's access rights.
  assert.equal(flags, 0x008b);
  order(token, ['SlotOpenToken', 'RequireInteractiveUser(Original)', 'SlotCreateRestricted',
    'DisableMaximumPrivileges or LuaToken', 'SlotSetToken', 'RequireRestrictedToken(Result)']);
  assert.match(token, /except\s+CloseToken\(Result\);\s+raise;/);
});

check('actual child token is checked while suspended and before any grant is released', () => {
  const launch = body(restricted, 'procedure CreateOverlayRestrictedProcess(', '\ninitialization');
  order(launch, ['Token := CreateOverlayRestrictedToken', 'SlotCreateProcess', 'CREATE_SUSPENDED',
    'RequireOverlayRestrictedProcess(Process.hProcess)', 'procedure ResumeHandoffChild(Thread: THandle; NativeError: PCardinal);', 'SlotResume']);
  assert.match(launch, /PreviousCount := TResumeThreadProc\(DecodeApiPointer\(SlotResume\)\)\(Thread\)/);
  assert.match(launch, /Require\(PreviousCount = 1,/);
  assert.match(launch, /if \(PreviousCount = DWORD\(-1\)\) and \(NativeError <> nil\) then\s+NativeError\^ := TGetLastErrorProc/);
  assert.doesNotMatch(launch, /CreateProcessW|CreateProcessWithLogon|ShellExecute|except/);
  const actual = body(handoff, 'function LaunchWithHandoff(', '\nconstructor THandoffContext.Create;');
  order(actual, ['HANDOFF_RESTRICTED_PROFILE_O_ONLY', 'if LaunchProfile = hlpOverlayRestricted then',
    'CreateOverlayRestrictedProcess(', 'CREATE_SUSPENDED', 'Check(NativeResult(DuplicateHandle(GetCurrentProcess, Process.hProcess',
    'Check(NativeResult(CloseHandle(Process.hProcess)', 'Process.hProcess := ChildWaitHandle;', 'ResumeHandoffChild(Process.hThread, @FailureError);',
    'Hello := ReadHello(', 'RequireOverlayRestrictedProcess(Process.hProcess)',
    'Payload := BuildPayload(', 'WaitHandoffReadiness(', 'RequireOverlayRestrictedProcess(Process.hProcess)', 'Result := True']);
  assert.match(actual, /@ChildWaitHandle, SYNCHRONIZE or ProcessQueryLimitedInformation or PROCESS_TERMINATE,\s*False, 0\)/);
  assert.match(actual, /if not Result and \(Process.hProcess <> 0\) then[\s\S]*?TerminateProcess\(Process.hProcess, 1\)/);
  const cleanup = actual.slice(actual.indexOf('if not Result and (Process.hProcess <> 0) then'));
  assert.match(cleanup, /WaitResult := WaitForSingleObject\(Process\.hProcess, 0\);\s+if WaitResult = WAIT_OBJECT_0 then\s+begin\s+Observation\.ExitCodeKnown := GetExitCodeProcess\(Process\.hProcess, Observation\.ExitCode\);[\s\S]*?end\s+else\s+begin\s+TerminateProcess\(Process\.hProcess, 1\)/);
  assert.doesNotMatch(cleanup.slice(cleanup.indexOf('TerminateProcess(Process.hProcess, 1)')), /GetExitCodeProcess/,
    'forced child cleanup must never be reported as the original child exit');
});

check('token readback rejects elevation, service accounts, operator groups and remaining privileges', () => {
  assert.match(restricted, /TokenElevationKind = 20/);
  assert.match(restricted, /TokenIntegrityKind = 25/);
  assert.match(restricted, /DeniedBuiltinRIDs: array\[0\.\.6\] of DWORD = \(544, 547, 548, 549, 550, 551, 552\)/);
  for (const code of ['OVERLAY_SERVICE_ACCOUNT_FORBIDDEN', 'OVERLAY_INTERACTIVE_SESSION_REQUIRED',
    'OVERLAY_TOKEN_INTEGRITY_TOO_HIGH', 'OVERLAY_TOKEN_STILL_ELEVATED',
    'OVERLAY_TOKEN_PRIVILEGED_GROUP', 'OVERLAY_TOKEN_PRIVILEGES_REMAIN', 'OVERLAY_TOKEN_SID_RANGE']) {
    assert.ok(restricted.includes(code), code);
  }
  const query = body(restricted, 'function QueryToken(', 'function SidSizeInBuffer(');
  assert.match(query, /Required <= 65536/);
  assert.equal((query.match(/SetLength\(Result,/g) || []).length, 1,
    'absolute SID pointers must not be invalidated by a second resize');
});

check('public opt-in reaches the real O launch path and keeps the compatibility default', () => {
  assert.match(api, /function StartOverlay\(RestrictedPrivileges: Boolean = False;\s+const Progress: TProc<Integer> = nil;\s+const AwaitRelease: TOverlayReleaseGate = nil\): Boolean/);
  assert.match(api, /Result := StartOverlayCore\(RestrictedPrivileges, Progress, AwaitRelease\)/);
  assert.match(api, /FBoundImage.SHA512, FBootstrapSessionID, FailedChild, RestrictedPrivileges,\s+MaintainParent, Progress, PrepareGate\)/);
  assert.match(overlay, /if RestrictedPrivileges then LaunchProfile := hlpOverlayRestricted/);
  assert.match(overlay, /Flow.Release.SHA512, True,\s+LaunchProfile, WaitMaintenance,\s+procedure\(const Observation: THandoffCleanupObservation\)/);
  assert.match(api, /RestrictedPrivileges <> FOverlayRestrictedPrivileges/);
});

check('hidden O publishes bounded ready deadlines only to its gated parent', () => {
  const actual = body(handoff, 'function LaunchWithHandoff(', '\nconstructor THandoffContext.Create;');
  const payload = body(handoff, 'function BuildPayload(', 'procedure RequireReadyChild(');
  const writer = body(handoff, 'procedure THandoffContext.PublishReadyDeadlineCore(',
    'procedure THandoffContext.ConfirmOverlayReadyCore(');
  const confirm = body(handoff, 'procedure THandoffContext.ConfirmOverlayReadyCore(',
    'procedure THandoffContext.CleanupTransferredParentCore;');
  const poll = body(handoff, 'function PollReadyDeadline(', 'procedure WaitHandoffReadiness(');
  const validate = body(handoff, 'procedure ValidateReadyDeadline(', 'function PollReadyDeadline(');
  const receive = body(handoff, 'class function THandoffContext.ReceiveRole(', 'procedure THandoffContext.CompleteClaimAndCleanupCore(');
  assert.match(handoff, /HandoffReadyDeadlineFlag = \$100;\s+HandoffRollingReadyDeadlineFlag = \$200;/);
  assert.match(handoff, /ReadyDeadlineWindowMS = 30000;\s+ReadyDeadlineFrameLimit = 32;\s+ReadyDeadlinePipeBytes = 4096;/);
  order(receive, ['Cipher.Decrypt(Envelope, AAD,',
    'RollingReadyDeadline := OverlayRole and', 'or HandoffRollingReadyDeadlineFlag',
    'ReadyDeadlineExtension := RollingReadyDeadline or (OverlayRole and', 'or HandoffReadyDeadlineFlag',
    'Result.FRollingReadyDeadline := RollingReadyDeadline;', 'if ReadyDeadlineExtension then',
    'ValidateInherited(THandle(ReadyDeadlineHandle));', 'GetFileType(THandle(ReadyDeadlineHandle)) = FILE_TYPE_PIPE',
    'Result.FReadyDeadlinePipe := THandle(ReadyDeadlineHandle);']);
  order(payload, ['HandoffRoleName(Header.ComponentRole = 1)', 'if ReadyDeadlineHandle <> 0 then',
    'Header.ComponentRole := Header.ComponentRole or HandoffRollingReadyDeadlineFlag;',
    'Move(ReadyDeadlineHandle, Result[Offset], SizeOf(ReadyDeadlineHandle));']);
  order(actual, ['InheritedCount := 4;', 'if Assigned(AfterReady) then', 'Check(PreserveParent,',
    'CreatePipe(ReadyDeadlineRead, ReadyDeadlineWrite,', 'InheritedHandles[4] := ReadyDeadlineWrite;',
    'InheritedCount * SizeOf(THandle)', 'ChildKeyID, ChildNonce, UInt64(ReadyDeadlineWrite));',
    'Close(ReadyDeadlineWrite);', 'THandoffCipher.Encrypt(Wrapping, Payload, AAD,', 'WaitHandoffReadiness(',
    'if Deadline < ReadyReadDeadline then ReadyReadDeadline := Deadline;',
    'ReadExact(ReadyDeadlineRead, ReadyBytes, 0, Length(ReadyBytes),', 'RequireReadyChild(Process.hProcess,',
    'ValidateReadyDeadline(ChildCommitDeadline);', 'PollReadyDeadline(ReadyDeadlineRead,',
    'AfterReady(NativeUInt(Process.hProcess), ReadReadyDeadline);', 'Close(ReadyDeadlineRead);',
    'RequireReadyChild(Process.hProcess,', 'Result := True;']);
  assert.doesNotMatch(actual, /RequirePipeEnd\(ReadyDeadlineRead,/);
  order(confirm, ['ParentIsAliveCore', 'if FReadyDeadlinePipe <> 0 then',
    'PublishReadyDeadlineCore(CommitDeadline, False);',
    'if not FRollingReadyDeadline then Close(FReadyDeadlinePipe);', 'SetEvent(FReadyEvent)']);
  order(writer, ['CommitDeadline > At', 'CommitDeadline <= At + ReadyDeadlineWindowMS',
    'if CommitDeadline = FLastReadyDeadline then Exit;', 'FReadyDeadlineFrames < ReadyDeadlineFrameLimit',
    'WriteFile(FReadyDeadlinePipe, CommitDeadline, SizeOf(CommitDeadline),',
    'AllowReaderClosed and', 'ERROR_BROKEN_PIPE', 'Close(FReadyDeadlinePipe);',
    'Written = SizeOf(CommitDeadline)', 'Inc(FReadyDeadlineFrames);']);
  order(poll, ['RequireReadyChild(ChildProcess,', 'Result := Previous;',
    'for I := 1 to ReadyDeadlineFrameLimit do', 'PeekNamedPipe(Pipe,', 'if Available < SizeOf(Candidate) then Break;',
    'ReadFile(Pipe, Candidate, SizeOf(Candidate),', 'ReadCount = SizeOf(Candidate)', 'ValidateReadyDeadline(Candidate);',
    'Result := Candidate;', 'RequireReadyChild(ChildProcess,']);
  assert.match(validate, /Candidate > 0\) and \(Candidate <= CozyTick \+ ReadyDeadlineWindowMS\)/);
});

check('ready acceptance rechecks cancellation and process death and retains the original deadline', () => {
  const wait = body(handoff, 'procedure WaitHandoffReadiness(', 'function LaunchWithHandoff(');
  const pending = body(handoff, 'procedure RequireReadyChild(', 'procedure ValidateReadyDeadline(');
  order(pending, ['Status := WaitForSingleObject(CancelEvent, 0)', 'HANDOFF_CANCELLED',
    'Status := WaitForSingleObject(ChildProcess, 0)', 'HANDOFF_CHILD_EXITED']);
  assert.match(wait, /procedure RequirePending;\s*begin\s*RequireReadyChild\(ChildProcess, CancelEvent, NativeError\);/);
  order(wait.slice(wait.indexOf('repeat')), [
    'RequirePending;', "Check(Remaining(Deadline) > 0, 'HANDOFF_READY_TIMEOUT')",
    'WaitResult := WaitForSingleObject(ReadyEvent, 0)', 'if WaitResult = WAIT_OBJECT_0 then',
    'RequirePending;', "Check(Remaining(Deadline) > 0, 'HANDOFF_READY_TIMEOUT')", 'Exit;',
    'if Assigned(MaintainParent) then', 'MaintainParent();', 'RequirePending;',
    "Check(Remaining(Deadline) > 0, 'HANDOFF_READY_TIMEOUT')"]);
  order(wait.slice(wait.indexOf('WaitResult := WaitForMultipleObjects')), [
    'RequirePending;', "Check(Remaining(Deadline) > 0, 'HANDOFF_READY_TIMEOUT')",
    'if WaitResult = WAIT_OBJECT_0 + ReadyIndex then Exit']);
  assert.match(wait, /if Assigned\(MaintainParent\) and \(WaitMS > 1000\) then WaitMS := 1000/);
  assert.match(wait, /Check\(Assigned\(MaintainParent\), 'HANDOFF_READY_TIMEOUT'\)/);
  assert.doesNotMatch(wait, /Deadline :=|Inc\(Deadline/);
});

check('real Windows probe includes owned process, stale file identity and restricted-resource scenarios', () => {
  for (const code of ['PROBE_READY_CANCEL_ACCEPTED', 'PROBE_EXPIRED_READY_ACCEPTED',
    'PROBE_READY_DEAD_CHILD_ACCEPTED', 'PROBE_DEAD_PARENT_CONFIRM_ACCEPTED',
    'PROBE_PIN_ALLOWS_WRITE', 'PROBE_PIN_ALLOWS_REPLACE',
    'PROBE_REPLACEMENT_CLEANUP_ACCEPTED', 'PROBE_REPLACEMENT_OBSERVATION',
    'PROBE_RESTRICTED_ADMIN_WRITE_ALLOWED', 'PROBE_RESTRICTED_CNG_SIGN',
    'PROBE_RESTRICTED_CHILD_EXIT_CODE', 'PROBE_FIXTURE_DACL_RESTORE']) assert.ok(probe.includes(code), code);
  assert.match(probe, /Observation.ExitObserved and not Observation.CleanupAttempted and\s+not Observation.DispositionAccepted and not Observation.FileRemoved/);
  assert.doesNotMatch(probe, /OpenProcess\(/);
  const rolling = probe.slice(probe.indexOf('function RunHandoffReadyDeadlineContracts('),
    probe.indexOf('function RunHandoffReadinessAndIdentityContracts:'));
  order(rolling, ['Context.ConfirmOverlayReady(Initial);', 'Context.RefreshOverlayReady(Initial);',
    'Context.FReadyDeadlineFrames = 1', 'Context.RefreshOverlayReady(Later);',
    'Context.RefreshOverlayReady(Shorter);', 'SetEvent(CancelEvent)', 'PROBE_READY_CANCEL_ACCEPTED',
    'ResetEvent(CancelEvent)', 'Seen = Shorter', 'Close(Reader);',
    'Context.RefreshOverlayReady(Later);', 'not Context.RollingOverlayReady',
    'Context.FRollingReadyDeadline := False;', 'Context.ConfirmOverlayReady(Initial);',
    'RequirePipeEnd(Reader, CozyTick + 1000);',
    '(Seen = Initial) and (Context.FReadyDeadlinePipe = 0)']);
  assert.ok(probe.includes('Inc(Result, RunHandoffReadyDeadlineContracts(Child, CancelEvent));'));
});

console.log(`Handoff restricted-profile source contracts: ${checks} passed; Windows/Delphi/graphics/TPM/TLS runtime NOT_RUN.`);
