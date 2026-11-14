program CozyNHW_Hardened4_Tests;

{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Build this test project with Delphi Win64.'}
{$ENDIF}
{$IFNDEF NHW_HARDENING_TESTS}
  {$MESSAGE FATAL 'Open Cozy.NHW.Hardened4.Tests.dproj; it defines NHW_HARDENING_TESTS for every unit.'}
{$ENDIF}

uses
  Winapi.Windows,
  System.SysUtils,
  Cozy.NHW.Types in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Types.pas',
  Cozy.NHW.NativeSafety in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.NativeSafety.pas',
  Cozy.NHW.WinPointers in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.WinPointers.pas',
  Cozy.NHW.Native in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Native.pas',
  Cozy.NHW.IPCNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.IPCNative.pas',
  Cozy.NHW.Handles in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Handles.pas',
  Cozy.NHW.Process in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Process.pas',
  Cozy.NHW.RegistryNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.RegistryNative.pas',
  Cozy.NHW.ThreadOriginNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ThreadOriginNative.pas';

type
  TCheckGroup = function(out Failure: string; out Checks: Integer): Boolean;

var
  Total: Integer;

procedure RunGroup(const Name: string; Group: TCheckGroup);
var
  Failure: string;
  Checks: Integer;
begin
  if not Group(Failure, Checks) then
    raise Exception.Create(Name + ': ' + Failure);
  Inc(Total, Checks);
end;

procedure LiveReadOnlySmoke;
var
  H: TTargetHolder;
  PID: Cardinal;
  Count: Integer;
  Why, Root: string;
  Key, Ev: THandle;
  Address: NativeUInt;
  Region: TThreadOriginRegion;
begin
  // First try before bootstrap. The lazy resolvers must remain retryable.
  if RegistryNativeAvailable or ThreadOriginNativeAvailable then
    raise Exception.Create('Unexpected resolver bootstrap state.');
  ResolveWinPointers;
  ResolveNativeAPIs;
  if not RegistryNativeAvailable or not ThreadOriginNativeAvailable then
    raise Exception.Create('Required NT metadata APIs unavailable.');
  H := Default(TTargetHolder);
  H.PID := WinCurrentProcessId;
  QueryOwnerInfo(H);
  if (H.CreateTime = 0) or (H.ImagePath = '<path unavailable>') then
    raise Exception.Create('Self process metadata query failed.');
  if not FindTargetByName(ExtractFileName(ParamStr(0)), PID, Count, Why) then
    raise Exception.Create('Process list: ' + Why);
  if (PID = 0) or (Count = 0) then
    raise Exception.Create('Self image not found in process enumeration.');
  Root := NativeCurrentUserRegistryRoot;
  if Root = '' then raise Exception.Create('Token SID/root query failed.');
  Key := NativeOpenRegistryKey(Root);
  if Key = 0 then raise Exception.Create('Read-only current-user key unavailable.');
  try
    Ev := NativeCreateRegistryEvent;
    if Ev = 0 then raise Exception.Create('Registry event creation failed.');
    try
      if NativePollRegistryEvent(Ev) then
        raise Exception.Create('New registry event should not be signaled.');
    finally
      NativeCloseRegistry(Ev);
    end;
    if Ev <> 0 then raise Exception.Create('Event close failed.');
  finally
    NativeCloseRegistry(Key);
  end;
  if Key <> 0 then raise Exception.Create('Registry key close failed.');
  NativeCloseRegistry(Key); // idempotent zero-handle cleanup
  // -2 is the documented current-thread pseudo handle; never sent to NtClose.
  if not QueryWin32ThreadStart(THandle(High(NativeUInt) - NativeUInt(1)), Address) then
    raise Exception.Create('Thread start query failed.');
  if not QueryThreadStartRegion(WinCurrentProcess, Address, Region) or not Region.Known then
    raise Exception.Create('Thread start mapping query failed.');
  Writeln('PASS: read-only Windows smoke checks');
end;

begin
  Total := 0;
  try
    RunGroup('NHW.Handles', TestHandleHardening);
    RunGroup('NHW.Process', TestProcessHardening);
    RunGroup('NHW.RegistryNative', TestRegistryHardening);
    RunGroup('NHW.ThreadOriginNative', TestThreadOriginHardening);
    Writeln('PASS: hardened four-unit assertions=', Total);
    if (ParamCount > 0) and SameText(ParamStr(1), '--live') then
      LiveReadOnlySmoke
    else
      Writeln('Windows smoke not requested; --live enables read-only live checks.');
  except
    on E: Exception do
    begin
      Writeln('FAIL: ', E.Message);
      ExitCode := 1;
    end;
  end;
end.
