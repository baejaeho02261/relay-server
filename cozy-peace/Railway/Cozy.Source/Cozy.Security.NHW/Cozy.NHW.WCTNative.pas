unit Cozy.NHW.WCTNative;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows, System.SysUtils;

const
  WCT_MAX_NODE_COUNT = 16;
  WCT_OUT_OF_PROC_FLAG = 1;
  WCT_OUT_OF_PROC_CS_FLAG = 4;
  WCT_OBJECT_CRITICAL_SECTION = 1;
  WCT_OBJECT_MUTEX = 3;
  WCT_OBJECT_THREAD = 8;
  WCT_STATUS_NO_ACCESS = 1;
  WCT_STATUS_BLOCKED = 3;
  WCT_STATUS_ERROR = 10;

  // WCT is a native Windows service exposed through Advapi32. It does NOT
  // reveal the underlying function call that caused the wait.
type
  PWindowsBool = ^BOOL;
  PWaitChainNode = ^TWaitChainNode;
  TWaitChainNode = record
    ObjectType: Cardinal;
    ObjectStatus: Cardinal;
    Payload: array[0..271] of Byte; // union: LockObject/ThreadObject
  end;
  TWaitThreadNode = record
    ProcessId: Cardinal;
    ThreadId: Cardinal;
    WaitTime: Cardinal;
    ContextSwitches: Cardinal;
  end;
  PWaitThreadNode = ^TWaitThreadNode;

  TWCTCallback = procedure(Session: THandle; Context: NativeUInt;
    CallbackStatus: Cardinal; NodeCount: PCardinal;
    Nodes: PWaitChainNode; IsCycle: PWindowsBool); stdcall;

function WCTAvailable: Boolean;
function WCTOpen(Callback: TWCTCallback): THandle;
function WCTGet(Session: THandle; Context: NativeUInt; Flags, ThreadId: Cardinal;
  Count: PCardinal; Nodes: PWaitChainNode; Cycle: PWindowsBool): BOOL;
procedure WCTClose(Session: THandle);

{$IFDEF NHW_NATIVE5_TESTS}
function TestWCTNativeHardening(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  System.SyncObjs,
  Cozy.NHW.WinPointers,
  Cozy.NHW.NativeSafety;

type
  TOpenWCT = function(Flags: Cardinal; Callback: TWCTCallback): THandle; stdcall;
  TGetWCT = function(Session: THandle; Context: NativeUInt;
    Flags, ThreadId: Cardinal; Count: PCardinal;
    Nodes: PWaitChainNode; Cycle: PWindowsBool): BOOL; stdcall;
  TCloseWCT = procedure(Session: THandle); stdcall;
  TSetWCTError = procedure(Value: Cardinal); stdcall;
  TWCTAPI = record
    OpenSession: TOpenWCT;
    GetChain: TGetWCT;
    CloseSession: TCloseWCT;
    SetError: TSetWCTError;
  end;

var
  WCTLock: TCriticalSection;
  APIs: TWCTAPI;
  WCTModule: HMODULE;

procedure ResolveWCTSessionPointers;
begin
  if WCTModule = 0 then
  begin
    // Keep one owned reference for the lifetime of asynchronous sessions.
    WCTModule := WinLoadLibrary('advapi32.dll');
  end;
  if WCTModule = 0 then Exit;
  APIs.OpenSession := TOpenWCT(WinExport(WCTModule, 'OpenThreadWaitChainSession'));
  APIs.GetChain := TGetWCT(WinExport(WCTModule, 'GetThreadWaitChain'));
  APIs.CloseSession := TCloseWCT(WinExport(WCTModule, 'CloseThreadWaitChainSession'));
end;

procedure ResolveWCTErrorPointer;
var
  K: HMODULE;
begin
  K := WinModule('kernel32.dll');
  APIs.SetError := TSetWCTError(WinExport(K, 'SetLastError'));
end;

function WCTFunctionTableComplete: Boolean;
begin
  Result := Assigned(APIs.OpenSession) and Assigned(APIs.GetChain) and
    Assigned(APIs.CloseSession) and Assigned(APIs.SetError);
end;

procedure WCTAPI(out A: TWCTAPI);
begin
  WCTLock.Acquire;
  try
    if not WCTFunctionTableComplete then
    begin
      ResolveWCTSessionPointers;
      ResolveWCTErrorPointer;
    end;
    A := APIs;
  finally
    WCTLock.Release;
  end;
end;

function WCTReady(const A: TWCTAPI): Boolean;
begin
  Result := Assigned(A.OpenSession) and Assigned(A.GetChain) and
    Assigned(A.CloseSession) and (SizeOf(TWaitChainNode) = 280) and
    (SizeOf(TWaitThreadNode) = 16);
end;

procedure WCTError(const A: TWCTAPI; ErrorCode: Cardinal);
begin
  if Assigned(A.SetError) then A.SetError(ErrorCode);
end;

function WCTAvailable: Boolean;
var A: TWCTAPI;
begin
  WCTAPI(A);
  Result := WCTReady(A);
end;

function WCTOpen(Callback: TWCTCallback): THandle;
var A: TWCTAPI;
begin
  Result := 0;
  WCTAPI(A);
  if not WCTReady(A) then
  begin
    WCTError(A, ERROR_NOT_SUPPORTED);
    Exit;
  end;
  if not Assigned(Callback) then
  begin
    WCTError(A, ERROR_INVALID_PARAMETER);
    Exit;
  end;
  Result := A.OpenSession(1, Callback); // async only; never silently block
end;

function WCTRequestValid(Session: THandle; Flags, ThreadId: Cardinal;
  Count: PCardinal; Nodes: PWaitChainNode; Cycle: PWindowsBool): Boolean;
begin
  Result := False;
  if (Session = 0) or (NativeUInt(Session) > NativeUInt(High(NativeInt))) or
     (ThreadId = 0) or ((Flags and not Cardinal($7)) <> 0) then Exit;
  if not NHWAddressSpan(NativeUInt(Count), SizeOf(Cardinal)) or
     not NHWAddressSpan(NativeUInt(Cycle), SizeOf(BOOL)) then Exit;
  if (Count^ = 0) or (Count^ > WCT_MAX_NODE_COUNT) then Exit;
  Result := NHWAddressSpan(NativeUInt(Nodes),
    NativeUInt(Count^) * SizeOf(TWaitChainNode));
end;


function ValidateWCTResult(const A: TWCTAPI; Capacity: Cardinal;
  Count: PCardinal): Boolean;
begin
  Result := (Count^ <> 0) and (Count^ <= Capacity);
  if not Result then WCTError(A, ERROR_INVALID_DATA);
end;

function WCTGet(Session: THandle; Context: NativeUInt; Flags, ThreadId: Cardinal;
  Count: PCardinal; Nodes: PWaitChainNode; Cycle: PWindowsBool): BOOL;
var
  A: TWCTAPI;
  Capacity: Cardinal;
begin
  Result := False;
  WCTAPI(A);
  if not WCTReady(A) then
  begin
    WCTError(A, ERROR_NOT_SUPPORTED);
    Exit;
  end;
  if not WCTRequestValid(Session, Flags, ThreadId, Count, Nodes, Cycle) then
  begin
    WCTError(A, ERROR_INVALID_PARAMETER);
    Exit;
  end;
  Capacity := Count^;
  Result := A.GetChain(Session, Context, Flags, ThreadId, Count, Nodes, Cycle);
  // On ERROR_IO_PENDING all caller-owned buffers remain alive and untouched.
  // No cleanup/API call here may overwrite the native GetLastError result.
  if not Result then Exit;
  Result := ValidateWCTResult(A, Capacity, Count);
end;

procedure WCTClose(Session: THandle);
var A: TWCTAPI;
begin
  if (Session = 0) or (NativeUInt(Session) > NativeUInt(High(NativeInt))) then Exit;
  WCTAPI(A);
  // Do not hold WCTLock while Windows drains/cancels callbacks. The owner
  // (NHW.WaitChain) must stop submissions, then close, then release requests.
  // Do not call Close from the session's own callback.
  if Assigned(A.CloseSession) then A.CloseSession(Session);
end;

{$IFDEF NHW_NATIVE5_TESTS}
  {$I Cozy.NHW.Native5.WCT.inc}
{$ENDIF}
initialization
  WCTLock := TCriticalSection.Create;
finalization
  WCTLock.Free;
end.
