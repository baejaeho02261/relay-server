unit Cozy.NHW.AsyncNative;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows;

// Win32 calls are resolved at runtime through the existing NHW.WinPointers
// bootstrap. The actual call sites use typed function pointers only.
procedure ResolveAsyncNative;
function AsyncPortAvailable: Boolean;
function AsyncPoolAvailable: Boolean;
function NewCompletionPort: THandle;
function PostCompletionPacket(Port: THandle; Bytes: Cardinal;
  Key: NativeUInt): Boolean;
function PollCompletionPacket(Port: THandle; out Bytes: Cardinal;
  out Key: NativeUInt; out Overlapped: Pointer): Boolean;
function NewPoolWork(Callback, Context: Pointer): Pointer;
procedure PostPoolWork(Work: Pointer);
procedure StopPoolWork(Work: Pointer);
function NewPoolTimer(Callback, Context: Pointer): Pointer;
procedure StartPoolTimer(Timer: Pointer);
procedure StopPoolTimer(Timer: Pointer);

{$IFDEF NHW_NATIVE5B_TESTS}
function TestAsyncNativeHardening(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  System.SysUtils,
  System.SyncObjs,
  Cozy.NHW.WinPointers;

type
  TCreatePort = function(FileHandle, ExistingPort: THandle;
    Key: NativeUInt; Concurrency: Cardinal): THandle; stdcall;
  TPostCompletion = function(Port: THandle; Bytes: Cardinal;
    Key: NativeUInt; Overlapped: Pointer): BOOL; stdcall;
  TGetCompletion = function(Port: THandle; out Bytes: Cardinal;
    out Key: NativeUInt; out Overlapped: Pointer;
    Timeout: Cardinal): BOOL; stdcall;
  TCreatePoolWork = function(Callback, Context, Environment: Pointer): Pointer; stdcall;
  TSubmitPoolWork = procedure(Work: Pointer); stdcall;
  TWaitPoolWork = procedure(Work: Pointer; CancelPending: BOOL); stdcall;
  TClosePoolWork = procedure(Work: Pointer); stdcall;
  TCreatePoolTimer = function(Callback, Context, Environment: Pointer): Pointer; stdcall;
  TSetPoolTimer = procedure(Timer, DueTime: Pointer;
    PeriodMS, WindowMS: Cardinal); stdcall;
  TWaitPoolTimer = procedure(Timer: Pointer; CancelPending: BOOL); stdcall;
  TClosePoolTimer = procedure(Timer: Pointer); stdcall;

var
  AsyncResolveLock: TCriticalSection;
  AsyncResolved: Integer = 0;
  CreatePortPtr: TCreatePort = nil;
  PostPtr: TPostCompletion = nil;
  GetPtr: TGetCompletion = nil;
  CreateWorkPtr: TCreatePoolWork = nil;
  SubmitWorkPtr: TSubmitPoolWork = nil;
  WaitWorkPtr: TWaitPoolWork = nil;
  CloseWorkPtr: TClosePoolWork = nil;
  CreateTimerPtr: TCreatePoolTimer = nil;
  SetTimerPtr: TSetPoolTimer = nil;
  WaitTimerPtr: TWaitPoolTimer = nil;
  CloseTimerPtr: TClosePoolTimer = nil;

procedure ResolveAsyncNative;
var
  ModKernel: HMODULE;

  procedure ResolvePortAPIs;
  begin
    CreatePortPtr := TCreatePort(WinExport(ModKernel, 'CreateIoCompletionPort'));
    PostPtr := TPostCompletion(WinExport(ModKernel, 'PostQueuedCompletionStatus'));
    GetPtr := TGetCompletion(WinExport(ModKernel, 'GetQueuedCompletionStatus'));
  end;

  procedure ResolveWorkAPIs;
  begin
    CreateWorkPtr := TCreatePoolWork(WinExport(ModKernel, 'CreateThreadpoolWork'));
    SubmitWorkPtr := TSubmitPoolWork(WinExport(ModKernel, 'SubmitThreadpoolWork'));
    WaitWorkPtr := TWaitPoolWork(WinExport(ModKernel, 'WaitForThreadpoolWorkCallbacks'));
    CloseWorkPtr := TClosePoolWork(WinExport(ModKernel, 'CloseThreadpoolWork'));
  end;

  procedure ResolveTimerAPIs;
  begin
    CreateTimerPtr := TCreatePoolTimer(WinExport(ModKernel, 'CreateThreadpoolTimer'));
    SetTimerPtr := TSetPoolTimer(WinExport(ModKernel, 'SetThreadpoolTimer'));
    WaitTimerPtr := TWaitPoolTimer(WinExport(ModKernel, 'WaitForThreadpoolTimerCallbacks'));
    CloseTimerPtr := TClosePoolTimer(WinExport(ModKernel, 'CloseThreadpoolTimer'));
  end;
begin
  if TInterlocked.CompareExchange(AsyncResolved, 0, 0) <> 0 then Exit;
  AsyncResolveLock.Acquire;
  try
    if AsyncResolved <> 0 then Exit;
    ModKernel := WinModule('kernel32.dll');
    if ModKernel = 0 then Exit; // Retry after the common bootstrap is ready.
    ResolvePortAPIs;
    ResolveWorkAPIs;
    ResolveTimerAPIs;
    // The table is immutable after publication; absent exports mean unsupported.
    TInterlocked.Exchange(AsyncResolved, 1);
  finally
    AsyncResolveLock.Release;
  end;
end;

function AsyncPortAvailable: Boolean;
begin
  ResolveAsyncNative;
  Result := Assigned(CreatePortPtr) and Assigned(PostPtr) and Assigned(GetPtr);
end;

function AsyncPoolAvailable: Boolean;
begin
  ResolveAsyncNative;
  Result := Assigned(CreateWorkPtr) and Assigned(SubmitWorkPtr) and
    Assigned(WaitWorkPtr) and Assigned(CloseWorkPtr) and
    Assigned(CreateTimerPtr) and Assigned(SetTimerPtr) and
    Assigned(WaitTimerPtr) and Assigned(CloseTimerPtr);
end;

function NewCompletionPort: THandle;
begin
  Result := 0;
  if AsyncPortAvailable then
    Result := CreatePortPtr(INVALID_HANDLE_VALUE, 0, 0, 1);
end;

function PostCompletionPacket(Port: THandle; Bytes: Cardinal;
  Key: NativeUInt): Boolean;
begin
  Result := False;
  if (Port = 0) or (Port = INVALID_HANDLE_VALUE) then Exit;
  ResolveAsyncNative;
  if Assigned(PostPtr) then Result := PostPtr(Port, Bytes, Key, nil);
end;

function PollCompletionPacket(Port: THandle; out Bytes: Cardinal;
  out Key: NativeUInt; out Overlapped: Pointer): Boolean;
var
  PacketBytes: Cardinal;
  PacketKey: NativeUInt;
  PacketOverlapped: Pointer;

  procedure PublishDequeuedPacket;
  begin
    Bytes := PacketBytes;
    Key := PacketKey;
    Overlapped := PacketOverlapped;
  end;
begin
  Bytes := 0;
  Key := 0;
  Overlapped := nil;
  Result := False;
  if (Port = 0) or (Port = INVALID_HANDLE_VALUE) then Exit;
  ResolveAsyncNative;
  if not Assigned(GetPtr) then Exit;
  PacketBytes := 0;
  PacketKey := 0;
  PacketOverlapped := nil;
  Result := GetPtr(Port, PacketBytes, PacketKey, PacketOverlapped, 0);
  // FALSE + nil OVERLAPPED dequeues nothing: bytes/key are undefined.
  // FALSE + non-nil OVERLAPPED is a real failed-I/O packet: preserve it.
  if Result or (PacketOverlapped <> nil) then PublishDequeuedPacket;
  // No OS call here: preserve GetQueuedCompletionStatus's last error.
end;

function NewPoolWork(Callback, Context: Pointer): Pointer;
begin
  Result := nil;
  if (Callback <> nil) and AsyncPoolAvailable then
    Result := CreateWorkPtr(Callback, Context, nil);
end;

procedure PostPoolWork(Work: Pointer);
begin
  if Assigned(SubmitWorkPtr) and (Work <> nil) then
    SubmitWorkPtr(Work);
end;

procedure StopPoolWork(Work: Pointer);
begin
  if Work = nil then Exit;
  ResolveAsyncNative;
  if not Assigned(WaitWorkPtr) or not Assigned(CloseWorkPtr) then Exit;
  // The owner must stop submissions first. Never invoke this from the same
  // object's callback or while holding a lock that the callback needs.
  WaitWorkPtr(Work, True);
  CloseWorkPtr(Work);
end;

function NewPoolTimer(Callback, Context: Pointer): Pointer;
begin
  Result := nil;
  if (Callback <> nil) and AsyncPoolAvailable then
    Result := CreateTimerPtr(Callback, Context, nil);
end;

procedure StartPoolTimer(Timer: Pointer);
var
  DueTime: Int64;
begin
  if (Timer = nil) or not Assigned(SetTimerPtr) then Exit;
  // Relative FILETIME in signed 100ns units: first tick after one second.
  DueTime := -Int64(10000000);
  SetTimerPtr(Timer, @DueTime, 2000, 0);
end;

procedure StopPoolTimer(Timer: Pointer);
begin
  if Timer = nil then Exit;
  ResolveAsyncNative;
  if not Assigned(SetTimerPtr) or not Assigned(WaitTimerPtr) or
     not Assigned(CloseTimerPtr) then Exit;
  // No resolver lock is held while joining callbacks. The owner serializes
  // arm/stop, and must not free the callback context before this returns.
  SetTimerPtr(Timer, nil, 0, 0);
  WaitTimerPtr(Timer, True);
  CloseTimerPtr(Timer);
end;

{$IFDEF NHW_NATIVE5B_TESTS}
  {$I Cozy.NHW.Native5B.Async.inc}
{$ENDIF}
initialization
  AsyncResolveLock := TCriticalSection.Create;
finalization
  // The engine must have joined workers before Delphi unit finalization.
  AsyncResolveLock.Free;
end.
