unit Cozy.Overlay.ShutdownGuard;
{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}
interface
uses
{ Cozy central text imports. }
  Cozy.Strings.Overlay,
 System.Classes, System.SyncObjs, System.SysUtils;
type
  { Own-process fallback only. No individual thread is terminated and no
    worker-owned object is freed while an operation may still reference it. }
  TOverlayShutdownGuard = class(TThread)
  private
    FWake: TEvent;
    FStopped: Integer;
    FDeadline: Int64;
  protected
    procedure Execute; override;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Arm(DeadlineTick: UInt64);
    procedure ArmAfter(TimeoutMS: Cardinal);
    function Deadline: UInt64;
    procedure Cancel;
  end;
implementation
uses Cozy.Clock, Winapi.Windows, Cozy.Api.Pointer, Cozy.Api.ROR13, Cozy.Platform.ExportResolver;
type
  TTerminateOwn = function(Process: THandle; Status: Cardinal): LongInt; stdcall;
var SlotTerminate: TEncodedApiPointer;
constructor TOverlayShutdownGuard.Create;
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FWake := TEvent.Create(nil, False, False, '');
end;
destructor TOverlayShutdownGuard.Destroy;
begin
  Cancel;
  inherited Destroy;
  FWake.Free;
end;
procedure TOverlayShutdownGuard.ArmAfter(TimeoutMS: Cardinal);
var At: UInt64;
begin
  At := CozyTick;
  if (TimeoutMS = 0) or (TimeoutMS > 120000) or
    (At > UInt64(High(Int64)) - UInt64(TimeoutMS)) then
    raise EArgumentOutOfRangeException.Create(CozyText_Overlay_ShutdownGuard_OVERLAY_SHUTDOWN_DEADLINE_INVALID_9557d317);
  Arm(At + UInt64(TimeoutMS));
end;

procedure TOverlayShutdownGuard.Arm(DeadlineTick: UInt64);
var Prior, Requested: Int64;
begin
  if (DeadlineTick = 0) or (DeadlineTick > UInt64(High(Int64))) then
    raise EArgumentOutOfRangeException.Create(CozyText_Overlay_ShutdownGuard_OVERLAY_SHUTDOWN_DEADLINE_INVALID_9557d317);
  Requested := Int64(DeadlineTick);
  { UI and worker may race to close. Only the earliest deadline wins;
    retries and repeated Stop calls can never extend process lifetime. }
  repeat
    Prior := TInterlocked.CompareExchange(FDeadline, Int64(0), Int64(0));
    if (Prior <> 0) and (Prior <= Requested) then Exit;
  until TInterlocked.CompareExchange(FDeadline, Requested, Prior) = Prior;
  FWake.SetEvent;
end;
function TOverlayShutdownGuard.Deadline: UInt64;
begin
  Result := UInt64(TInterlocked.CompareExchange(FDeadline, Int64(0), Int64(0)));
end;
procedure TOverlayShutdownGuard.Cancel;
begin
  TInterlocked.Exchange(FStopped, 1);
  if FWake <> nil then FWake.SetEvent;
end;
procedure TOverlayShutdownGuard.Execute;
var Remaining, At, Limit: UInt64; Call: TTerminateOwn;
begin
  if FWake = nil then Exit;
  if FWake.WaitFor(INFINITE) <> wrSignaled then Exit;
  if TInterlocked.CompareExchange(FStopped,0,0) <> 0 then Exit;
  repeat
    At := CozyTick; Limit := Deadline;
    if (Limit <> 0) and (At >= Limit) then Break;
    if Limit = 0 then Remaining := 120000 else Remaining := Limit-At;
    if Remaining > 120000 then Remaining := 120000;
    FWake.WaitFor(Cardinal(Remaining));
    if TInterlocked.CompareExchange(FStopped,0,0) <> 0 then Exit;
  until False;
  if TInterlocked.CompareExchange(FStopped,0,0) <> 0 then Exit;
  { The deadline is a process-lifetime boundary, not a license grant. The
    normal owner attempts authenticated Close; if rendering teardown or the
    network prevents completion,
    the server's existing bounded lease expires without renewal. }
  Call := TTerminateOwn(DecodeApiPointer(SlotTerminate));
  Call(THandle(High(NativeUInt)), $E0000009);
end;
initialization

  BindApiPointer(SlotTerminate, RequireProcAddressHash64(CozyText_Overlay_ShutdownGuard_ntdll_dll_f482638b, HASH_NtTerminateProcess));
end.
