unit Cozy.Lifetime;

{$IFDEF FPC}{$MODE DELPHI}{$ENDIF}
{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}

interface

uses
{ Cozy central text imports. }
  Cozy.Strings.Lifecycle,

  {$IFDEF FPC}SysUtils{$ELSE}System.SysUtils, System.SyncObjs{$ENDIF};

type
  { One atomic word: sign bit closes admission, remaining bits count callers.
    Initialize only before publication. The native gate and portable tests use
    these same transitions, not a second behavioral model. }
  TGameCallState = record
  private
    FState: Integer;
  public
    procedure Initialize;
    function TryEnter: Boolean;
    function Leave: Boolean;
    function Close: Boolean;
    function IsClosing: Boolean;
    function ActiveCount: Integer;
  end;

  { Object-reference lifetime remains the owner's responsibility. Stop exposing
    the object to new threads before Free. Existing admitted operations drain
    before the owning object's keys/buffers/locks are released. Never call
    CloseAndWait from inside an admitted operation on this same gate. }
  TGameCallGate = class
  private
    FState: TGameCallState;
    {$IFDEF FPC}FEvent: PRTLEvent;{$ELSE}FEvent: NativeUInt;{$ENDIF}
    procedure SignalDrained;
  public
    constructor Create;
    destructor Destroy; override;
    function TryEnter: Boolean;
    procedure Enter;
    procedure Leave;
    procedure CloseAndWait;
    function IsClosing: Boolean;
    function ActiveCount: Integer;
  end;

implementation

{$IFNDEF FPC}
uses Winapi.Windows, Cozy.WinApi, Cozy.Api.Pointer,
  Cozy.Platform.ExportResolver, Cozy.Api.ROR13;
var
  ApiSlot_CreateEventW, ApiSlot_SetEvent, ApiSlot_WaitForSingleObject,
    ApiSlot_CloseHandle: TEncodedApiPointer;
{$ENDIF}

function CompareExchange(var Target: Integer; Value, Comparand: Integer): Integer; inline;
begin
  {$IFDEF FPC}Result := InterlockedCompareExchange(Target, Value, Comparand);
  {$ELSE}Result := TInterlocked.CompareExchange(Target, Value, Comparand);{$ENDIF}
end;

procedure TGameCallState.Initialize;
begin
  FState := 0;
end;

function TGameCallState.TryEnter: Boolean;
var Current: Integer;
begin
  repeat
    Current := CompareExchange(FState, 0, 0);
    if (Current < 0) or (Current = High(Integer)) then Exit(False);
  until CompareExchange(FState, Current + 1, Current) = Current;
  Result := True;
end;

function TGameCallState.Leave: Boolean;
var Current, Next: Integer;
begin
  repeat
    Current := CompareExchange(FState, 0, 0);
    if (Current = 0) or (Current = Low(Integer)) then
      raise EInvalidOpException.Create(CozyText_Lifetime_CALL_GATE_UNBALANCED_LEAVE_c67373ac);
    Next := Current - 1;
  until CompareExchange(FState, Next, Current) = Current;
  Result := Next = Low(Integer);
end;

function TGameCallState.Close: Boolean;
var Current, Next: Integer;
begin
  repeat
    Current := CompareExchange(FState, 0, 0);
    if Current < 0 then Exit(False);
    Next := Current + Low(Integer);
  until CompareExchange(FState, Next, Current) = Current;
  Result := Next = Low(Integer);
end;

function TGameCallState.IsClosing: Boolean;
begin
  Result := CompareExchange(FState, 0, 0) < 0;
end;

function TGameCallState.ActiveCount: Integer;
begin
  Result := CompareExchange(FState, 0, 0) and High(Integer);
end;

constructor TGameCallGate.Create;
{$IFNDEF FPC}var ApiTarget: TApiCreateEventW;{$ENDIF}
begin
  inherited Create;
  FState.Initialize;
  {$IFDEF FPC}
  FEvent := RTLEventCreate;
  if FEvent = nil then raise EOutOfMemory.Create(CozyText_Lifetime_CALL_GATE_EVENT_FAILED_c43780f2);
  {$ELSE}
  ApiTarget := TApiCreateEventW(DecodeApiPointer(ApiSlot_CreateEventW));
  FEvent := ApiTarget(nil, True, False, nil);
  if FEvent = 0 then raise EInvalidOpException.Create(CozyText_Lifetime_CALL_GATE_EVENT_FAILED_c43780f2);
  {$ENDIF}
end;

procedure TGameCallGate.SignalDrained;
{$IFNDEF FPC}var ApiTarget: TApiSetEvent;{$ENDIF}
begin
  {$IFDEF FPC}RTLEventSetEvent(FEvent);
  {$ELSE}
  ApiTarget := TApiSetEvent(DecodeApiPointer(ApiSlot_SetEvent));
  if not ApiTarget(FEvent) then raise EInvalidOpException.Create(CozyText_Lifetime_CALL_GATE_SIGNAL_FAILED_be61fddb);
  {$ENDIF}
end;

function TGameCallGate.TryEnter: Boolean;
begin
  Result := FState.TryEnter;
end;

procedure TGameCallGate.Enter;
begin
  if not TryEnter then raise EInvalidOpException.Create(CozyText_Lifetime_OBJECT_CLOSING_f1014188);
end;

procedure TGameCallGate.Leave;
begin
  if FState.Leave then SignalDrained;
end;

procedure TGameCallGate.CloseAndWait;
{$IFNDEF FPC}var ApiTarget: TApiWaitForSingleObject;{$ENDIF}
begin
  {$IFDEF FPC}if FEvent = nil then Exit;{$ELSE}if FEvent = 0 then Exit;{$ENDIF}
  if FState.Close then SignalDrained;
  {$IFDEF FPC}
  RTLEventWaitFor(FEvent);
  { FPC RTL events auto-reset; keep completion observable for later joins. }
  RTLEventSetEvent(FEvent);
  {$ELSE}
  ApiTarget := TApiWaitForSingleObject(DecodeApiPointer(ApiSlot_WaitForSingleObject));
  if ApiTarget(FEvent, INFINITE) <> WAIT_OBJECT_0 then
    raise EInvalidOpException.Create(CozyText_Lifetime_CALL_GATE_JOIN_FAILED_34d77ef6);
  {$ENDIF}
end;

function TGameCallGate.IsClosing: Boolean;
begin
  Result := FState.IsClosing;
end;

function TGameCallGate.ActiveCount: Integer;
begin
  Result := FState.ActiveCount;
end;

destructor TGameCallGate.Destroy;
{$IFNDEF FPC}var ApiTarget: TApiCloseHandle;{$ENDIF}
begin
  CloseAndWait;
  {$IFDEF FPC}
  if FEvent <> nil then RTLEventDestroy(FEvent);
  FEvent := nil;
  {$ELSE}
  if FEvent <> 0 then
  begin
    ApiTarget := TApiCloseHandle(DecodeApiPointer(ApiSlot_CloseHandle));
    ApiTarget(FEvent);
    FEvent := 0;
  end;
  {$ENDIF}
  inherited Destroy;
end;

{$IFNDEF FPC}
initialization
  BindApiPointer(ApiSlot_CreateEventW, RequireProcAddressHash64(CozyText_Lifetime_kernel32_dll_e230722c, HASH_CreateEventW));
  BindApiPointer(ApiSlot_SetEvent, RequireProcAddressHash64(CozyText_Lifetime_kernel32_dll_e230722c, HASH_SetEvent));
  BindApiPointer(ApiSlot_WaitForSingleObject, RequireProcAddressHash64(CozyText_Lifetime_kernel32_dll_e230722c, HASH_WaitForSingleObject));
  BindApiPointer(ApiSlot_CloseHandle, RequireProcAddressHash64(CozyText_Lifetime_kernel32_dll_e230722c, HASH_CloseHandle));
{$ENDIF}
end.
