unit Cozy.Clock;
{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}
interface
uses
{ Cozy central text imports. }
  Cozy.Strings.Platform,
 System.SysUtils;
type
  TCozyClockRead = function: UInt64; stdcall;
{ One process-wide monotonic millisecond domain; includes system sleep.
  Not UTC, a server timestamp, an authorization decision, or GetTickCount. }
function CozyTick: UInt64; stdcall;
{ UI animation only. Never use floating seconds as a lease/security deadline. }
function CozyFrameSeconds: Double;
{ True = elapsed; False = cancellation observed. The callback is synchronous.
  Every wait is bounded and rechecks the total monotonic deadline on return. }
function CozyWaitForDelay(Milliseconds: Cardinal;
  const Cancelled: TFunc<Boolean> = nil): Boolean;
procedure CozyPause(Milliseconds: Cardinal);
{ Borrowed, never-signaled delay event. Do not signal or close this handle.
  Used only by the hash-worker join fallback with its pre-resolved wait target,
  so an exception cannot release memory while a worker might still use it. }
function CozyClockDelayHandle: NativeUInt;
implementation
uses Winapi.Windows, Cozy.Api.Pointer, Cozy.Platform.ExportResolver, Cozy.Clock.Math;
type
  TClockCounter = function(var Value: Int64): BOOL; stdcall;
  TClockCreateEvent = function(Attributes: PSecurityAttributes;
    ManualReset, InitialState: BOOL; Name: PWideChar): THandle; stdcall;
  TClockWait = function(Handle: THandle; Milliseconds: DWORD): DWORD; stdcall;
  TClockClose = function(Handle: THandle): BOOL; stdcall;
  TClockReadError = function: DWORD; stdcall;
  TClockWriteError = procedure(Value: DWORD); stdcall;
var
  ClockSlot_QueryPerformanceCounter, ClockSlot_QueryPerformanceFrequency,
    ClockSlot_CreateEventW, ClockSlot_WaitForSingleObject, ClockSlot_CloseHandle,
    ClockSlot_GetLastError, ClockSlot_SetLastError: TEncodedApiPointer;
  ClockFrequency: Int64;
  DelayEvent: THandle;
function RequireClockApi(Name: PAnsiChar): Pointer;
var Module: HMODULE;
begin
  { Named documented loader calls are initialization bootstrap exclusions.
    kernel32 is already loaded for process lifetime; its handle is borrowed.
    Resolve the real export, never assume @external is not an import thunk. }
  Module := Winapi.Windows.GetModuleHandleW(CozyText_Clock_kernel32_dll_cc35ee58);
  if Module = 0 then raise EInvalidOpException.Create(CozyText_Clock_CLOCK_MODULE_UNAVAILABLE_5316e621);
  Result := Winapi.Windows.GetProcAddress(Module, Name);
  if Result = nil then raise EInvalidOpException.Create(CozyText_Clock_CLOCK_API_UNAVAILABLE_7a5d1b63);
end;
function CozyTick: UInt64; stdcall;
var Query: TClockCounter; ReadError: TClockReadError; WriteError: TClockWriteError;
  Counter: Int64; SavedError: DWORD;
begin
  Query := TClockCounter(DecodeApiPointer(ClockSlot_QueryPerformanceCounter));
  ReadError := TClockReadError(DecodeApiPointer(ClockSlot_GetLastError));
  WriteError := TClockWriteError(DecodeApiPointer(ClockSlot_SetLastError));
  SavedError := ReadError();
  try
    Counter := 0;
    if not Query(Counter) then raise EInvalidOpException.Create(CozyText_Clock_CLOCK_READ_FAILED_47bcf620);
    Result := CozyCounterMilliseconds(Counter, ClockFrequency);
    { Reserve enough headroom for existing bounded Cardinal-sized deadlines
      and signed shutdown timestamps. Failure never grants a longer lease. }
    if Result > UInt64(High(Int64)) - High(Cardinal) then
      raise EInvalidOpException.Create(CozyText_Clock_CLOCK_COUNTER_OVERFLOW_53af3cef);
  finally WriteError(SavedError); end;
end;
function CozyFrameSeconds: Double;
var Query: TClockCounter; ReadError: TClockReadError; WriteError: TClockWriteError;
  Counter: Int64; SavedError: DWORD;
begin
  Query := TClockCounter(DecodeApiPointer(ClockSlot_QueryPerformanceCounter));
  ReadError := TClockReadError(DecodeApiPointer(ClockSlot_GetLastError));
  WriteError := TClockWriteError(DecodeApiPointer(ClockSlot_SetLastError));
  SavedError := ReadError();
  try
    Counter := 0;
    if not Query(Counter) or (Counter < 0) or (ClockFrequency <= 0) then
      raise EInvalidOpException.Create(CozyText_Clock_CLOCK_READ_FAILED_47bcf620);
    Result := Counter / ClockFrequency;
  finally WriteError(SavedError); end;
end;

function CozyClockDelayHandle: NativeUInt;
begin
  if DelayEvent = 0 then raise EInvalidOpException.Create(CozyText_Clock_CLOCK_WAIT_UNAVAILABLE_fedfb776);
  Result := NativeUInt(DelayEvent);
end;
function CozyWaitForDelay(Milliseconds: Cardinal;
  const Cancelled: TFunc<Boolean>): Boolean;
var Wait: TClockWait; ReadError: TClockReadError; WriteError: TClockWriteError;
  At, Deadline: UInt64; Slice, Status, SavedError: DWORD; Handle: THandle;
begin
  Wait := TClockWait(DecodeApiPointer(ClockSlot_WaitForSingleObject));
  ReadError := TClockReadError(DecodeApiPointer(ClockSlot_GetLastError));
  WriteError := TClockWriteError(DecodeApiPointer(ClockSlot_SetLastError));
  Handle := THandle(CozyClockDelayHandle);
  SavedError := ReadError();
  try
    Deadline := CozyDeadlineAfter(CozyTick, Milliseconds);
    repeat
      if Assigned(Cancelled) and Cancelled() then Exit(False);
      At := CozyTick;
      Slice := CozyDeadlineRemaining(At, Deadline, 100);
      if Slice = 0 then Exit(True);
      Status := Wait(Handle, Slice);
      if Status <> WAIT_TIMEOUT then
        raise EInvalidOpException.Create(CozyText_Clock_CLOCK_WAIT_FAILED_e7319768);
      { Windows8+ waits exclude low-power time; QPC does not. Recheck after
        every wake before callers can act on an expired local deadline. }
    until False;
  finally WriteError(SavedError); end;
end;
procedure CozyPause(Milliseconds: Cardinal);
begin
  CozyWaitForDelay(Milliseconds);
end;
procedure InitializeClock;
var Frequency: TClockCounter; Create: TClockCreateEvent;
  ReadError: TClockReadError; WriteError: TClockWriteError; SavedError: DWORD;
begin
  BindApiPointer(ClockSlot_QueryPerformanceCounter, RequireClockApi(CozyText_Clock_QueryPerformanceCounter_2b979b4b));
  BindApiPointer(ClockSlot_QueryPerformanceFrequency, RequireClockApi(CozyText_Clock_QueryPerformanceFrequency_649eba80));
  BindApiPointer(ClockSlot_CreateEventW, RequireClockApi(CozyText_Clock_CreateEventW_17a9fb00));
  BindApiPointer(ClockSlot_WaitForSingleObject, RequireClockApi(CozyText_Clock_WaitForSingleObject_5ebf7fd7));
  BindApiPointer(ClockSlot_CloseHandle, RequireClockApi(CozyText_Clock_CloseHandle_316c7c58));
  BindApiPointer(ClockSlot_GetLastError, RequireClockApi(CozyText_Clock_GetLastError_3b71a19f));
  BindApiPointer(ClockSlot_SetLastError, RequireClockApi(CozyText_Clock_SetLastError_527b0897));
  Frequency := TClockCounter(DecodeApiPointer(ClockSlot_QueryPerformanceFrequency));
  Create := TClockCreateEvent(DecodeApiPointer(ClockSlot_CreateEventW));
  ReadError := TClockReadError(DecodeApiPointer(ClockSlot_GetLastError));
  WriteError := TClockWriteError(DecodeApiPointer(ClockSlot_SetLastError));
  SavedError := ReadError();
  try
    ClockFrequency := 0;
    if not Frequency(ClockFrequency) or (ClockFrequency <= 0) then
      raise EInvalidOpException.Create(CozyText_Clock_CLOCK_FREQUENCY_INVALID_d11f427f);
    DelayEvent := Create(nil, True, False, nil);
    if DelayEvent = 0 then raise EInvalidOpException.Create(CozyText_Clock_CLOCK_WAIT_UNAVAILABLE_fedfb776);
  finally WriteError(SavedError); end;
end;
procedure FinalizeClock;
var Close: TClockClose;
begin
  { All dependent units finalize before this unit. Their worker/I/O owners
    must drain before releasing the shared wait resource. }
  if DelayEvent <> 0 then
  begin
    Close := TClockClose(DecodeApiPointer(ClockSlot_CloseHandle));
    Close(DelayEvent);
    DelayEvent := 0;
  end;
end;
initialization
  InitializeClock;
finalization
  FinalizeClock;
end.
