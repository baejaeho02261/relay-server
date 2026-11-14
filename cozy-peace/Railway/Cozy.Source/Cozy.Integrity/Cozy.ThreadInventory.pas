unit Cozy.ThreadInventory;
{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}
interface
uses
{ Cozy central text imports. }
  Cozy.Strings.Integrity,
 System.JSON, Cozy.Measurement;
{ Own-process observations only. Counts never authorize or terminate anything.
  No raw addresses, thread IDs, paths or memory contents enter this JSON.
  COMPLETE means the accessible native iterator ended and its observations
  were readable. This is not an atomic census: short-lived threads and threads
  inaccessible at the requested rights may be absent. A reported start address
  is not the current instruction pointer, nor proof that later execution is safe. }
function CollectThreadInventoryJSON(const Budget: TMeasurementBudget): TJSONObject;
implementation
uses Winapi.Windows, System.SysUtils, Cozy.WinApi, Cozy.Api.ROR13,
  Cozy.Api.Pointer, Cozy.Platform.ExportResolver, Cozy.ThreadInventory.Core;
type
  TNtGetNextThread = function(Process, Previous: THandle; DesiredAccess,
    Attributes, Flags: Cardinal; out NewHandle: THandle): LongInt; stdcall;
  TNtQueryInformationThread = function(Thread: THandle; InformationClass: Cardinal;
    Buffer: Pointer; Bytes: Cardinal; out Returned: Cardinal): LongInt; stdcall;
  TQueryRegion = function(Address: Pointer; var Region: TGameMemoryBasicInformation;
    Bytes: NativeUInt): NativeUInt; stdcall;
  TModuleFromAddress = function(Flags: DWORD; Address: PWideChar;
    out Module: HMODULE): BOOL; stdcall;
  TReleaseModule = function(Module: HMODULE): BOOL; stdcall;
  PScanContext = ^TScanContext;
  TScanContext = record
    Budget: TMeasurementBudget;
    Started: UInt64;
    NextTarget: TNtGetNextThread;
    QueryTarget: TNtQueryInformationThread;
    MemoryTarget: TQueryRegion;
    RetainTarget: TModuleFromAddress;
    ReleaseTarget: TReleaseModule;
    CloseTarget: TApiCloseHandle;
  end;
var
  Slot_NtGetNextThread, Slot_NtQueryInformationThread, Slot_VirtualQuery,
    Slot_GetModuleHandleExW, Slot_FreeLibrary, Slot_CloseHandle: TEncodedApiPointer;
const
  StatusNoMoreEntries = $8000001A;
  QueryStartAddress = 9;
  ThreadQueryInformation = $0040;
  MaximumThreadMilliseconds = 1500;
function NextThread(Context: Pointer; Previous: NativeUInt;
  out NewHandle: NativeUInt): TThreadNextKind;
var Target: TNtGetNextThread; Status: LongInt; Handle: THandle;
begin
  NewHandle := 0; Handle := 0;
  Target := PScanContext(Context).NextTarget;
  { The pseudo-handle can only name this process; no caller-selected PID exists.
    No suspend/context/write permissions are requested. }
  Status := Target(THandle(High(NativeUInt)), THandle(Previous),
    ThreadQueryInformation, 0, 0, Handle);
  NewHandle := NativeUInt(Handle);
  if Cardinal(Status) = StatusNoMoreEntries then Result := tnkEnd
  else if Status = 0 then Result := tnkItem else Result := tnkError;
end;
function ReleaseThread(Context: Pointer; Thread: NativeUInt): Boolean;
var Target: TApiCloseHandle;
begin
  Target := PScanContext(Context).CloseTarget;
  Result := Target(THandle(Thread));
end;
function ClassifyThread(Context: Pointer; Thread: NativeUInt): TThreadStartKind;
var Query: TNtQueryInformationThread; Memory: TQueryRegion;
  Retain: TModuleFromAddress; Release: TReleaseModule;
  Start: Pointer; Returned: Cardinal; Region: TGameMemoryBasicInformation;
  Module: HMODULE; Retained: Boolean;
begin
  Result := tskUnreadable; Start := nil; Returned := 0;
  Query := PScanContext(Context).QueryTarget;
  if (Query(THandle(Thread), QueryStartAddress, @Start, SizeOf(Start), Returned) <> 0) or
    (Returned <> SizeOf(Start)) then Exit;
  if Start = nil then Exit(tskUnknownStart);
  Memory := PScanContext(Context).MemoryTarget;
  Retain := PScanContext(Context).RetainTarget;
  Release := PScanContext(Context).ReleaseTarget;
  Module := 0;
  { FROM_ADDRESS increments a loader reference. Hold it through VirtualQuery,
    then release it. No process-lifetime pinning for arbitrary observed modules. }
  Retained := Retain($00000004, PWideChar(Start), Module);
  try
    FillChar(Region, SizeOf(Region), 0);
    if Memory(Start, Region, SizeOf(Region)) <> SizeOf(Region) then Exit;
    if not Retained then Module := 0;
    Result := ClassifyThreadRegion(NativeUInt(Start), NativeUInt(Region.BaseAddress),
      Region.RegionSize, NativeUInt(Region.AllocationBase), NativeUInt(Module),
      Region.State, Region.Protect, Region.Kind);
  finally
    if Retained and (Module <> 0) then
      if not Release(Module) then Result := tskUnreadable;
  end;
end;
function WithinBudget(Context: Pointer): Boolean;
var State: PScanContext; Tick: UInt64;
begin
  State := PScanContext(Context);
  try
    State.Budget.Check(0, 0);
    Tick := MeasurementTick;
    Result := (Tick >= State.Started) and
      (Tick - State.Started < MaximumThreadMilliseconds);
  except on E: EMeasurement do Result := False; end;
end;
function CollectThreadInventoryJSON(const Budget: TMeasurementBudget): TJSONObject;
var Calls: TThreadInventoryCalls; Counts: TThreadInventoryCounts; Context: TScanContext;
begin
  Counts := Default(TThreadInventoryCounts); Counts.Status := tisUnavailable;
  if Slot_NtGetNextThread.IsBound and Slot_NtQueryInformationThread.IsBound then
  begin
    Context.Budget := Budget; Context.Started := MeasurementTick;
    { Decode before any handle is acquired. Cleanup never needs a potentially
      throwing pointer lookup while it owns an enumerated thread/module. These
      borrowed targets live only in this synchronous bounded stack context. }
    Context.NextTarget := TNtGetNextThread(DecodeApiPointer(Slot_NtGetNextThread));
    Context.QueryTarget := TNtQueryInformationThread(DecodeApiPointer(Slot_NtQueryInformationThread));
    Context.MemoryTarget := TQueryRegion(DecodeApiPointer(Slot_VirtualQuery));
    Context.RetainTarget := TModuleFromAddress(DecodeApiPointer(Slot_GetModuleHandleExW));
    Context.ReleaseTarget := TReleaseModule(DecodeApiPointer(Slot_FreeLibrary));
    Context.CloseTarget := TApiCloseHandle(DecodeApiPointer(Slot_CloseHandle));
    Calls := Default(TThreadInventoryCalls); Calls.Context := @Context;
    Calls.Next := NextThread; Calls.Classify := ClassifyThread;
    Calls.Close := ReleaseThread; Calls.WithinBudget := WithinBudget;
    try Counts := ScanThreadStarts(Calls);
    finally
      Context.NextTarget := nil; Context.QueryTarget := nil;
      Context.MemoryTarget := nil; Context.RetainTarget := nil;
      Context.ReleaseTarget := nil; Context.CloseTarget := nil;
    end;
  end;
  Result := TJSONObject.Create;
  try
    Result.AddPair(CozyText_ThreadInventory_version_f33787ad, TJSONNumber.Create(1));
    Result.AddPair(CozyText_ThreadInventory_status_6bb789c5, ThreadInventoryStatusName(Counts.Status));
    Result.AddPair(CozyText_ThreadInventory_enumerated_5400d332, TJSONNumber.Create(Counts.Enumerated));
    Result.AddPair(CozyText_ThreadInventory_knownImage_52344353, TJSONNumber.Create(Counts.KnownImage));
    Result.AddPair(CozyText_ThreadInventory_unknownStart_1c7d266b, TJSONNumber.Create(Counts.UnknownStart));
    Result.AddPair(CozyText_ThreadInventory_unreadable_36425bd4, TJSONNumber.Create(Counts.Unreadable));
    Result.AddPair(CozyText_ThreadInventory_truncated_125753da, TJSONBool.Create(Counts.Truncated));
  except Result.Free; raise; end;
end;
procedure BindOptionalApis;
var Address: Pointer;
begin
  Address := OptionalSystemProcAddressHash64(CozyText_ThreadInventory_ntdll_dll_44c28d73, HASH_NtGetNextThread);
  if Address <> nil then BindApiPointer(Slot_NtGetNextThread, Address);
  Address := OptionalSystemProcAddressHash64(CozyText_ThreadInventory_ntdll_dll_44c28d73, HASH_NtQueryInformationThread);
  if Address <> nil then BindApiPointer(Slot_NtQueryInformationThread, Address);
end;
initialization
  BindApiPointer(Slot_VirtualQuery, RequireProcAddressHash64(CozyText_ThreadInventory_kernel32_dll_d6a49e3d, HASH_VirtualQuery));
  BindApiPointer(Slot_GetModuleHandleExW, RequireProcAddressHash64(CozyText_ThreadInventory_kernel32_dll_d6a49e3d, HASH_GetModuleHandleExW));
  BindApiPointer(Slot_FreeLibrary, RequireProcAddressHash64(CozyText_ThreadInventory_kernel32_dll_d6a49e3d, HASH_FreeLibrary));
  BindApiPointer(Slot_CloseHandle, RequireProcAddressHash64(CozyText_ThreadInventory_kernel32_dll_d6a49e3d, HASH_CloseHandle));
  BindOptionalApis;
end.
