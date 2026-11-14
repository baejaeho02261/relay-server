unit Cozy.ThreadInventory.Core;
{$IFDEF FPC}{$MODE DELPHI}{$ENDIF}
{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}
interface
{ Cozy central text imports. }
uses
  Cozy.Strings.Integrity;

type
  TThreadStartKind = (tskKnownImage, tskUnknownStart, tskUnreadable);
  TThreadInventoryStatus = (tisComplete, tisPartial, tisUnavailable);
  TThreadNextKind = (tnkItem, tnkEnd, tnkError);
  TThreadInventoryCounts = record
    Status: TThreadInventoryStatus;
    Enumerated, KnownImage, UnknownStart, Unreadable: Cardinal;
    Truncated: Boolean;
  end;
  { Synchronous borrowed callbacks. The caller owns Context through return.
    Next transfers each newly opened handle; Close must never raise. }
  TThreadInventoryCalls = record
    Context: Pointer;
    Next: function(Context: Pointer; Previous: NativeUInt;
      out NewHandle: NativeUInt): TThreadNextKind;
    Classify: function(Context: Pointer; Thread: NativeUInt): TThreadStartKind;
    Close: function(Context: Pointer; Thread: NativeUInt): Boolean;
    WithinBudget: function(Context: Pointer): Boolean;
  end;
const MaximumObservedThreads = 1024;
function ScanThreadStarts(const Calls: TThreadInventoryCalls): TThreadInventoryCounts;
function ClassifyThreadRegion(Start, RegionBase, RegionBytes, AllocationBase,
  ModuleBase: NativeUInt; State, Protect, Kind: Cardinal): TThreadStartKind;
function ThreadInventoryStatusName(Status: TThreadInventoryStatus): string;
implementation
function ThreadInventoryStatusName(Status: TThreadInventoryStatus): string;
begin
  case Status of
    tisComplete: Result := CozyText_ThreadInventory_Core_COMPLETE_2e3b6e3b;
    tisPartial: Result := CozyText_ThreadInventory_Core_PARTIAL_e68cc24f;
  else Result := CozyText_ThreadInventory_Core_UNAVAILABLE_859f2f2d; end;
end;
function ClassifyThreadRegion(Start, RegionBase, RegionBytes, AllocationBase,
  ModuleBase: NativeUInt; State, Protect, Kind: Cardinal): TThreadStartKind;
var Protection: Cardinal;
begin
  Result := tskUnknownStart;
  { No memory is dereferenced. Unknown includes legitimate JIT code, unmapped
    former starts, private executable memory and unregistered image views. }
  if (Start = 0) or (RegionBytes = 0) or (Start < RegionBase) or
    (Start - RegionBase >= RegionBytes) then Exit;
  if (State <> $1000) or (Kind <> $1000000) or
    (AllocationBase = 0) or (ModuleBase <> AllocationBase) or
    ((Protect and $100) <> 0) then Exit;
  Protection := Protect and $FF;
  if (Protection = $10) or (Protection = $20) or
    (Protection = $40) or (Protection = $80) then Result := tskKnownImage;
  { Writable/executable image code is still image-backed, NOT attested safe.
    Code integrity and mitigation policy are independent server signals. }
end;
function ScanThreadStarts(const Calls: TThreadInventoryCalls): TThreadInventoryCounts;
var Current, Next: NativeUInt; Step: TThreadNextKind; Kind: TThreadStartKind;
  Exhausted, CloseFailed: Boolean;
  procedure ReleaseHandle(var Handle: NativeUInt);
  var Owned: NativeUInt;
  begin
    Owned := Handle; Handle := 0;
    if (Owned <> 0) and not Calls.Close(Calls.Context, Owned) then CloseFailed := True;
  end;
begin
  Result := Default(TThreadInventoryCounts); Result.Status := tisUnavailable;
  if not Assigned(Calls.Next) or not Assigned(Calls.Classify) or
    not Assigned(Calls.Close) or not Assigned(Calls.WithinBudget) then Exit;
  Result.Status := tisPartial;
  Current := 0; Next := 0; Exhausted := False; CloseFailed := False;
  try
    while True do
    begin
      if not Calls.WithinBudget(Calls.Context) then
      begin Result.Truncated := True; Break; end;
      Next := 0;
      Step := Calls.Next(Calls.Context, Current, Next);
      { A live previous handle cannot also be a newly allocated handle. Do not
        double-close an invalid provider result. Native iteration never does this. }
      if (Next <> 0) and (Next = Current) then
      begin Next := 0; Break; end;
      ReleaseHandle(Current);
      if Step = tnkEnd then
      begin Exhausted := Next = 0; Break; end;
      if (Step <> tnkItem) or (Next = 0) then Break;
      Current := Next; Next := 0;
      if Result.Enumerated >= MaximumObservedThreads then
      begin Result.Truncated := True; Break; end;
      if not Calls.WithinBudget(Calls.Context) then
      begin Result.Truncated := True; Break; end;
      Kind := Calls.Classify(Calls.Context, Current);
      Inc(Result.Enumerated);
      case Kind of
        tskKnownImage: Inc(Result.KnownImage);
        tskUnknownStart: Inc(Result.UnknownStart);
      else Inc(Result.Unreadable); end;
    end;
  finally
    try ReleaseHandle(Next); finally ReleaseHandle(Current); end;
  end;
  if Exhausted and not CloseFailed and (Result.Unreadable = 0) then
    Result.Status := tisComplete;
end;
end.
