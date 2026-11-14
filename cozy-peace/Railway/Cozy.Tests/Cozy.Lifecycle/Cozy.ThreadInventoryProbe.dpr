program Cozy_ThreadInventoryProbe;
{$IFDEF FPC}{$MODE DELPHI}{$ELSE}{$APPTYPE CONSOLE}{$ENDIF}
uses
{ Cozy central text imports. }
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.TestsLifecycle in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsLifecycle.pas',
{$IF (Defined(GAME_NATIVE_ABI_TESTS))}
  Cozy.Strings.TestsPlatform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsPlatform.pas',
{$ENDIF}

  {$IFDEF FPC}SysUtils,{$ELSE}System.SysUtils, System.JSON, System.Generics.Collections, Cozy.ThreadInventory,
    Cozy.Measurement, Cozy.Api.Pointer,{$ENDIF}
  Cozy.ThreadInventory.Core;
type
  PFixture = ^TFixture;
  TFixture = record
    Limit, Opened, Closed, Checks, StopAt, FailAt, ThrowAt, DuplicateAt,
      UnreadableAt, UnknownAt, CloseFailAt: Integer;
    FailWithHandle, EndWithHandle: Boolean;
    Live: array[1..MaximumObservedThreads + 4] of Boolean;
  end;
var F: TFixture; Calls: TThreadInventoryCalls; C: TThreadInventoryCounts;
  Passed: Integer; Raised: Boolean;
procedure Require(Condition: Boolean);
begin
  if not Condition then raise Exception.Create(CozyText_ThreadInventoryProbe_THREAD_INVENTORY_CONTRACT_1d3d8f19);
  Inc(Passed);
end;
function NextFixture(Context: Pointer; Previous: NativeUInt;
  out NewHandle: NativeUInt): TThreadNextKind;
var S: PFixture;
begin
  S := PFixture(Context); NewHandle := 0;
  if Previous <> 0 then Require(S.Live[Previous]);
  if (S.DuplicateAt > 0) and (S.Opened = S.DuplicateAt) then
  begin NewHandle := Previous; Exit(tnkItem); end;
  if (S.FailAt > 0) and (S.Opened = S.FailAt) then
  begin
    if S.FailWithHandle then
    begin Inc(S.Opened); NewHandle := S.Opened; S.Live[NewHandle] := True; end;
    Exit(tnkError);
  end;
  if S.Opened >= S.Limit then
  begin
    if S.EndWithHandle then
    begin Inc(S.Opened); NewHandle := S.Opened; S.Live[NewHandle] := True; end;
    Exit(tnkEnd);
  end;
  Inc(S.Opened); NewHandle := S.Opened; S.Live[NewHandle] := True;
  Result := tnkItem;
end;
function ClassifyFixture(Context: Pointer; Thread: NativeUInt): TThreadStartKind;
var S: PFixture;
begin
  S := PFixture(Context); Require(S.Live[Thread]);
  if Thread = NativeUInt(S.ThrowAt) then raise Exception.Create(CozyText_ThreadInventoryProbe_SIMULATED_QUERY_EXCEPTION_ccac38f9);
  if Thread = NativeUInt(S.UnreadableAt) then Result := tskUnreadable
  else if Thread = NativeUInt(S.UnknownAt) then Result := tskUnknownStart
  else Result := tskKnownImage;
end;
function CloseFixture(Context: Pointer; Thread: NativeUInt): Boolean;
var S: PFixture;
begin
  S := PFixture(Context); Require(S.Live[Thread]);
  S.Live[Thread] := False; Inc(S.Closed);
  Result := Thread <> NativeUInt(S.CloseFailAt);
end;
function BudgetFixture(Context: Pointer): Boolean;
var S: PFixture;
begin
  S := PFixture(Context); Inc(S.Checks);
  Result := (S.StopAt = 0) or (S.Checks < S.StopAt);
end;
procedure Setup(Limit: Integer);
begin
  F := Default(TFixture); F.Limit := Limit;
  Calls := Default(TThreadInventoryCalls); Calls.Context := @F;
  Calls.Next := NextFixture; Calls.Classify := ClassifyFixture;
  Calls.Close := CloseFixture; Calls.WithinBudget := BudgetFixture;
end;
procedure CheckCounts;
begin
  Require(C.Enumerated = C.KnownImage + C.UnknownStart + C.Unreadable);
  Require(C.Enumerated <= MaximumObservedThreads);
  Require(F.Closed = F.Opened);
end;
{$IFNDEF FPC}
procedure NativeSmoke;
var J: TJSONObject; Budget: TMeasurementBudget; Status: string;
  Count, Known, Unknown, Unread: Integer;
begin
  SealApiPointerStorage;
  Budget := TMeasurementBudget.Start(1024, 5000);
  J := CollectThreadInventoryJSON(Budget);
  try
    Require(J.Count = 7); Require(J.GetValue<Integer>(CozyText_ThreadInventoryProbe_version_45042994) = 1);
    Status := J.GetValue<string>(CozyText_ThreadInventoryProbe_status_61f9c79e);
    Require((Status = CozyText_ThreadInventoryProbe_COMPLETE_5a37cb37) or (Status = CozyText_ThreadInventoryProbe_PARTIAL_1a72a6a0) or (Status = CozyText_ThreadInventoryProbe_UNAVAILABLE_9b4ecf6c));
    Count := J.GetValue<Integer>(CozyText_ThreadInventoryProbe_enumerated_b71d38c0); Known := J.GetValue<Integer>(CozyText_ThreadInventoryProbe_knownImage_a57d471b);
    Unknown := J.GetValue<Integer>(CozyText_ThreadInventoryProbe_unknownStart_bf26e165); Unread := J.GetValue<Integer>(CozyText_ThreadInventoryProbe_unreadable_aee2e4c9);
    Require((Count >= 0) and (Count <= MaximumObservedThreads));
    Require((Known >= 0) and (Unknown >= 0) and (Unread >= 0));
    Require(Count = Known + Unknown + Unread);
    if Status = CozyText_ThreadInventoryProbe_COMPLETE_5a37cb37 then Require((Count > 0) and (Unread = 0));
    Writeln(CozyText_ThreadInventoryProbe_OBSERVED_thread_start_inventory_bd6af40f, J.ToJSON);
    if Status = CozyText_ThreadInventoryProbe_UNAVAILABLE_9b4ecf6c then Writeln(CozyText_ThreadInventoryProbe_SKIP_actual_Windows_thread_start_observation_nat_fd7ea1e5)
    else if Status = CozyText_ThreadInventoryProbe_PARTIAL_1a72a6a0 then Writeln(CozyText_ThreadInventoryProbe_PARTIAL_actual_Windows_thread_start_observation__11f2bfe3);
  finally J.Free; end;
end;
{$ENDIF}
begin
  try
    Calls := Default(TThreadInventoryCalls); C := ScanThreadStarts(Calls);
    Require((C.Status = tisUnavailable) and (C.Enumerated = 0));
    Setup(3); F.UnknownAt := 2; C := ScanThreadStarts(Calls); CheckCounts;
    Require((C.Status = tisComplete) and (C.KnownImage = 2) and (C.UnknownStart = 1));
    Setup(3); F.UnreadableAt := 2; C := ScanThreadStarts(Calls); CheckCounts;
    Require((C.Status = tisPartial) and (C.Unreadable = 1) and not C.Truncated);
    Setup(4); F.FailAt := 2; C := ScanThreadStarts(Calls); CheckCounts;
    Require((C.Status = tisPartial) and (C.Enumerated = 2));
    Setup(4); F.FailAt := 2; F.FailWithHandle := True; C := ScanThreadStarts(Calls); CheckCounts;
    Require((C.Status = tisPartial) and (C.Enumerated = 2));
    Setup(MaximumObservedThreads + 1); C := ScanThreadStarts(Calls); CheckCounts;
    Require((C.Status = tisPartial) and C.Truncated and (C.Enumerated = MaximumObservedThreads));
    Setup(MaximumObservedThreads); C := ScanThreadStarts(Calls); CheckCounts;
    Require((C.Status = tisComplete) and not C.Truncated);
    Setup(2); F.StopAt := 1; C := ScanThreadStarts(Calls); CheckCounts;
    Require((C.Status = tisPartial) and C.Truncated and (C.Enumerated = 0));
    Setup(2); F.StopAt := 2; C := ScanThreadStarts(Calls); CheckCounts;
    Require((C.Status = tisPartial) and C.Truncated and (C.Enumerated = 0));
    Setup(3); F.ThrowAt := 2; Raised := False;
    try ScanThreadStarts(Calls); except on E: Exception do Raised := True; end;
    Require(Raised and (F.Closed = F.Opened) and (F.Opened = 2));
    Setup(3); F.DuplicateAt := 1; C := ScanThreadStarts(Calls); CheckCounts;
    Require((C.Status = tisPartial) and (C.Enumerated = 1));
    Setup(1); F.EndWithHandle := True; C := ScanThreadStarts(Calls); CheckCounts;
    Require(C.Status = tisPartial);
    Setup(2); F.CloseFailAt := 1; C := ScanThreadStarts(Calls); CheckCounts;
    Require(C.Status = tisPartial);
    Require(ClassifyThreadRegion($1010,$1000,$1000,$1000,$1000,$1000,$20,$1000000) = tskKnownImage);
    Require(ClassifyThreadRegion($1010,$1000,$1000,$1000,$1000,$1000,$40,$1000000) = tskKnownImage);
    Require(ClassifyThreadRegion($1010,$1000,$1000,$1000,0,$1000,$20,$1000000) = tskUnknownStart);
    Require(ClassifyThreadRegion($1010,$1000,$1000,$1000,$1000,$1000,$20,$20000) = tskUnknownStart);
    Require(ClassifyThreadRegion($1010,$1000,$1000,$1000,$1000,$1000,$120,$1000000) = tskUnknownStart);
    Require(ClassifyThreadRegion($1010,$1000,$1000,$1000,$1000,$1000,$04,$1000000) = tskUnknownStart);
    Require(ClassifyThreadRegion($2000,$1000,$1000,$1000,$1000,$1000,$20,$1000000) = tskUnknownStart);
    Require(ClassifyThreadRegion($FFF,$1000,$1000,$1000,$1000,$1000,$20,$1000000) = tskUnknownStart);
    Require(ClassifyThreadRegion(High(NativeUInt),High(NativeUInt)-1,2,1,1,$1000,$20,$1000000) = tskKnownImage);
    {$IFNDEF FPC}NativeSmoke;{$ENDIF}
    Writeln(CozyText_ThreadInventoryProbe_PASS_own_process_thread_inventory_contracts_d644cd39, Passed);
  except on E: Exception do begin Writeln(E.ClassName, CozyText_ThreadInventoryProbe_Text_191fb4dc, E.Message); Halt(1); end; end;
end.
