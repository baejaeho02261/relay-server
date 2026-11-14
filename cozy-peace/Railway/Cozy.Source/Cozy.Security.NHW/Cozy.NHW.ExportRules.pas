unit Cozy.NHW.ExportRules;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  Cozy.NHW.PERules;

const
  NHW_DELAY_SLOT_LIMIT = 4096;

type
  TDelaySlotObservation = record
    SlotAddress: NativeUInt;
    TargetAddress: NativeUInt;
    UnloadTarget: NativeUInt; // optional UIAT helper thunk, not executed
    Resolved: Boolean;
  end;
  TDelaySlotObservations = TArray<TDelaySlotObservation>;
  TDelaySlotSnapshot = record
    Complete: Boolean;
    ImageBase: NativeUInt;
    LayoutDigest: UInt64; // descriptors/slot addresses, never resolved targets
    Slots: TDelaySlotObservations; // unique SlotAddress, ascending
  end;
  TDelaySlotWatch = record
    SlotAddress: NativeUInt;
    LocalThunk: NativeUInt;
    WasResolved: Boolean;
    Target: TPEWatchCell;
  end;

  // The six records describe observations, not proven external tampering.
  // Unavailable queries are ignored rather than considered suspicious.
  TExportSnapshot = record
    Table: TPEFeature;
    Forwarder: TPEFeature;
    ApiSet: TPEFeature;
    DelayImport: TPEFeature;
    Target: TPEFeature;
    Resolution: TPEFeature;
    ResolvedDelaySlots: Cardinal;
    DelaySlots: TDelaySlotSnapshot;
  end;

  TExportWatch = record
    Table: TPEWatchCell;
    Forwarder: TPEWatchCell;
    ApiSet: TPEWatchCell;
    DelayImport: TPEWatchCell;
    Target: TPEWatchCell;
    Resolution: TPEWatchCell;
    PreviousResolvedSlots: Cardinal;
    DelayPrimed: Boolean;
    DelayImageBase: NativeUInt;
    DelayLayout: TPEWatchCell;
    DelaySlots: TArray<TDelaySlotWatch>;
  end;

procedure DelayImportObservationGap(var State: TExportWatch);
function ObserveDelayImportSlots(var State: TExportWatch;
  const Snapshot: TDelaySlotSnapshot; Baseline: Boolean): Boolean;

function ExportHash(const H, Value: UInt64): UInt64;
function IsApiSetContract(const Forwarder: AnsiString): Boolean;
function IsValidForwarder(const Forwarder: AnsiString): Boolean;
// Compatibility scalar helper for old tests/callers. Production ExportGuard
// uses the detailed slot path; a scalar digest cannot disambiguate two slots.
function ObserveDelayImport(var State: TExportWatch;
  const Feature: TPEFeature; ResolvedSlots: Cardinal;
  Baseline: Boolean): Boolean;

{$IFDEF NHW_NATIVE10Q_TESTS}
function TestExportRules10Q(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  System.SysUtils;

function ExportHash(const H, Value: UInt64): UInt64;
begin
  Result := PEHashInteger(H, Value);
end;

function IsApiSetContract(const Forwarder: AnsiString): Boolean;
var
  S: AnsiString;
  I: Integer;
begin
  Result := False;
  if Length(Forwarder) < 4 then Exit;
  S := Copy(Forwarder, 1, 4);
  // PE export forwarders use ASCII module names. Avoid codepage conversion.
  for I := 1 to 4 do
    if (S[I] >= 'A') and (S[I] <= 'Z') then
      S[I] := AnsiChar(Ord(S[I]) + 32);
  Result := (S = AnsiString('api-')) or (S = AnsiString('ext-'));
end;

function IsValidForwarder(const Forwarder: AnsiString): Boolean;
var
  I, Dot: Integer;
begin
  Result := False;
  if (Length(Forwarder) < 3) or (Length(Forwarder) > 240) then Exit;
  Dot := 0;
  for I := 1 to Length(Forwarder) do
  begin
    if (Byte(Forwarder[I]) < 33) or (Byte(Forwarder[I]) > 126) then Exit;
    if Forwarder[I] = '.' then Dot := I;
  end;
  if (Dot <= 1) or (Dot >= Length(Forwarder)) then Exit;
  if Forwarder[Dot + 1] = '#' then
  begin
    if Dot + 2 > Length(Forwarder) then Exit;
    for I := Dot + 2 to Length(Forwarder) do
      if not (Forwarder[I] in ['0'..'9']) then Exit;
  end;
  Result := True;
end;

function ObserveDelayImport(var State: TExportWatch;
  const Feature: TPEFeature; ResolvedSlots: Cardinal;
  Baseline: Boolean): Boolean;
begin
  Result := False;
  if not Feature.Available or not Feature.Valid then Exit;
  // The legitimate first delay-load replaces a local thunk with an external
  // function pointer. Increasing the number of resolved slots is therefore
  // *not* considered a change event; the new state is a fresh baseline.
  if not State.DelayPrimed or Baseline or
     (ResolvedSlots <> State.PreviousResolvedSlots) then
  begin
    State.DelayImport := Default(TPEWatchCell);
    State.DelayPrimed := True;
    State.PreviousResolvedSlots := ResolvedSlots;
    PEObserve(State.DelayImport, Feature, True);
    Exit;
  end;
  Result := PEObserve(State.DelayImport, Feature, False);
end;

procedure DelayImportObservationGap(var State: TExportWatch);
var I: Integer;
begin
  PEObservationGap(State.DelayImport);
  PEObservationGap(State.DelayLayout);
  for I := 0 to Length(State.DelaySlots) - 1 do
    PEObservationGap(State.DelaySlots[I].Target);
end;

function DelaySnapshotValid(const Snapshot: TDelaySlotSnapshot): Boolean;
var I: Integer;
begin
  Result := False;
  if not Snapshot.Complete or (Snapshot.ImageBase = 0) or
     (Length(Snapshot.Slots) > NHW_DELAY_SLOT_LIMIT) then Exit;
  for I := 0 to Length(Snapshot.Slots) - 1 do
  begin
    if (Snapshot.Slots[I].SlotAddress = 0) or
       (Snapshot.Slots[I].TargetAddress = 0) then Exit;
    if I > 0 then
      if Snapshot.Slots[I].SlotAddress <= Snapshot.Slots[I-1].SlotAddress then Exit;
  end;
  Result := True;
end;

function ObserveDelayImportSlots(var State: TExportWatch;
  const Snapshot: TDelaySlotSnapshot; Baseline: Boolean): Boolean;
var
  NextSlots: TArray<TDelaySlotWatch>;
  NextLayout: TPEWatchCell;
  OldIndex: Integer;
  NewImage, KnownSlot, LegitimateLocal, Changed: Boolean;
  Item: TDelaySlotObservation;
  Feature: TPEFeature;

  procedure PrepareLayoutCandidate;
  begin
    NewImage := State.DelayImageBase <> Snapshot.ImageBase;
    NextLayout := State.DelayLayout;
    if NewImage then NextLayout := Default(TPEWatchCell);
    Feature := Default(TPEFeature);
    Feature.Available := True;
    Feature.Valid := True;
    Feature.Digest := Snapshot.LayoutDigest;
    Changed := PEObserve(NextLayout, Feature, Baseline or NewImage);
  end;

  procedure BuildSlotCandidates;
  var
    I: Integer;
  begin
    SetLength(NextSlots, Length(Snapshot.Slots));
    OldIndex := 0;
    for I := 0 to Length(Snapshot.Slots) - 1 do
    begin
      Item := Snapshot.Slots[I];
      while OldIndex < Length(State.DelaySlots) do
      begin
        if State.DelaySlots[OldIndex].SlotAddress >= Item.SlotAddress then Break;
        Inc(OldIndex);
      end;
      KnownSlot := False;
      if not NewImage and (OldIndex < Length(State.DelaySlots)) then
        KnownSlot := State.DelaySlots[OldIndex].SlotAddress = Item.SlotAddress;
      if KnownSlot then NextSlots[I] := State.DelaySlots[OldIndex];
      NextSlots[I].SlotAddress := Item.SlotAddress;
      if (NextSlots[I].LocalThunk = 0) and (Item.UnloadTarget <> 0) then
        NextSlots[I].LocalThunk := Item.UnloadTarget;
      Feature.Digest := UInt64(Item.TargetAddress);
      if not Item.Resolved then
      begin
        if NextSlots[I].LocalThunk = 0 then
          NextSlots[I].LocalThunk := Item.TargetAddress;
        LegitimateLocal := Item.TargetAddress = NextSlots[I].LocalThunk;
        if LegitimateLocal then
        begin
          NextSlots[I].Target := Default(TPEWatchCell);
          NextSlots[I].WasResolved := False; // explicit unload/rearm, this slot only
        end
        else
        begin
          // A different local destination is not an ordinary unload thunk.
          if not NextSlots[I].Target.Fingerprint.HasBaseline then
          begin
            Feature.Digest := UInt64(NextSlots[I].LocalThunk);
            PEObserve(NextSlots[I].Target, Feature, True);
            Feature.Digest := UInt64(Item.TargetAddress);
          end;
          if PEObserve(NextSlots[I].Target, Feature, Baseline) then Changed := True;
        end;
      end
      else if not NextSlots[I].WasResolved or not KnownSlot or NewImage then
      begin
        NextSlots[I].Target := Default(TPEWatchCell);
        PEObserve(NextSlots[I].Target, Feature, True);
        NextSlots[I].WasResolved := True;
      end
      else if PEObserve(NextSlots[I].Target, Feature, Baseline) then Changed := True;
    end;
  end;

  procedure CommitSlotSnapshot;
  begin
    State.DelaySlots := NextSlots;
    State.DelayLayout := NextLayout;
    State.DelayImageBase := Snapshot.ImageBase;
  end;

begin
  Result := False;
  if not DelaySnapshotValid(Snapshot) then
  begin
    DelayImportObservationGap(State);
    Exit;
  end;
  // Build a new watch array first; allocation failure never publishes half a
  // generation. A normally resolving slot affects only its own baseline.
  try
    PrepareLayoutCandidate;
    BuildSlotCandidates;
    CommitSlotSnapshot;
    Result := Changed;
  except
    DelayImportObservationGap(State);
    raise;
  end;
end;

{$IFDEF NHW_NATIVE10Q_TESTS}
{$I Cozy.NHW.Native10Q.ExportRules.inc}
{$ENDIF}

end.
