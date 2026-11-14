unit Cozy.NHW.IndirectTargets;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows, Cozy.NHW.Logging;

type
  TIndirectTarget = record
    Expected: NativeUInt;
    Observed: NativeUInt;
    OriginalRegion, ObservedRegion: NativeUInt;
    LastValid: UInt64;
    Confirmations: Byte;
  end;

  // Owned callback entry points; IAT/EAT/TLS parsing remains in its own sensors.
  // Engine owns the monitor and serializes all calls.
  TIndirectTargetMonitor = class
  private
    FItems: array[0..2] of TIndirectTarget;
    FEpoch: Cardinal;
    FLastReport: UInt64;
    procedure InvalidateCandidates;
  public
    constructor Create;
    procedure Reset;
    procedure Examine(OwnTarget, Baseline, EpochStable: Boolean;
      Epoch: Cardinal; Callback, RecordCallback,
      BufferCallback: NativeUInt; const Kinds: TDetectionKinds;
      Tick: UInt64; var Detected: TDetectionKinds);
  end;

function IndirectTargetCandidate(OriginalIsImage, CurrentIsPrivate:
  Boolean; Confirmations: Byte; Independent, EpochStable: Boolean): Boolean;
{$IFDEF NHW_NATIVE5H_TESTS}
function TestIndirectTargetsHardening(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses Cozy.NHW.PEView {$IFDEF NHW_NATIVE5H_TESTS}, System.SysUtils{$ENDIF};

{$IFDEF NHW_NATIVE5H_TESTS}
type TIndirectDescribeHook = function(Address: NativeUInt;
  out Kind: TCodeLocation; out Region: NativeUInt): Boolean;
var IndirectDescribeHook: TIndirectDescribeHook = nil;
{$ENDIF}

function QueryIndirectCode(Address: NativeUInt; out Kind: TCodeLocation;
  out Region: NativeUInt): Boolean;
begin
  Kind := clUnknown;
  Region := 0;
  {$IFDEF NHW_NATIVE5H_TESTS}
  if Assigned(IndirectDescribeHook) then
    Result := IndirectDescribeHook(Address, Kind, Region)
  else
  {$ENDIF}
    Result := DescribeCodeAddress(Address, Kind, Region);
  Result := Result and (Address <> 0) and (Region <> 0) and
    (Region <= Address) and (Kind <> clUnknown);
end;

procedure ClearIndirectCandidate(var Item: TIndirectTarget);
begin
  Item.Observed := 0;
  Item.OriginalRegion := 0;
  Item.ObservedRegion := 0;
  Item.LastValid := 0;
  Item.Confirmations := 0;
  // Expected is an approved registration, not a pending candidate.
end;

function IndirectTargetCandidate(OriginalIsImage, CurrentIsPrivate:
  Boolean; Confirmations: Byte; Independent, EpochStable: Boolean): Boolean;
begin
  Result := OriginalIsImage and CurrentIsPrivate and
    (Confirmations >= 2) and Independent and EpochStable;
end;

constructor TIndirectTargetMonitor.Create;
begin inherited Create; Reset; end;

procedure TIndirectTargetMonitor.Reset;
var I: Integer;
begin
  FEpoch := 0;
  FLastReport := 0;
  for I := 0 to 2 do FItems[I] := Default(TIndirectTarget);
end;

procedure TIndirectTargetMonitor.InvalidateCandidates;
var I: Integer;
begin
  for I := 0 to 2 do ClearIndirectCandidate(FItems[I]);
end;

procedure TIndirectTargetMonitor.Examine(OwnTarget,
  Baseline, EpochStable: Boolean; Epoch: Cardinal;
  Callback, RecordCallback, BufferCallback: NativeUInt;
  const Kinds: TDetectionKinds; Tick: UInt64;
  var Detected: TDetectionKinds);
var
  Values: array[0..2] of NativeUInt;
  I: Integer;
  OriginalRegion, CurrentRegion: NativeUInt;
  Independent: Boolean;

  function TryObserveRelationship: Boolean;
  var
    Kind, OriginalKind: TCodeLocation;
  begin
    if Values[I] = 0 then
    begin ClearIndirectCandidate(FItems[I]); Exit(False); end;
    if FItems[I].Expected = 0 then
    begin
      // Do not approve a nonzero address whose metadata is unavailable.
      if QueryIndirectCode(Values[I], Kind, CurrentRegion) then
        FItems[I].Expected := Values[I];
      ClearIndirectCandidate(FItems[I]);
      Exit(False);
    end;
    if Baseline or (Values[I] = FItems[I].Expected) then
    begin ClearIndirectCandidate(FItems[I]); Exit(False); end;
    if not QueryIndirectCode(FItems[I].Expected, OriginalKind, OriginalRegion) then
    begin ClearIndirectCandidate(FItems[I]); Exit(False); end;
    if not QueryIndirectCode(Values[I], Kind, CurrentRegion) then
    begin ClearIndirectCandidate(FItems[I]); Exit(False); end;
    if (OriginalKind <> clImage) or (Kind <> clPrivate) then
    begin ClearIndirectCandidate(FItems[I]); Exit(False); end;
    Result := True;
  end;

  procedure UpdateIndirectCandidate;
  var
    SameCandidate: Boolean;
  begin
    // Count only two fully validated observations of the SAME relationship.
    SameCandidate := (FItems[I].Confirmations <> 0) and
      (FItems[I].Observed = Values[I]) and
      (FItems[I].OriginalRegion = OriginalRegion) and
      (FItems[I].ObservedRegion = CurrentRegion) and
      (Tick >= FItems[I].LastValid);
    if not SameCandidate then
    begin
      FItems[I].Observed := Values[I];
      FItems[I].OriginalRegion := OriginalRegion;
      FItems[I].ObservedRegion := CurrentRegion;
      FItems[I].Confirmations := 1;
    end
    else if (Tick > FItems[I].LastValid) and (FItems[I].Confirmations < 2) then
      Inc(FItems[I].Confirmations);
    FItems[I].LastValid := Tick;
  end;

  procedure ReportIndirectCandidate;
  begin
    if IndirectTargetCandidate(True, True, FItems[I].Confirmations,
      Independent, EpochStable) and
      ((FLastReport = 0) or (Tick < FLastReport) or
       (Tick - FLastReport >= 60000)) then
    begin
      Include(Detected, dkIndirectTarget);
      FLastReport := Tick;
    end;
  end;

begin
  if not OwnTarget then begin Reset; Exit; end;
  if (Epoch = 0) or not EpochStable then
  begin InvalidateCandidates; Exit; end;
  if FEpoch <> Epoch then
  begin Reset; FEpoch := Epoch; end;
  Values[0] := Callback;
  Values[1] := RecordCallback;
  Values[2] := BufferCallback;
  Independent := (Kinds * [dkIAT, dkFunctionPointer, dkCallback,
    dkImportRedirect, dkTLSCallbackIntegrity, dkControlFlow]) <> [];
  try
    for I := 0 to 2 do
    begin
      if not TryObserveRelationship then Continue;
      UpdateIndirectCandidate;
      ReportIndirectCandidate;
    end;
  except
    InvalidateCandidates;
    raise;
  end;
end;

{$IFDEF NHW_NATIVE5H_TESTS}
{$I Cozy.NHW.Native5H.IndirectTargets.inc}
{$ENDIF}
end.
