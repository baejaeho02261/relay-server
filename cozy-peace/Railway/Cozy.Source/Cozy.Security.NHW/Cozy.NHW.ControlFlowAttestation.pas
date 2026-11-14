unit Cozy.NHW.ControlFlowAttestation;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows, Cozy.NHW.Logging;

type
  TControlFlowAttestation = class
  private
    FExpected: array[0..2] of NativeUInt;
    FLastObserved: array[0..2] of NativeUInt;
    FConfirm: array[0..2] of Integer;
    FObservedRegion: array[0..2] of NativeUInt;
    FConfirmTick: array[0..2] of UInt64;
    FHasScan: Boolean;
    FLastScan: UInt64;
    FLastReport: UInt64;
    procedure ClearCandidate(Index: Integer);
  public
    constructor Create;
    procedure Reset;
    procedure Examine(Baseline, IndependentEvidence: Boolean;
      Callback, TraceRecordCallback, TraceBufferCallback: NativeUInt;
      Tick: UInt64; var Detected: TDetectionKinds);
  end;

function CallbackAttestationCandidate(Original, Current: NativeUInt;
  InPrivateCode: Boolean; Confirmations: Integer;
  IndependentEvidence: Boolean): Boolean;

{$IFDEF NHW_NATIVE5G_TESTS}
function TestControlFlowHardening(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses System.SysUtils, Cozy.NHW.PEView;

{$IFDEF NHW_NATIVE5G_TESTS}
type TControlDescribeHook = function(Address: NativeUInt;
  out Kind: TCodeLocation; out Region: NativeUInt): Boolean;
var ControlDescribeHook: TControlDescribeHook = nil;
{$ENDIF}

function ControlDescribe(Address: NativeUInt; out Kind: TCodeLocation;
  out Region: NativeUInt): Boolean;
begin
  Kind := clUnknown;
  Region := 0;
{$IFDEF NHW_NATIVE5G_TESTS}
  if Assigned(ControlDescribeHook) then
    Exit(ControlDescribeHook(Address, Kind, Region));
{$ENDIF}
  Result := DescribeCodeAddress(Address, Kind, Region);
end;

function CallbackAttestationCandidate(Original, Current: NativeUInt;
  InPrivateCode: Boolean; Confirmations: Integer;
  IndependentEvidence: Boolean): Boolean;
begin
  Result := (Original <> 0) and (Current <> 0) and
    (Original <> Current) and InPrivateCode and
    (Confirmations >= 2) and IndependentEvidence;
end;

constructor TControlFlowAttestation.Create;
begin inherited Create; Reset; end;

procedure TControlFlowAttestation.ClearCandidate(Index: Integer);
begin
  FLastObserved[Index] := 0;
  FConfirm[Index] := 0;
  FObservedRegion[Index] := 0;
  FConfirmTick[Index] := 0;
end;

procedure TControlFlowAttestation.Reset;
var I: Integer;
begin
  FLastScan := 0;
  FLastReport := 0;
  FHasScan := False;
  for I := 0 to 2 do
  begin
    FExpected[I] := 0;
    ClearCandidate(I);
  end;
end;

procedure TControlFlowAttestation.Examine(Baseline,
  IndependentEvidence: Boolean; Callback, TraceRecordCallback,
  TraceBufferCallback: NativeUInt; Tick: UInt64;
  var Detected: TDetectionKinds);
var
  Values: array[0..2] of NativeUInt;
  I: Integer;
  Kind: TCodeLocation;
  Region: NativeUInt;

  function TryObserveCallback: Boolean;
  var
    J: Integer;
    QueryOK: Boolean;
  begin
    if Values[I] = 0 then Exit(False);
    if (FExpected[I] <> 0) and
      (Baseline or (Values[I] = FExpected[I])) then
    begin ClearCandidate(I); Exit(False); end;
    try
      QueryOK := ControlDescribe(Values[I], Kind, Region);
    except
      for J := 0 to 2 do ClearCandidate(J);
      raise;
    end;
    if not QueryOK or (Region = 0) or (Region > Values[I]) or
      (Kind = clUnknown) then
    begin ClearCandidate(I); Exit(False); end;
    if FExpected[I] = 0 then
    begin
      FExpected[I] := Values[I];
      ClearCandidate(I);
      Exit(False); // establish only a successfully described registration
    end;
    if Kind <> clPrivate then
    begin ClearCandidate(I); Exit(False); end;
    Result := True;
  end;

  procedure UpdateCallbackCandidate;
  begin
    if (FLastObserved[I] <> Values[I]) or
      (FObservedRegion[I] <> Region) or (Tick < FConfirmTick[I]) then
      ClearCandidate(I);
    FLastObserved[I] := Values[I];
    FObservedRegion[I] := Region;
    if (FConfirm[I] = 0) or (Tick > FConfirmTick[I]) then
    begin
      if FConfirm[I] < 2 then Inc(FConfirm[I]);
      FConfirmTick[I] := Tick;
    end;
  end;

  procedure ReportCallbackCandidate;
  begin
    if CallbackAttestationCandidate(FExpected[I], Values[I],
      True, FConfirm[I], IndependentEvidence) and
      ((FLastReport = 0) or (Tick < FLastReport) or
       (Tick - FLastReport >= 60000)) then
    begin
      Include(Detected, dkControlFlow);
      FLastReport := Tick;
    end;
  end;

begin
  Values[0] := Callback;
  Values[1] := TraceRecordCallback;
  Values[2] := TraceBufferCallback;
  // A disappearance/baseline invalidates pending evidence even on a throttled
  // call. A skipped query, by contrast, is not a failed query.
  for I := 0 to 2 do
    if Baseline or (Values[I] = 0) then ClearCandidate(I);
  if FHasScan and (Tick < FLastScan) then
  begin
    for I := 0 to 2 do ClearCandidate(I);
    FLastReport := 0;
  end;
  if FHasScan and (Tick >= FLastScan) and
    (Tick - FLastScan < 4000) then Exit;
  FLastScan := Tick;
  FHasScan := True;
  for I := 0 to 2 do
  begin
    if not TryObserveCallback then Continue;
    UpdateCallbackCandidate;
    ReportCallbackCandidate;
  end;
end;

{$IFDEF NHW_NATIVE5G_TESTS}
{$I Cozy.NHW.Native5G.ControlFlow.inc}
{$ENDIF}

end.
