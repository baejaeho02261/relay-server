unit Cozy.NHW.PERules;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  Cozy.NHW.SelfRules,
  Cozy.NHW.ExceptionRules;

type
  // Successful memory queries are distinct from malformed metadata.
  // A temporarily unreadable page is UNKNOWN, never a tamper indicator.
  TPEFeature = record
    Available: Boolean;
    Valid: Boolean;
    Digest: UInt64;
  end;

  TPEImageSnapshot = record
    Header: TPEFeature;
    Sections: TPEFeature;
    Relocations: TPEFeature;
    TLSDirectory: TPEFeature;
    LoadConfig: TPEFeature;
    Directories: TPEFeature;
  end;

  TPEWatchCell = record
    Fingerprint: TStableFingerprint;
    Invalid: TConfirmedCondition;
  end;

function PERangeInImage(RVA, Span, ImageSize: Cardinal): Boolean;
function PEHashByte(Hash: UInt64; Value: Byte): UInt64;
function PEHashInteger(Hash, Value: UInt64): UInt64;
procedure PEObservationGap(var Cell: TPEWatchCell);
function PEObserve(var Cell: TPEWatchCell;
  const Feature: TPEFeature; Baseline: Boolean): Boolean;

{$IFDEF NHW_NATIVE10N_TESTS}
function TestPERules10N(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

{$IFDEF NHW_NATIVE10N_TESTS}
uses System.SysUtils;
{$ENDIF}

function PERangeInImage(RVA, Span, ImageSize: Cardinal): Boolean;
begin
  Result := (RVA <= ImageSize) and (Span <= ImageSize - RVA);
end;

function PEHashByte(Hash: UInt64; Value: Byte): UInt64;
begin
  Result := (Hash xor UInt64(Value)) * UInt64($00000100000001B3);
end;

function PEHashInteger(Hash, Value: UInt64): UInt64;
var
  I: Integer;
begin
  Result := Hash;
  for I := 0 to 7 do
  begin
    Result := PEHashByte(Result, Byte(Value and $FF));
    Value := Value shr 8;
  end;
end;

procedure ResetPEFingerprintCandidate(var Cell: TPEWatchCell);
begin
  Cell.Fingerprint.CandidateCount := 0;
  if not Cell.Fingerprint.AlreadyReported then
    Cell.Fingerprint.Candidate := Cell.Fingerprint.Baseline;
end;

procedure PEObservationGap(var Cell: TPEWatchCell);
begin
  ResetPEFingerprintCandidate(Cell);
  // A gap is not proof that a reported error has disappeared.
  Cell.Invalid.Consecutive := 0;
end;

function ObserveValidPEFeature(var Cell: TPEWatchCell;
  const Feature: TPEFeature; Baseline: Boolean): Boolean;
begin
  Result := False;
  ConfirmExceptionCondition(Cell.Invalid, False);
  if Baseline then
  begin
    PEObservationGap(Cell);
    if not Cell.Fingerprint.HasBaseline then
      ObserveFingerprint(Cell.Fingerprint, Feature.Digest, True);
    Exit;
  end;
  Result := ObserveFingerprint(Cell.Fingerprint, Feature.Digest, True);
end;

function ObserveInvalidPEFeature(var Cell: TPEWatchCell;
  Baseline: Boolean): Boolean;
begin
  Result := False;
  // Structural invalidity is a separate candidate, not a digest observation.
  ResetPEFingerprintCandidate(Cell);
  if Cell.Fingerprint.HasBaseline and (not Baseline) then
    Result := ConfirmExceptionCondition(Cell.Invalid, True)
  else
    Cell.Invalid.Consecutive := 0;
end;

function PEObserve(var Cell: TPEWatchCell;
  const Feature: TPEFeature; Baseline: Boolean): Boolean;
begin
  Result := False;
  if not Feature.Available then
  begin
    PEObservationGap(Cell);
    Exit;
  end;
  if Feature.Valid then
    Result := ObserveValidPEFeature(Cell, Feature, Baseline)
  else
    Result := ObserveInvalidPEFeature(Cell, Baseline);
end;

{$IFDEF NHW_NATIVE10N_TESTS}
{$I Cozy.NHW.Native10N.PERules.inc}
{$ENDIF}

end.
