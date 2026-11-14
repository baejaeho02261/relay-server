unit Cozy.NHW.ObservationTrust;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows, Cozy.NHW.Logging;

type
  TObservationGrade = (ogUnknown, ogDegraded, ogReliable);

  // v77: visibility quality is metadata, NOT evidence of an adversary.
  TObservationTrust = class
  private
    FConsecutiveDegraded: Byte;
    FLastWarning: UInt64;
    FCurrent: TObservationGrade;
    FHadReliable: Boolean;
    FLastTick: UInt64;
    FHaveTick, FHaveWarning: Boolean;
  public
    constructor Create;
    procedure Reset;
    function Examine(ThreadsValid, IdentityValid, EpochStable,
      TraceAvailable, TraceLost: Boolean; GapMS: UInt64;
      IntervalMS: Cardinal; Tick: UInt64;
      var Detected: TDetectionKinds): TObservationGrade;
    property Current: TObservationGrade read FCurrent;
  end;

function GradeObservation(ThreadsValid, IdentityValid, EpochStable,
  TraceAvailable, TraceLost: Boolean; GapMS: UInt64;
  IntervalMS: Cardinal): TObservationGrade;

{$IFDEF NHW_NATIVE10P_TESTS}
function TestObservationTrust10P(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

{$IFDEF NHW_NATIVE10P_TESTS}
uses System.SysUtils;
{$ENDIF}

function GradeObservation(ThreadsValid, IdentityValid, EpochStable,
  TraceAvailable, TraceLost: Boolean; GapMS: UInt64;
  IntervalMS: Cardinal): TObservationGrade;
var Limit: UInt64;
begin
  Result := ogUnknown;
  if (IntervalMS = 0) or not ThreadsValid or not IdentityValid or not TraceAvailable then Exit;
  Result := ogDegraded;
  if not EpochStable or TraceLost then Exit;
  Limit := IntervalMS;
  if Limit < 250 then Limit := 250;
  // No preceding valid sample => unknown visibility, never reliable.
  if GapMS = 0 then Exit(ogUnknown);
  if GapMS > Limit * 4 then Exit;
  Result := ogReliable;
end;

constructor TObservationTrust.Create;
begin inherited Create; Reset; end;

procedure TObservationTrust.Reset;
begin
  FConsecutiveDegraded := 0;
  FLastWarning := 0;
  FCurrent := ogUnknown;
  FHadReliable := False;
  FLastTick := 0;
  FHaveTick := False;
  FHaveWarning := False;
end;

function TObservationTrust.Examine(ThreadsValid, IdentityValid,
  EpochStable, TraceAvailable, TraceLost: Boolean; GapMS: UInt64;
  IntervalMS: Cardinal; Tick: UInt64;
  var Detected: TDetectionKinds): TObservationGrade;
var
  Limit: UInt64;
  Gap: Boolean;
  Grade: TObservationGrade;

  function HandleNonForwardTick: Boolean;
  begin
    Result := FHaveTick and (Tick <= FLastTick);
    if not Result then Exit;
    if Tick < FLastTick then
    begin
      Reset;
      FHaveTick := True;
      FLastTick := Tick;
    end
    else if Grade <> FCurrent then
    begin
      FCurrent := ogUnknown;
      FConsecutiveDegraded := 0;
    end;
  end;

  procedure ApplyObservationState;
  begin
    if Gap then FConsecutiveDegraded := 0;
    FCurrent := Grade;
    if Gap and (FCurrent = ogReliable) then FCurrent := ogUnknown;
    if FCurrent = ogReliable then
    begin
      FConsecutiveDegraded := 0;
      FHadReliable := True;
    end
    else if not Gap and FHadReliable and (FConsecutiveDegraded < 255) then
      Inc(FConsecutiveDegraded);
  end;

  procedure ReportDegradedObservation;
  begin
    // Do not reinterpret unavailable ETW as an attack. Mark a sustained
    // degraded observation window as a sampling warning only.
    if FHadReliable and (FConsecutiveDegraded >= 3) and
       ((not FHaveWarning) or (Tick < FLastWarning) or
        (Tick - FLastWarning >= 30000)) then
    begin
      Include(Detected, dkObservationUncertain);
      FLastWarning := Tick;
      FHaveWarning := True;
    end;
  end;
begin
  Grade := GradeObservation(ThreadsValid, IdentityValid,
    EpochStable, TraceAvailable, TraceLost, GapMS, IntervalMS);
  if HandleNonForwardTick then Exit(FCurrent);
  Limit := IntervalMS;
  if Limit < 250 then Limit := 250;
  Gap := FHaveTick and (Tick - FLastTick > Limit * 4);
  FLastTick := Tick;
  FHaveTick := True;
  if (IntervalMS = 0) or (GapMS = 0) or (GapMS > Limit * 4) then Gap := True;
  ApplyObservationState;
  ReportDegradedObservation;
  Result := FCurrent;
end;

{$IFDEF NHW_NATIVE10P_TESTS}
{$I Cozy.NHW.Native10P.ObservationTrust.inc}
{$ENDIF}

end.
