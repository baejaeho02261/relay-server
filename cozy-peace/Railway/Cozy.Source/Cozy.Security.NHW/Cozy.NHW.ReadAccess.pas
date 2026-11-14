unit Cozy.NHW.ReadAccess;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows, System.Generics.Collections, Cozy.NHW.Types,
  Cozy.NHW.Logging;

type
  TCanaryObservationState = (cosUnknown, cosArming, cosGuarded, cosUnguarded);
  TReadAccessMonitor = class
  private
    FCanary: Pointer;
    FCanaryActive: Boolean;
    FGuardBaseline: Boolean;
    FPreviousGuarded: Boolean;
    FCanaryState: TCanaryObservationState;
    FLastCanaryCheck: UInt64;
    FNextRearmTick: UInt64;
    FLastReadCapabilityTick: UInt64;
    FLastFreshReadTick: UInt64;
    FReadSeenThisSnapshot: Boolean;
    FReadEpisodes: TList<UInt64>;
    FLastReadEpisodeTick: UInt64;
    FCanaryEpisodes: TList<UInt64>;
    FLastPatternTick: UInt64;
    FLastReadGapTick: UInt64;
    FLastCorrelationTick: UInt64;
    procedure BreakCanaryCoverage;
    procedure TryRearmCanary(Tick: UInt64);
    procedure PruneEpisodes(History: TList<UInt64>; Tick: UInt64);
    procedure RecordEpisode(History: TList<UInt64>; Tick: UInt64);
    procedure CheckPattern(Tick: UInt64; var Detected: TDetectionKinds);
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset(TargetPID: Cardinal);
    procedure BeginSnapshot;
    procedure ObserveHolder(const H: TTargetHolder;
      First, WasInactive, InBaseline: Boolean;
      PreviousRights: Cardinal; Tick: UInt64;
      var Detected: TDetectionKinds);
    procedure EndSnapshot;
    function CanaryAddress: NativeUInt;
    procedure ExamineCanary(TargetPID: Cardinal; Tick: UInt64;
      var Detected: TDetectionKinds);
    procedure ExamineSampling(const Stats: TScanStats;
      IntervalMS: Cardinal; Tick: UInt64; var Detected: TDetectionKinds);
  end;

{$IFDEF NHW_NATIVE5I_TESTS}
function TestReadAccess5I(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  Cozy.NHW.ReadRules, Cozy.NHW.ReadCanaryNative, Cozy.NHW.WinPointers
{$IFDEF NHW_NATIVE5I_TESTS}
  , System.SysUtils
{$ENDIF}
  ;

{$IFDEF NHW_NATIVE5I_TESTS}
type
  TCanaryQueryHook = function(Page: Pointer; out Guarded: Boolean): Boolean;
  TCanaryArmHook = function(Page: Pointer): Boolean;
var
  CanaryQueryHook: TCanaryQueryHook;
  CanaryArmHook: TCanaryArmHook;
{$ENDIF}

function ReadGuardState(Page: Pointer; out Guarded: Boolean): Boolean;
begin
  Guarded := False;
{$IFDEF NHW_NATIVE5I_TESTS}
  if Assigned(CanaryQueryHook) then Exit(CanaryQueryHook(Page, Guarded));
{$ENDIF}
  Result := QueryReadCanary(Page, Guarded);
end;

function RearmGuardPage(Page: Pointer): Boolean;
begin
{$IFDEF NHW_NATIVE5I_TESTS}
  if Assigned(CanaryArmHook) then Exit(CanaryArmHook(Page));
{$ENDIF}
  Result := ArmReadCanary(Page);
end;

const
  CANARY_SAMPLE_MS = 500;
  CANARY_REARM_MS = 1200;
  PATTERN_COOLDOWN_MS = 10000;
  GAP_COOLDOWN_MS = 5000;
  CORRELATION_COOLDOWN_MS = 3000;

constructor TReadAccessMonitor.Create;
begin
  inherited Create;
  FReadEpisodes := TList<UInt64>.Create;
  FCanaryEpisodes := TList<UInt64>.Create;
  Reset(0);
end;

destructor TReadAccessMonitor.Destroy;
begin
  ReleaseReadCanary(FCanary);
  FCanaryEpisodes.Free;
  FReadEpisodes.Free;
  inherited Destroy;
end;

procedure TReadAccessMonitor.Reset(TargetPID: Cardinal);
begin
  ReleaseReadCanary(FCanary);
  FCanaryActive := False;
  FGuardBaseline := False;
  FPreviousGuarded := False;
  FCanaryState := cosUnknown;
  FLastCanaryCheck := 0;
  FNextRearmTick := 0;
  FLastReadCapabilityTick := 0;
  FLastFreshReadTick := 0;
  FReadSeenThisSnapshot := False;
  FReadEpisodes.Clear;
  FLastReadEpisodeTick := 0;
  FCanaryEpisodes.Clear;
  FLastPatternTick := 0;
  FLastReadGapTick := 0;
  FLastCorrelationTick := 0;
  // One private canary belonging to this console only. No remote allocation.
  if (TargetPID <> 0) and (TargetPID = WinCurrentProcessId) then
    FCanaryActive := CreateReadCanary(FCanary);
end;

procedure TReadAccessMonitor.BeginSnapshot;
begin
  FReadSeenThisSnapshot := False;
end;

procedure TReadAccessMonitor.PruneEpisodes(History: TList<UInt64>; Tick: UInt64);
var I: Integer;
begin
  for I := History.Count - 1 downto 0 do
    if (Tick < History[I]) or (Tick - History[I] > READ_WINDOW_MS) then
      History.Delete(I);
  while History.Count > 64 do History.Delete(0);
end;

procedure TReadAccessMonitor.RecordEpisode(History: TList<UInt64>; Tick: UInt64);
begin
  History.Add(Tick);
  PruneEpisodes(History, Tick);
end;

procedure TReadAccessMonitor.CheckPattern(Tick: UInt64;
  var Detected: TDetectionKinds);
begin
  // Prune BOTH histories: a new canary event must not revive old handle events.
  PruneEpisodes(FReadEpisodes, Tick);
  PruneEpisodes(FCanaryEpisodes, Tick);
  if (FReadEpisodes.Count < READ_PATTERN_EPISODES) and
     (FCanaryEpisodes.Count < CANARY_PATTERN_EPISODES) then Exit;
  if (FLastPatternTick <> 0) and
     (Tick >= FLastPatternTick) and
     (Tick - FLastPatternTick < PATTERN_COOLDOWN_MS) then Exit;
  Include(Detected, dkReadPattern);
  FLastPatternTick := Tick;
  FReadEpisodes.Clear;
  FLastReadEpisodeTick := 0;
  FCanaryEpisodes.Clear;
end;

procedure TReadAccessMonitor.ObserveHolder(const H: TTargetHolder;
  First, WasInactive, InBaseline: Boolean;
  PreviousRights: Cardinal; Tick: UInt64;
  var Detected: TDetectionKinds);
begin
  if not ReadCapable(H.IsThread, H.RightsUnion) then Exit;
  FReadSeenThisSnapshot := True;
  FLastReadCapabilityTick := Tick;
  if InBaseline then Exit;
  if NewlyReadCapable(H.IsThread, First, WasInactive,
      PreviousRights, H.RightsUnion) then
  begin
    Include(Detected, dkReadAccess);
    FLastFreshReadTick := Tick;
    // One episode per snapshot; multiple simultaneous owners are not a
    // repeated access pattern on their own.
    if Tick <> FLastReadEpisodeTick then
    begin
      FLastReadEpisodeTick := Tick;
      RecordEpisode(FReadEpisodes, Tick);
      CheckPattern(Tick, Detected);
    end;
  end;
end;

procedure TReadAccessMonitor.EndSnapshot;
begin
  // Keep FReadSeenThisSnapshot valid for the current scan's coverage check.
  // BeginSnapshot resets it when the next valid snapshot starts.
end;

function TReadAccessMonitor.CanaryAddress: NativeUInt;
begin
  if FCanaryActive then Result := NativeUInt(FCanary)
  else Result := 0;
end;

procedure TReadAccessMonitor.BreakCanaryCoverage;
begin
  FGuardBaseline := False;
  FPreviousGuarded := False;
  FCanaryState := cosUnknown;
  FCanaryEpisodes.Clear;
  FLastFreshReadTick := 0; // do not bridge handle/canary correlation over a gap
  // Valid handle episodes and independent sampling coverage are retained.
end;

procedure TReadAccessMonitor.TryRearmCanary(Tick: UInt64);
begin
  if Tick < FNextRearmTick then Exit;
  if Tick > High(UInt64) - CANARY_REARM_MS then
    FNextRearmTick := High(UInt64)
  else FNextRearmTick := Tick + CANARY_REARM_MS;
  if RearmGuardPage(FCanary) then
  begin
    // An arm API success is not an observed guarded baseline. The next
    // successful QueryReadCanary must establish it before any loss is counted.
    FCanaryState := cosArming;
    FGuardBaseline := False;
    FPreviousGuarded := False;
  end
  else BreakCanaryCoverage;
end;

procedure TReadAccessMonitor.ExamineCanary(TargetPID: Cardinal;
  Tick: UInt64; var Detected: TDetectionKinds);
var
  Guarded: Boolean;

  procedure EstablishGuardObservation;
  begin
    if Guarded then
    begin
      FGuardBaseline := True;
      FPreviousGuarded := True;
      FCanaryState := cosGuarded;
    end
    else
    begin
      FCanaryState := cosUnguarded;
      TryRearmCanary(Tick);
    end;
  end;

  procedure ObserveGuardLoss;
  begin
    if CanaryGuardLost(FGuardBaseline, FPreviousGuarded, True, Guarded) then
    begin
      Include(Detected, dkCanaryAccess);
      RecordEpisode(FCanaryEpisodes, Tick);
      CheckPattern(Tick, Detected);
      if RecentObservation(Tick, FLastFreshReadTick, READ_CORRELATION_MS) and
         ((FLastCorrelationTick = 0) or
          ((Tick >= FLastCorrelationTick) and
           (Tick - FLastCorrelationTick >= CORRELATION_COOLDOWN_MS))) then
      begin
        Include(Detected, dkReadCorrelation);
        FLastCorrelationTick := Tick;
      end;
      if Tick > High(UInt64) - CANARY_REARM_MS then
        FNextRearmTick := High(UInt64)
      else FNextRearmTick := Tick + CANARY_REARM_MS;
    end;
  end;

  procedure ApplyObservedGuardState;
  begin
    FPreviousGuarded := Guarded;
    if Guarded then FCanaryState := cosGuarded
    else
    begin
      FCanaryState := cosUnguarded;
      TryRearmCanary(Tick);
    end;
  end;

begin
  if not FCanaryActive or (TargetPID <> WinCurrentProcessId) then Exit;
  if (FLastCanaryCheck <> 0) and (Tick >= FLastCanaryCheck) and
     (Tick - FLastCanaryCheck < CANARY_SAMPLE_MS) then Exit;
  if Tick < FLastCanaryCheck then
  begin
    BreakCanaryCoverage;
    FNextRearmTick := 0;
  end;
  FLastCanaryCheck := Tick;
  try
    if not ReadGuardState(FCanary, Guarded) then
    begin
      BreakCanaryCoverage;
      Exit;
    end;
    if not FGuardBaseline then
    begin
      EstablishGuardObservation;
      Exit;
    end;
    ObserveGuardLoss;
    ApplyObservedGuardState;
  except
    BreakCanaryCoverage;
    raise;
  end;
end;

procedure TReadAccessMonitor.ExamineSampling(const Stats: TScanStats;
  IntervalMS: Cardinal; Tick: UInt64;
  var Detected: TDetectionKinds);
begin
  if not SamplingGapRelevant(Stats.ScanMS, Stats.GapMS, IntervalMS) then Exit;
  // This is a coverage warning, NEVER evidence of a successful memory read.
  if not FReadSeenThisSnapshot and
     not RecentObservation(Tick, FLastReadCapabilityTick, 3000) then Exit;
  if (FLastReadGapTick <> 0) and (Tick >= FLastReadGapTick) and
     (Tick - FLastReadGapTick < GAP_COOLDOWN_MS) then Exit;
  Include(Detected, dkReadGap);
  FLastReadGapTick := Tick;
end;

{$IFDEF NHW_NATIVE5I_TESTS}
{$I Cozy.NHW.Native5I.ReadAccess.inc}
{$ENDIF}

end.
