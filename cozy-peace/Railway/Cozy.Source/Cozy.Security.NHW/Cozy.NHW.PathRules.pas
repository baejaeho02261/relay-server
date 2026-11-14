unit Cozy.NHW.PathRules;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  System.SysUtils,
  System.Generics.Collections,
  Cozy.NHW.Logging;

type
  TPathCategory = (pcDNSServer, pcDNSPolicy, pcWinsock, pcInterface, pcRoute);
  TPathChangeEvent = record
    Kind: TPathCategory;
    Tick: UInt64;
  end;

  // Pure event-order rules, independent of the OS API probes.
  TPathSignalRules = class
  private
    FRecent: TList<TPathChangeEvent>;
    FLastRoute: UInt64;
    FLastDNS: UInt64;
    FLastPair: UInt64;
    FLastBurst: UInt64;
    FLastTick: UInt64;
    FLastKindTick: array[TPathCategory] of UInt64;
    procedure Trim(Tick: UInt64);
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure Signal(Kind: TPathCategory; Tick: UInt64;
      var Detected: TDetectionKinds);
  end;

{$IFDEF NHW_NATIVE10Q_TESTS}
function TestPathRules10Q(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

const
  CORRELATION_MS = 30000;
  REPEAT_WINDOW_MS = 90000;
  BURST_COOLDOWN_MS = 90000;
  PATH_HISTORY_LIMIT = 256;

constructor TPathSignalRules.Create;
begin
  inherited Create;
  FRecent := TList<TPathChangeEvent>.Create;
  Reset;
end;

destructor TPathSignalRules.Destroy;
begin
  FRecent.Free;
  inherited Destroy;
end;

procedure TPathSignalRules.Reset;
begin
  FRecent.Clear;
  FLastRoute := 0;
  FLastDNS := 0;
  FLastPair := 0;
  FLastBurst := 0;
  FLastTick := 0;
  FillChar(FLastKindTick, SizeOf(FLastKindTick), 0);
end;

procedure TPathSignalRules.Trim(Tick: UInt64);
var I: Integer;
begin
  // Inspect every entry rather than assuming an ordered prefix.
  for I := FRecent.Count - 1 downto 0 do
    if (Tick < FRecent[I].Tick) or
       (Tick - FRecent[I].Tick > REPEAT_WINDOW_MS) then FRecent.Delete(I);
end;

procedure RecordPathChange(Rules: TPathSignalRules;
  Kind: TPathCategory; Tick: UInt64);
var Event: TPathChangeEvent;
begin
  Rules.Trim(Tick);
  if Rules.FRecent.Count >= PATH_HISTORY_LIMIT then Rules.FRecent.Delete(0);
  Event.Kind := Kind;
  Event.Tick := Tick;
  Rules.FRecent.Add(Event);
  Rules.FLastTick := Tick;
  Rules.FLastKindTick[Kind] := Tick;
  if Kind = pcRoute then Rules.FLastRoute := Tick;
  if Kind in [pcDNSServer, pcDNSPolicy] then Rules.FLastDNS := Tick;
end;

procedure ReportPathPair(Rules: TPathSignalRules; Tick: UInt64;
  var Detected: TDetectionKinds);
var Later: UInt64;
begin
  if (Rules.FLastRoute = 0) or (Rules.FLastDNS = 0) then Exit;
  if Rules.FLastRoute > Rules.FLastDNS then Later := Rules.FLastRoute
  else Later := Rules.FLastDNS;
  if (Later >= Rules.FLastPair) and (Later <> Rules.FLastPair) and
     (Later - Rules.FLastRoute <= CORRELATION_MS) and
     (Later - Rules.FLastDNS <= CORRELATION_MS) then
  begin
    Include(Detected, dkPathCorrelation);
    Rules.FLastPair := Later;
  end;
end;

function RecentPathKindCount(Rules: TPathSignalRules): Integer;
var
  KindSeen: set of TPathCategory;
  Entry: TPathChangeEvent;
  K: TPathCategory;
begin
  KindSeen := [];
  for Entry in Rules.FRecent do Include(KindSeen, Entry.Kind);
  Result := 0;
  for K := Low(TPathCategory) to High(TPathCategory) do
    if K in KindSeen then Inc(Result);
end;

procedure ReportPathBurst(Rules: TPathSignalRules; Tick: UInt64;
  var Detected: TDetectionKinds);
begin
  // At least 3 separately confirmed changes across >=2 subsystems.
  if (Rules.FRecent.Count >= 3) and (RecentPathKindCount(Rules) >= 2) and
     ((Rules.FLastBurst = 0) or
      ((Tick >= Rules.FLastBurst) and
       (Tick - Rules.FLastBurst >= BURST_COOLDOWN_MS))) then
  begin
    Include(Detected, dkNetworkIntegrity);
    Rules.FLastBurst := Tick;
  end;
end;

procedure TPathSignalRules.Signal(Kind: TPathCategory; Tick: UInt64;
  var Detected: TDetectionKinds);
begin
  if (Ord(Kind) < Ord(Low(TPathCategory))) or
     (Ord(Kind) > Ord(High(TPathCategory))) or (Tick = 0) then Exit;
  if Tick < FLastTick then Exit; // old event does not rewrite the current timeline
  if FLastKindTick[Kind] = Tick then Exit;
  RecordPathChange(Self, Kind, Tick);
  ReportPathPair(Self, Tick, Detected);
  ReportPathBurst(Self, Tick, Detected);
end;

{$IFDEF NHW_NATIVE10Q_TESTS}
{$I Cozy.NHW.Native10Q.PathRules.inc}
{$ENDIF}

end.
