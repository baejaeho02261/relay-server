unit Cozy.NHW.DriverServiceTimeline;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  System.Generics.Collections,
  Cozy.NHW.Logging,
  Cozy.NHW.KernelTrust.Native,
  Cozy.NHW.KernelTrust.PlatformNative;

type
  TDriverServiceTimelineEntry = record
    FirstSeen: UInt64;
    LastSeen: UInt64;
    LoadedObserved: Boolean;
    RiskTagged: Boolean;
    MissingScans: Byte;
  end;

  TDriverServiceTimelineMonitor = class
  private
    FPrimed: Boolean;
    FKnown: TDictionary<string, Byte>;
    FTracked: TDictionary<string, TDriverServiceTimelineEntry>;
    FLastReport: UInt64;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure Examine(const Services: TDriverServiceInfos; ServicesValid: Boolean;
      const Modules: TKernelModuleInfos; ModulesValid, RiskEvidence: Boolean;
      Tick: UInt64; var Detected: TDetectionKinds);
  end;

function DriverServiceTimelineCandidate(LoadedObserved, RiskTagged: Boolean;
  LifetimeMS: UInt64; MissingScans: Byte): Boolean;

implementation

uses System.SysUtils;

const
  SERVICE_TRANSIENT_MAX_MS = 90000;
  SERVICE_MISSING_CONFIRMATIONS = 2;
  SERVICE_REPORT_MS = 60000;

function DriverServiceTimelineCandidate(LoadedObserved, RiskTagged: Boolean;
  LifetimeMS: UInt64; MissingScans: Byte): Boolean;
begin
  Result := LoadedObserved and RiskTagged and
    (LifetimeMS <= SERVICE_TRANSIENT_MAX_MS) and
    (MissingScans >= SERVICE_MISSING_CONFIRMATIONS);
end;

function ServicePresent(const Services: TDriverServiceInfos;
  const Key: string): Boolean;
var S: TDriverServiceInfo;
begin
  for S in Services do
    if SameText(DriverServiceKey(S), Key) then Exit(True);
  Result := False;
end;


function FindServiceByKey(const Services: TDriverServiceInfos;
  const Key: string; out Service: TDriverServiceInfo): Boolean;
var S: TDriverServiceInfo;
begin
  Service := Default(TDriverServiceInfo);
  for S in Services do
    if SameText(DriverServiceKey(S), Key) then
    begin
      Service := S;
      Exit(True);
    end;
  Result := False;
end;

function ServiceHasLoadedModule(const S: TDriverServiceInfo;
  const Modules: TKernelModuleInfos): Boolean;
var M: TKernelModuleInfo;
begin
  for M in Modules do
    if DriverServiceMatchesModule(S, M) then Exit(True);
  Result := False;
end;

constructor TDriverServiceTimelineMonitor.Create;
begin
  inherited Create;
  FKnown := TDictionary<string, Byte>.Create;
  FTracked := TDictionary<string, TDriverServiceTimelineEntry>.Create;
  Reset;
end;

destructor TDriverServiceTimelineMonitor.Destroy;
begin
  FTracked.Free;
  FKnown.Free;
  inherited Destroy;
end;

procedure TDriverServiceTimelineMonitor.Reset;
begin
  FPrimed := False;
  FKnown.Clear;
  FTracked.Clear;
  FLastReport := 0;
end;

procedure TDriverServiceTimelineMonitor.Examine(const Services: TDriverServiceInfos;
  ServicesValid: Boolean; const Modules: TKernelModuleInfos;
  ModulesValid, RiskEvidence: Boolean; Tick: UInt64;
  var Detected: TDetectionKinds);
var S, CurrentService: TDriverServiceInfo; K: string; E: TDriverServiceTimelineEntry;
  Keys: TArray<string>; Life: UInt64; CanReport: Boolean;
begin
  if not ServicesValid or not ModulesValid then Exit;
  if not FPrimed then
  begin
    for S in Services do FKnown.AddOrSetValue(DriverServiceKey(S), 1);
    FPrimed := True;
    Exit;
  end;

  for S in Services do
  begin
    K := DriverServiceKey(S);
    if FKnown.ContainsKey(K) then Continue;
    FKnown.AddOrSetValue(K, 1);
    E := Default(TDriverServiceTimelineEntry);
    E.FirstSeen := Tick;
    E.LastSeen := Tick;
    E.LoadedObserved := ServiceHasLoadedModule(S, Modules);
    E.RiskTagged := RiskEvidence;
    FTracked.AddOrSetValue(K, E);
  end;

  Keys := FTracked.Keys.ToArray;
  for K in Keys do
  begin
    if not FTracked.TryGetValue(K, E) then Continue;
    if FindServiceByKey(Services, K, CurrentService) then
    begin
      E.LastSeen := Tick;
      if not E.LoadedObserved then
        E.LoadedObserved := ServiceHasLoadedModule(CurrentService, Modules);
      if RiskEvidence then E.RiskTagged := True;
      E.MissingScans := 0;
      FTracked.AddOrSetValue(K, E);
      Continue;
    end;
    if E.MissingScans < High(Byte) then Inc(E.MissingScans);
    if Tick < E.FirstSeen then Life := High(UInt64) else Life := E.LastSeen - E.FirstSeen;
    if DriverServiceTimelineCandidate(E.LoadedObserved, E.RiskTagged,
       Life, E.MissingScans) then
    begin
      CanReport := (FLastReport = 0) or (Tick < FLastReport) or
        (Tick - FLastReport >= SERVICE_REPORT_MS);
      if CanReport then
      begin
        Include(Detected, dkDriverServiceTimeline);
        FLastReport := Tick;
      end;
    end;
    if E.MissingScans >= SERVICE_MISSING_CONFIRMATIONS then
    begin
      FTracked.Remove(K);
      FKnown.Remove(K);
    end
    else
      FTracked.AddOrSetValue(K, E);
  end;
end;

end.
