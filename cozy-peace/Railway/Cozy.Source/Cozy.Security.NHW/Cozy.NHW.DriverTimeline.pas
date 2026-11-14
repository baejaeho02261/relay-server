unit Cozy.NHW.DriverTimeline;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  System.Generics.Collections,
  Cozy.NHW.Logging,
  Cozy.NHW.KernelTrust.Native;

type
  TDriverTimelineEntry = record
    FirstSeen: UInt64;
    LastSeen: UInt64;
    MissingScans: Byte;
    RiskTagged: Boolean;
  end;

  TDriverLoadTimelineMonitor = class
  private
    FPrimed: Boolean;
    FEntries: TDictionary<string, TDriverTimelineEntry>;
    FLastReport: UInt64;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure Examine(const Modules: TKernelModuleInfos; Valid: Boolean;
      const VulnerableModuleKey: string; VulnerableTick, Tick: UInt64;
      var Detected: TDetectionKinds);
  end;

function DriverTimelineCandidate(RiskTagged: Boolean; LifetimeMS: UInt64;
  MissingScans: Byte): Boolean;

implementation

uses
  System.SysUtils;

const
  VULNERABLE_TAG_WINDOW_MS = 30000;
  TRANSIENT_DRIVER_MAX_MS = 60000;
  TIMELINE_MISSING_CONFIRMATIONS = 2;
  TIMELINE_REPORT_MS = 60000;

function DriverTimelineCandidate(RiskTagged: Boolean; LifetimeMS: UInt64;
  MissingScans: Byte): Boolean;
begin
  Result := RiskTagged and (LifetimeMS <= TRANSIENT_DRIVER_MAX_MS) and
    (MissingScans >= TIMELINE_MISSING_CONFIRMATIONS);
end;

constructor TDriverLoadTimelineMonitor.Create;
begin
  inherited Create;
  FEntries := TDictionary<string, TDriverTimelineEntry>.Create;
  Reset;
end;

destructor TDriverLoadTimelineMonitor.Destroy;
begin
  FEntries.Free;
  inherited Destroy;
end;

procedure TDriverLoadTimelineMonitor.Reset;
begin
  FPrimed := False;
  FEntries.Clear;
  FLastReport := 0;
end;

procedure TDriverLoadTimelineMonitor.Examine(const Modules: TKernelModuleInfos;
  Valid: Boolean; const VulnerableModuleKey: string;
  VulnerableTick, Tick: UInt64; var Detected: TDetectionKinds);
var
  Present: TDictionary<string, Byte>;
  Keys: TArray<string>;
  M: TKernelModuleInfo;
  K: string;
  E: TDriverTimelineEntry;
  Lifetime: UInt64;
  CanReport: Boolean;
begin
  if not Valid then Exit;
  Present := TDictionary<string, Byte>.Create;
  try
    for M in Modules do
    begin
      K := KernelModuleKey(M);
      Present.AddOrSetValue(K, 1);
      if not FEntries.TryGetValue(K, E) then
      begin
        E := Default(TDriverTimelineEntry);
        E.FirstSeen := Tick;
      end;
      E.LastSeen := Tick;
      E.MissingScans := 0;
      if (VulnerableModuleKey <> '') and SameText(K, VulnerableModuleKey) and
         (VulnerableTick <> 0) and (Tick >= VulnerableTick) and
         (Tick - VulnerableTick <= VULNERABLE_TAG_WINDOW_MS) then
        E.RiskTagged := True;
      FEntries.AddOrSetValue(K, E);
    end;
    if not FPrimed then
    begin
      FPrimed := True;
      Exit;
    end;
    Keys := FEntries.Keys.ToArray;
    for K in Keys do
    begin
      if Present.ContainsKey(K) then Continue;
      if not FEntries.TryGetValue(K, E) then Continue;
      if E.MissingScans < High(Byte) then Inc(E.MissingScans);
      FEntries.AddOrSetValue(K, E);
      if Tick < E.FirstSeen then Lifetime := High(UInt64)
      else Lifetime := E.LastSeen - E.FirstSeen;
      if DriverTimelineCandidate(E.RiskTagged, Lifetime, E.MissingScans) then
      begin
        CanReport := (FLastReport = 0) or (Tick < FLastReport) or
          (Tick - FLastReport >= TIMELINE_REPORT_MS);
        if CanReport then
        begin
          Include(Detected, dkDriverTimelineKernel);
          FLastReport := Tick;
        end;
      end;
      if E.MissingScans >= TIMELINE_MISSING_CONFIRMATIONS then
        FEntries.Remove(K);
    end;
  finally
    Present.Free;
  end;
end;

end.
