unit Cozy.NHW.DriverLoadProvenance;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  System.Generics.Collections,
  Cozy.NHW.Logging,
  Cozy.NHW.KernelTrust.Native,
  Cozy.NHW.KernelTrust.PlatformNative;

type
  TDriverLoadProvenanceMonitor = class
  private
    FPrimed: Boolean;
    FKnown: TDictionary<string, Byte>;
    FPending: TDictionary<string, Byte>;
    FLastReport: UInt64;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure Examine(const Modules: TKernelModuleInfos; ModulesValid: Boolean;
      const Services: TDriverServiceInfos; ServicesValid, Corroborated: Boolean;
      Tick: UInt64; var Detected: TDetectionKinds);
  end;

function DriverLoadProvenanceCandidate(HasService, Corroborated: Boolean;
  Confirmations: Byte): Boolean;

implementation

uses System.SysUtils;

const
  PROVENANCE_CONFIRMATIONS = 3;
  PROVENANCE_REPORT_MS = 60000;

function DriverLoadProvenanceCandidate(HasService, Corroborated: Boolean;
  Confirmations: Byte): Boolean;
begin
  Result := not HasService and Corroborated and
    (Confirmations >= PROVENANCE_CONFIRMATIONS);
end;

constructor TDriverLoadProvenanceMonitor.Create;
begin
  inherited Create;
  FKnown := TDictionary<string, Byte>.Create;
  FPending := TDictionary<string, Byte>.Create;
  Reset;
end;

destructor TDriverLoadProvenanceMonitor.Destroy;
begin
  FPending.Free;
  FKnown.Free;
  inherited Destroy;
end;

procedure TDriverLoadProvenanceMonitor.Reset;
begin
  FPrimed := False;
  FKnown.Clear;
  FPending.Clear;
  FLastReport := 0;
end;

procedure TDriverLoadProvenanceMonitor.Examine(const Modules: TKernelModuleInfos;
  ModulesValid: Boolean; const Services: TDriverServiceInfos;
  ServicesValid, Corroborated: Boolean; Tick: UInt64;
  var Detected: TDetectionKinds);
var M: TKernelModuleInfo; K: string; S: TDriverServiceInfo;
  C: Byte; CanReport: Boolean; Present: TDictionary<string, Byte>;
  Keys: TArray<string>;
begin
  if not ModulesValid or not ServicesValid then Exit;
  if not FPrimed then
  begin
    for M in Modules do FKnown.AddOrSetValue(KernelModuleKey(M), 1);
    FPrimed := True;
    Exit;
  end;

  Present := TDictionary<string, Byte>.Create;
  try
    for M in Modules do Present.AddOrSetValue(KernelModuleKey(M), 1);
    Keys := FPending.Keys.ToArray;
    for K in Keys do
      if not Present.ContainsKey(K) then FPending.Remove(K);

  for M in Modules do
  begin
    K := KernelModuleKey(M);
    if FKnown.ContainsKey(K) then Continue;
    if FindDriverServiceForModule(Services, M, S) then
    begin
      FKnown.AddOrSetValue(K, 1);
      FPending.Remove(K);
      Continue;
    end;
    C := 0;
    FPending.TryGetValue(K, C);
    if not Corroborated then
    begin
      if C <> 0 then FPending.AddOrSetValue(K, 0);
      Continue;
    end;
    if C < High(Byte) then Inc(C);
    FPending.AddOrSetValue(K, C);
    if not DriverLoadProvenanceCandidate(False, True, C) then Continue;
    CanReport := (FLastReport = 0) or (Tick < FLastReport) or
      (Tick - FLastReport >= PROVENANCE_REPORT_MS);
    if CanReport then
    begin
      Include(Detected, dkDriverLoadProvenance);
      FLastReport := Tick;
    end;
  end;
  finally
    Present.Free;
  end;
end;

end.
