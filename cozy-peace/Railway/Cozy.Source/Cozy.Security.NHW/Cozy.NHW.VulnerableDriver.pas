unit Cozy.NHW.VulnerableDriver;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  System.Generics.Collections,
  Cozy.NHW.Logging,
  Cozy.NHW.KernelTrust.Native;

type
  TVulnerableDriverCandidate = record
    Digest: string;
    Identity: TDriverFileIdentity;
    Confirmations: Byte;
    LastTick: UInt64;
  end;

  TVulnerableDriverMonitor = class
  private
    FPrimed: Boolean;
    FCatalogTried: Boolean;
    FCatalog: TDictionary<string, Byte>;
    FKnown: TDictionary<string, Byte>;
    FChecked: TDictionary<string, TDriverFileIdentity>;
    FPending: TDictionary<string, TVulnerableDriverCandidate>;
    FScanCursor: Integer;
    FLastReport: UInt64;
    FLastConfirmedKey: string;
    FLastConfirmedTick: UInt64;
    procedure EnsureCatalog;
    procedure ReconcilePresence(const Modules: TKernelModuleInfos);
    procedure CheckModule(const M: TKernelModuleInfo; Tick: UInt64;
      var Detected: TDetectionKinds);
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure Examine(const Modules: TKernelModuleInfos; Valid: Boolean;
      Tick: UInt64; var Detected: TDetectionKinds);
    property LastConfirmedModuleKey: string read FLastConfirmedKey;
    property LastConfirmedTick: UInt64 read FLastConfirmedTick;
  end;

function VulnerableDriverCandidate(CatalogMatch: Boolean;
  Confirmations: Byte): Boolean;

implementation

uses
  System.SysUtils;

const
  VULNERABLE_CONFIRMATIONS = 2;
  VULNERABLE_REPORT_MS = 60000;
  BASELINE_HASHES_PER_PASS = 12;

function VulnerableDriverCandidate(CatalogMatch: Boolean;
  Confirmations: Byte): Boolean;
begin
  Result := CatalogMatch and (Confirmations >= VULNERABLE_CONFIRMATIONS);
end;

function ModuleKey(const M: TKernelModuleInfo): string; inline;
begin
  Result := KernelModuleKey(M);
end;

function SameIdentity(const A, B: TDriverFileIdentity): Boolean; inline;
begin
  Result := A.Valid and B.Valid and
    (A.VolumeSerial = B.VolumeSerial) and
    (A.FileIndex = B.FileIndex) and
    (A.FileSize = B.FileSize) and
    (A.WriteTime = B.WriteTime);
end;

function ResolvableDriverPath(const Path: string): Boolean; inline;
begin
  Result := (Length(Path) >= 3) and (Path[2] = ':') and
    ((Path[3] = '\') or (Path[3] = '/'));
end;

constructor TVulnerableDriverMonitor.Create;
begin
  inherited Create;
  FCatalog := TDictionary<string, Byte>.Create;
  FKnown := TDictionary<string, Byte>.Create;
  FChecked := TDictionary<string, TDriverFileIdentity>.Create;
  FPending := TDictionary<string, TVulnerableDriverCandidate>.Create;
  Reset;
end;

destructor TVulnerableDriverMonitor.Destroy;
begin
  FPending.Free;
  FChecked.Free;
  FKnown.Free;
  FCatalog.Free;
  inherited Destroy;
end;

procedure TVulnerableDriverMonitor.Reset;
begin
  FPrimed := False;
  FKnown.Clear;
  FChecked.Clear;
  FPending.Clear;
  FScanCursor := 0;
  FLastReport := 0;
  FLastConfirmedKey := '';
  FLastConfirmedTick := 0;
  // The Microsoft deny-hash catalog is immutable for this process lifetime.
end;

procedure TVulnerableDriverMonitor.EnsureCatalog;
var Hashes: TArray<string>; H: string;
begin
  if FCatalogTried then Exit;
  FCatalogTried := True;
  if not LoadRecommendedDriverDenyHashes(Hashes) then Exit;
  for H in Hashes do
    if Length(H) = 64 then FCatalog.AddOrSetValue(UpperCase(H), 1);
end;

procedure TVulnerableDriverMonitor.ReconcilePresence(
  const Modules: TKernelModuleInfos);
var
  Present: TDictionary<string, Byte>;
  M: TKernelModuleInfo;
  Keys: TArray<string>;
  K: string;
begin
  Present := TDictionary<string, Byte>.Create;
  try
    for M in Modules do Present.AddOrSetValue(ModuleKey(M), 1);
    Keys := FKnown.Keys.ToArray;
    for K in Keys do if not Present.ContainsKey(K) then FKnown.Remove(K);
    Keys := FPending.Keys.ToArray;
    for K in Keys do if not Present.ContainsKey(K) then FPending.Remove(K);
    Keys := FChecked.Keys.ToArray;
    for K in Keys do if not Present.ContainsKey(K) then FChecked.Remove(K);
  finally
    Present.Free;
  end;
end;

procedure TVulnerableDriverMonitor.CheckModule(const M: TKernelModuleInfo;
  Tick: UInt64; var Detected: TDetectionKinds);
var
  K, Digest: string;
  Identity, CheckedIdentity: TDriverFileIdentity;
  C: TVulnerableDriverCandidate;
  CanReport: Boolean;
begin
  if not ResolvableDriverPath(M.Path) then Exit;
  K := ModuleKey(M);
  if not QueryDriverFileIdentity(M.Path, Identity) then Exit; // UNKNOWN

  if FChecked.TryGetValue(K, CheckedIdentity) and
     SameIdentity(Identity, CheckedIdentity) then Exit;

  if FPending.TryGetValue(K, C) and SameIdentity(Identity, C.Identity) then
  begin
    // Do not re-hash the same pending module more than once in one scan tick.
    if Tick = C.LastTick then Exit;
    // Re-hash a pending deny-list candidate before the second confirmation.
    Digest := '';
    if not HashDriverFileSHA256(M.Path, Digest) then Exit;
    Digest := UpperCase(Digest);
    if not SameText(Digest, C.Digest) or not FCatalog.ContainsKey(Digest) then
    begin
      FPending.Remove(K);
      if not FCatalog.ContainsKey(Digest) then FChecked.AddOrSetValue(K, Identity);
      Exit;
    end;
    if Tick > C.LastTick then
    begin
      if C.Confirmations < VULNERABLE_CONFIRMATIONS then Inc(C.Confirmations);
      C.LastTick := Tick;
      FPending.AddOrSetValue(K, C);
    end;
  end
  else
  begin
    Digest := '';
    if not HashDriverFileSHA256(M.Path, Digest) then Exit;
    Digest := UpperCase(Digest);
    if not FCatalog.ContainsKey(Digest) then
    begin
      FPending.Remove(K);
      FChecked.AddOrSetValue(K, Identity);
      Exit;
    end;
    C := Default(TVulnerableDriverCandidate);
    C.Digest := Digest;
    C.Identity := Identity;
    C.Confirmations := 1;
    C.LastTick := Tick;
    FPending.AddOrSetValue(K, C);
  end;

  if not FPending.TryGetValue(K, C) or
     not VulnerableDriverCandidate(True, C.Confirmations) then Exit;
  FLastConfirmedKey := K;
  FLastConfirmedTick := Tick;
  CanReport := (FLastReport = 0) or (Tick < FLastReport) or
    (Tick - FLastReport >= VULNERABLE_REPORT_MS);
  if CanReport then
  begin
    Include(Detected, dkVulnerableDriver);
    FLastReport := Tick;
  end;
end;

procedure TVulnerableDriverMonitor.Examine(const Modules: TKernelModuleInfos;
  Valid: Boolean; Tick: UInt64; var Detected: TDetectionKinds);
var
  M: TKernelModuleInfo;
  I, Passes, Index: Integer;
  K: string;
  WasKnown: Boolean;
begin
  if not Valid then Exit; // unavailable is UNKNOWN; do not mutate baseline
  EnsureCatalog;
  if FCatalog.Count = 0 then Exit;

  ReconcilePresence(Modules);
  if not FPrimed then
  begin
    // Prime presence only. Pre-existing modules are still hash-audited below in
    // bounded batches so a BYOVD loaded before this process is not trusted away.
    for M in Modules do FKnown.AddOrSetValue(ModuleKey(M), 1);
    FPrimed := True;
    FScanCursor := 0;
  end
  else
  begin
    // New module identities are high-priority and checked immediately.
    for M in Modules do
    begin
      K := ModuleKey(M);
      WasKnown := FKnown.ContainsKey(K);
      FKnown.AddOrSetValue(K, 1);
      if not WasKnown then CheckModule(M, Tick, Detected);
    end;
  end;

  // Reconfirm pending deny-list hits every pass instead of waiting for the
  // baseline cursor to cycle through all loaded drivers.
  for M in Modules do
    if FPending.ContainsKey(ModuleKey(M)) then CheckModule(M, Tick, Detected);

  if Length(Modules) = 0 then Exit;
  if FScanCursor >= Length(Modules) then FScanCursor := 0;
  Passes := BASELINE_HASHES_PER_PASS;
  if Passes > Length(Modules) then Passes := Length(Modules);
  for I := 0 to Passes - 1 do
  begin
    Index := (FScanCursor + I) mod Length(Modules);
    CheckModule(Modules[Index], Tick, Detected);
  end;
  FScanCursor := (FScanCursor + Passes) mod Length(Modules);
end;

end.
