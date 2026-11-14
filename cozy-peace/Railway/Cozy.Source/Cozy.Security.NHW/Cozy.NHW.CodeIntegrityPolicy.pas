unit Cozy.NHW.CodeIntegrityPolicy;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Cozy.NHW.Logging,
  Cozy.NHW.KernelTrust.Native;

type
  TCodeIntegrityPolicySnapshot = record
    Valid: Boolean;
    PolicyCount: Cardinal;
    Fingerprint: UInt64;
    HasSiPolicy: Boolean;
  end;

  TCodeIntegrityPolicyMonitor = class
  private
    FPrimed: Boolean;
    FBaseline: TCodeIntegrityPolicySnapshot;
    FPending: TCodeIntegrityPolicySnapshot;
    FConfirmations: Byte;
    FSafeStable: Byte;
    FLastConfirmTick: UInt64;
    FLastReport: UInt64;
    procedure ClearCandidate;
  public
    constructor Create;
    procedure Reset;
    procedure Examine(const Snapshot: TCodeIntegrityPolicySnapshot;
      RuntimeDowngrade: Boolean; Tick: UInt64;
      var Detected: TDetectionKinds);
  end;

function CaptureCodeIntegrityPolicySnapshot(
  out Snapshot: TCodeIntegrityPolicySnapshot): Boolean;
function CodeIntegrityPolicyChanged(const A,
  B: TCodeIntegrityPolicySnapshot): Boolean;
function CodeIntegrityPolicyReduced(const Baseline,
  Current: TCodeIntegrityPolicySnapshot): Boolean;
function CodeIntegrityPolicyCandidate(Changed, Reduced,
  RuntimeDowngrade: Boolean; Confirmations: Byte): Boolean;

implementation

uses
  System.SysUtils,
  System.Classes;

const
  POLICY_CONFIRMATIONS = 3;
  POLICY_SAFE_ADOPT_CONFIRMATIONS = 6;
  POLICY_REPORT_MS = 60000;
  FNV_OFFSET: UInt64 = $CBF29CE484222325;
  FNV_PRIME: UInt64 = $00000100000001B3;

function FingerprintAdd(H: UInt64; const S: string): UInt64;
var I: Integer; C: Char;
begin
  Result := H;
  for I := 1 to Length(S) do
  begin
    C := S[I];
    Result := (Result xor UInt64(Ord(C) and $FF)) * FNV_PRIME;
    Result := (Result xor UInt64((Ord(C) shr 8) and $FF)) * FNV_PRIME;
  end;
end;

function AddPolicyFile(const Path, Name: string; L: TStringList): Boolean;
var Digest: string; Identity: TDriverFileIdentity;
begin
  Result := False;
  if not QueryDriverFileIdentity(Path, Identity) then Exit;
  if not HashDriverFileSHA256(Path, Digest) then Exit;
  L.Add(LowerCase(Name) + '|' + UpperCase(Digest));
  Result := True;
end;

function CaptureCodeIntegrityPolicySnapshot(
  out Snapshot: TCodeIntegrityPolicySnapshot): Boolean;
var
  Root, Dir, Legacy: string;
  SR: TSearchRec;
  L: TStringList;
  H: UInt64;
  I: Integer;
begin
  Snapshot := Default(TCodeIntegrityPolicySnapshot);
  Result := False;
  Root := GetWindowsRoot;
  if Root = '' then Exit;
  L := TStringList.Create;
  try
    L.CaseSensitive := False;
    L.Sorted := True;
    L.Duplicates := dupIgnore;
    Dir := IncludeTrailingPathDelimiter(Root) +
      'System32\CodeIntegrity\CiPolicies\Active';
    if DirectoryExists(Dir) then
    begin
      if FindFirst(IncludeTrailingPathDelimiter(Dir) + '*.cip',
           faAnyFile, SR) = 0 then
      try
        repeat
          if (SR.Name = '.') or (SR.Name = '..') or
             ((SR.Attr and faDirectory) <> 0) then Continue;
          if not AddPolicyFile(IncludeTrailingPathDelimiter(Dir) + SR.Name,
               SR.Name, L) then Exit;
        until FindNext(SR) <> 0;
      finally
        FindClose(SR);
      end;
    end;
    Legacy := IncludeTrailingPathDelimiter(Root) +
      'System32\CodeIntegrity\SiPolicy.p7b';
    if FileExists(Legacy) then
    begin
      if not AddPolicyFile(Legacy, 'SiPolicy.p7b', L) then Exit;
      Snapshot.HasSiPolicy := True;
    end;
    H := FNV_OFFSET;
    for I := 0 to L.Count - 1 do H := FingerprintAdd(H, L[I]);
    Snapshot.PolicyCount := Cardinal(L.Count);
    Snapshot.Fingerprint := H;
    Snapshot.Valid := True;
    Result := True;
  finally
    L.Free;
  end;
end;

function CodeIntegrityPolicyChanged(const A,
  B: TCodeIntegrityPolicySnapshot): Boolean;
begin
  Result := A.Valid and B.Valid and
    ((A.PolicyCount <> B.PolicyCount) or
     (A.Fingerprint <> B.Fingerprint) or
     (A.HasSiPolicy <> B.HasSiPolicy));
end;

function CodeIntegrityPolicyReduced(const Baseline,
  Current: TCodeIntegrityPolicySnapshot): Boolean;
begin
  Result := Baseline.Valid and Current.Valid and
    ((Current.PolicyCount < Baseline.PolicyCount) or
     (Baseline.HasSiPolicy and not Current.HasSiPolicy));
end;

function CodeIntegrityPolicyCandidate(Changed, Reduced,
  RuntimeDowngrade: Boolean; Confirmations: Byte): Boolean;
begin
  Result := Changed and RuntimeDowngrade and
    (Confirmations >= POLICY_CONFIRMATIONS);
  if Result and (not Reduced) then
    Result := Confirmations >= POLICY_CONFIRMATIONS + 1;
end;

constructor TCodeIntegrityPolicyMonitor.Create;
begin
  inherited Create;
  Reset;
end;

procedure TCodeIntegrityPolicyMonitor.ClearCandidate;
begin
  FPending := Default(TCodeIntegrityPolicySnapshot);
  FConfirmations := 0;
  FLastConfirmTick := 0;
end;

procedure TCodeIntegrityPolicyMonitor.Reset;
begin
  FPrimed := False;
  FBaseline := Default(TCodeIntegrityPolicySnapshot);
  FSafeStable := 0;
  FLastReport := 0;
  ClearCandidate;
end;

procedure TCodeIntegrityPolicyMonitor.Examine(
  const Snapshot: TCodeIntegrityPolicySnapshot; RuntimeDowngrade: Boolean;
  Tick: UInt64; var Detected: TDetectionKinds);
var Changed, Reduced, SamePending, CanReport: Boolean;
begin
  if not Snapshot.Valid then
  begin
    ClearCandidate;
    Exit;
  end;
  if not FPrimed then
  begin
    FPrimed := True;
    FBaseline := Snapshot;
    FSafeStable := 0;
    ClearCandidate;
    Exit;
  end;
  Changed := CodeIntegrityPolicyChanged(FBaseline, Snapshot);
  if not Changed then
  begin
    FSafeStable := 0;
    ClearCandidate;
    Exit;
  end;
  Reduced := CodeIntegrityPolicyReduced(FBaseline, Snapshot);
  if not RuntimeDowngrade then
  begin
    ClearCandidate;
    if not Reduced then
    begin
      if FSafeStable < POLICY_SAFE_ADOPT_CONFIRMATIONS then Inc(FSafeStable);
      if FSafeStable >= POLICY_SAFE_ADOPT_CONFIRMATIONS then
      begin
        FBaseline := Snapshot;
        FSafeStable := 0;
      end;
    end
    else
      FSafeStable := 0;
    Exit;
  end;
  FSafeStable := 0;
  SamePending := FPending.Valid and
    not CodeIntegrityPolicyChanged(FPending, Snapshot);
  if not SamePending or
     ((FLastConfirmTick <> 0) and (Tick < FLastConfirmTick)) then
  begin
    FPending := Snapshot;
    FConfirmations := 1;
    FLastConfirmTick := Tick;
    Exit;
  end;
  if Tick > FLastConfirmTick then
  begin
    if FConfirmations < POLICY_CONFIRMATIONS then Inc(FConfirmations);
    FLastConfirmTick := Tick;
  end;
  if not CodeIntegrityPolicyCandidate(True, Reduced,
       RuntimeDowngrade, FConfirmations) then Exit;
  CanReport := (FLastReport = 0) or (Tick < FLastReport) or
    (Tick - FLastReport >= POLICY_REPORT_MS);
  if CanReport then
  begin
    Include(Detected, dkCodeIntegrityPolicy);
    FLastReport := Tick;
  end;
end;

end.
