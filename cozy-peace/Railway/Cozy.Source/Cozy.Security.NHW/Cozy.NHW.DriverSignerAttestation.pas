unit Cozy.NHW.DriverSignerAttestation;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  System.Generics.Collections,
  Cozy.NHW.Logging,
  Cozy.NHW.KernelTrust.Native,
  Cozy.NHW.KernelTrust.PlatformNative;

type
  TSignerBaseline = record
    Identity: TDriverFileIdentity;
    TrustState: Byte;
    PendingConfirmations: Byte;
    LastTick: UInt64;
  end;

  TDriverSignerAttestationMonitor = class
  private
    FItems: TDictionary<string, TSignerBaseline>;
    FCursor: Integer;
    FLastReport: UInt64;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure Examine(const Modules: TKernelModuleInfos; Valid, Corroborated: Boolean;
      Tick: UInt64; var Detected: TDetectionKinds);
  end;

function DriverSignerAttestationCandidate(BaselineTrusted, CurrentUntrusted,
  IdentityChanged, Corroborated: Boolean; Confirmations: Byte): Boolean;

implementation

uses System.SysUtils;

const
  SIGNER_CONFIRMATIONS = 3;
  SIGNER_PER_PASS = 4;
  SIGNER_REPORT_MS = 60000;

function SameIdentity(const A, B: TDriverFileIdentity): Boolean;
begin
  Result := A.Valid and B.Valid and (A.VolumeSerial = B.VolumeSerial) and
    (A.FileIndex = B.FileIndex) and (A.FileSize = B.FileSize) and
    (A.WriteTime = B.WriteTime);
end;

function TrustedState(S: Byte): Boolean;
begin
  Result := (S = DRIVER_TRUST_EMBEDDED) or (S = DRIVER_TRUST_CATALOG);
end;

function DriverSignerAttestationCandidate(BaselineTrusted, CurrentUntrusted,
  IdentityChanged, Corroborated: Boolean; Confirmations: Byte): Boolean;
begin
  Result := BaselineTrusted and CurrentUntrusted and IdentityChanged and
    Corroborated and (Confirmations >= SIGNER_CONFIRMATIONS);
end;

constructor TDriverSignerAttestationMonitor.Create;
begin
  inherited Create;
  FItems := TDictionary<string, TSignerBaseline>.Create;
  Reset;
end;

destructor TDriverSignerAttestationMonitor.Destroy;
begin
  FItems.Free;
  inherited Destroy;
end;

procedure TDriverSignerAttestationMonitor.Reset;
begin
  FItems.Clear;
  FCursor := 0;
  FLastReport := 0;
end;

procedure TDriverSignerAttestationMonitor.Examine(const Modules: TKernelModuleInfos;
  Valid, Corroborated: Boolean; Tick: UInt64; var Detected: TDetectionKinds);
var I, Passes, Index: Integer; M: TKernelModuleInfo; K: string;
  B: TSignerBaseline; Id: TDriverFileIdentity; Trust, NextConfirm: Byte;
  Changed, Candidate, CanReport: Boolean;
begin
  if not Valid or (Length(Modules) = 0) then Exit;
  if FCursor >= Length(Modules) then FCursor := 0;
  Passes := SIGNER_PER_PASS;
  if Passes > Length(Modules) then Passes := Length(Modules);
  for I := 0 to Passes - 1 do
  begin
    Index := (FCursor + I) mod Length(Modules);
    M := Modules[Index];
    if (Length(M.Path) < 3) or (M.Path[2] <> ':') then Continue;
    K := KernelModuleKey(M);
    if not QueryDriverFileIdentity(M.Path, Id) then Continue;
    if not QueryDriverTrustState(M.Path, Trust) then Continue;
    if not FItems.TryGetValue(K, B) then
    begin
      B := Default(TSignerBaseline);
      B.Identity := Id;
      B.TrustState := Trust;
      B.LastTick := Tick;
      FItems.Add(K, B);
      Continue;
    end;
    Changed := not SameIdentity(B.Identity, Id);
    if not Changed then
    begin
      B.PendingConfirmations := 0;
      B.LastTick := Tick;
      FItems.AddOrSetValue(K, B);
      Continue;
    end;
    if not TrustedState(B.TrustState) or
       (Trust <> DRIVER_TRUST_UNTRUSTED) or not Corroborated then
    begin
      B.PendingConfirmations := 0;
      B.LastTick := Tick;
      FItems.AddOrSetValue(K, B);
      Continue;
    end;
    NextConfirm := B.PendingConfirmations;
    if NextConfirm < High(Byte) then Inc(NextConfirm);
    Candidate := DriverSignerAttestationCandidate(True, True, True, True,
      NextConfirm);
    B.PendingConfirmations := NextConfirm;
    B.LastTick := Tick;
    FItems.AddOrSetValue(K, B);
    if not Candidate then Continue;
    CanReport := (FLastReport = 0) or (Tick < FLastReport) or
      (Tick - FLastReport >= SIGNER_REPORT_MS);
    if CanReport then
    begin
      Include(Detected, dkDriverSignerAttestation);
      FLastReport := Tick;
    end;
  end;
  FCursor := (FCursor + Passes) mod Length(Modules);
end;

end.
