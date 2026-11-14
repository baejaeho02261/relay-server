unit Cozy.NHW.SystemViewDisagreement;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Cozy.NHW.Logging,
  Cozy.NHW.KernelTrust.Native;

const
  SVD_MODULE_BASE = $00000001;
  SVD_MODULE_PATH = $00000002;
  SVD_HVCI_STATE  = $00000004;
  SVD_BOOT_STATE  = $00000008;

type
  TSystemViewDisagreementMonitor = class
  private
    FPrimed: Boolean;
    FBaselineMask: Cardinal;
    FPendingMask: Cardinal;
    FConfirmations: Byte;
    FLastConfirmTick: UInt64;
    FLastReport: UInt64;
    procedure ClearCandidate;
  public
    constructor Create;
    procedure Reset;
    procedure Examine(const Boot: TSecureBootSnapshot;
      const CI: TCodeIntegritySnapshot;
      const NativeModules, PSAPIModules: TKernelModuleInfos;
      NativeValid, PSAPIValid: Boolean; Tick: UInt64;
      var Detected: TDetectionKinds);
  end;

function BuildSystemViewDisagreementMask(const Boot: TSecureBootSnapshot;
  const CI: TCodeIntegritySnapshot;
  const NativeModules, PSAPIModules: TKernelModuleInfos;
  NativeValid, PSAPIValid: Boolean): Cardinal;
function SystemViewDisagreementCandidate(NewMask: Cardinal;
  Confirmations: Byte): Boolean;

implementation

uses System.SysUtils;

const
  SVD_CONFIRMATIONS = 3;
  SVD_REPORT_MS = 60000;

function CountBits(V: Cardinal): Integer;
begin
  Result := 0;
  while V <> 0 do
  begin
    Inc(Result);
    V := V and (V - 1);
  end;
end;

function ResolvableDriverPath(const Path: string): Boolean;
begin
  Result := (Length(Path) >= 3) and (Path[2] = ':') and
    ((Path[3] = '\') or (Path[3] = '/'));
end;

function BaseSetsDiffer(const A, B: TKernelModuleInfos): Boolean;
var I, J: Integer;
begin
  I := 0; J := 0;
  while (I < Length(A)) or (J < Length(B)) do
  begin
    if I >= Length(A) then Exit(True);
    if J >= Length(B) then Exit(True);
    if A[I].Base = B[J].Base then
    begin Inc(I); Inc(J); Continue; end;
    Exit(True);
  end;
  Result := False;
end;

function PathsDiffer(const A, B: TKernelModuleInfos): Boolean;
var I, J: Integer; PA, PB: string;
begin
  Result := False;
  I := 0; J := 0;
  while (I < Length(A)) and (J < Length(B)) do
  begin
    if A[I].Base < B[J].Base then begin Inc(I); Continue; end;
    if A[I].Base > B[J].Base then begin Inc(J); Continue; end;
    PA := A[I].Path;
    PB := B[J].Path;
    if ResolvableDriverPath(PA) and ResolvableDriverPath(PB) and
       not SameText(PA, PB) then Exit(True);
    Inc(I); Inc(J);
  end;
end;

function BuildSystemViewDisagreementMask(const Boot: TSecureBootSnapshot;
  const CI: TCodeIntegritySnapshot;
  const NativeModules, PSAPIModules: TKernelModuleInfos;
  NativeValid, PSAPIValid: Boolean): Cardinal;
var RuntimeHVCI: Boolean;
begin
  Result := 0;
  if NativeValid and PSAPIValid then
  begin
    if BaseSetsDiffer(NativeModules, PSAPIModules) then
      Result := Result or SVD_MODULE_BASE;
    if PathsDiffer(NativeModules, PSAPIModules) then
      Result := Result or SVD_MODULE_PATH;
  end;
  if CI.NativeValid and CI.RegistryHVCIValid then
  begin
    RuntimeHVCI := (CI.Options and CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED) <> 0;
    if RuntimeHVCI <> CI.RegistryHVCIEnabled then
      Result := Result or SVD_HVCI_STATE;
  end;
  if Boot.NativeValid and Boot.RegistryValid and
     (Boot.SecureBootEnabled <> Boot.RegistryEnabled) then
    Result := Result or SVD_BOOT_STATE;
end;

function SystemViewDisagreementCandidate(NewMask: Cardinal;
  Confirmations: Byte): Boolean;
begin
  Result := (CountBits(NewMask) >= 2) and
    ((NewMask and (SVD_MODULE_BASE or SVD_MODULE_PATH)) <> 0) and
    (Confirmations >= SVD_CONFIRMATIONS);
end;

constructor TSystemViewDisagreementMonitor.Create;
begin
  inherited Create;
  Reset;
end;

procedure TSystemViewDisagreementMonitor.ClearCandidate;
begin
  FPendingMask := 0;
  FConfirmations := 0;
  FLastConfirmTick := 0;
end;

procedure TSystemViewDisagreementMonitor.Reset;
begin
  FPrimed := False;
  FBaselineMask := 0;
  FLastReport := 0;
  ClearCandidate;
end;

procedure TSystemViewDisagreementMonitor.Examine(
  const Boot: TSecureBootSnapshot; const CI: TCodeIntegritySnapshot;
  const NativeModules, PSAPIModules: TKernelModuleInfos;
  NativeValid, PSAPIValid: Boolean; Tick: UInt64;
  var Detected: TDetectionKinds);
var Mask, NewMask: Cardinal; CanReport: Boolean;
begin
  Mask := BuildSystemViewDisagreementMask(Boot, CI,
    NativeModules, PSAPIModules, NativeValid, PSAPIValid);
  if not FPrimed then
  begin
    FPrimed := True;
    FBaselineMask := Mask;
    ClearCandidate;
    Exit;
  end;
  NewMask := Mask and not FBaselineMask;
  if CountBits(NewMask) < 2 then
  begin
    ClearCandidate;
    Exit;
  end;
  if (FPendingMask <> NewMask) or
     ((FLastConfirmTick <> 0) and (Tick < FLastConfirmTick)) then
  begin
    FPendingMask := NewMask;
    FConfirmations := 1;
    FLastConfirmTick := Tick;
    Exit;
  end;
  if Tick > FLastConfirmTick then
  begin
    if FConfirmations < SVD_CONFIRMATIONS then Inc(FConfirmations);
    FLastConfirmTick := Tick;
  end;
  if not SystemViewDisagreementCandidate(NewMask, FConfirmations) then Exit;
  CanReport := (FLastReport = 0) or (Tick < FLastReport) or
    (Tick - FLastReport >= SVD_REPORT_MS);
  if CanReport then
  begin
    Include(Detected, dkSystemViewDisagreement);
    FLastReport := Tick;
  end;
end;

end.
