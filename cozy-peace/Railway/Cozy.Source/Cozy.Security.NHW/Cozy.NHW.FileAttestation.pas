unit Cozy.NHW.FileAttestation;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows, Cozy.NHW.Logging, Cozy.NHW.SectionBackingIdentity;

type
  TAttestedFileIdentity = record
    Valid: Boolean;
    Base: NativeUInt;
    PathFileID: UInt64;
    MappedNameHash: UInt64;
    PEImageSize: Cardinal;
  end;

  // v63: baseline for disk identities resolved through loaded-image paths.
  // Not an attestation of the original SEC_IMAGE kernel file object.
  TFileAttestationMonitor = class
  private
    FBase: array[0..3] of TAttestedFileIdentity;
    FLast: array[0..3] of TAttestedFileIdentity;
    FSince: array[0..3] of UInt64;
    FSeenAt: array[0..3] of UInt64;
    FConfirm: array[0..3] of Integer;
    FLastTick: UInt64;
    FLastReport: UInt64;
    procedure ClearCandidate(Index: Integer);
  public
    constructor Create;
    procedure Reset;
    procedure Examine(Baseline, IndependentEvidence: Boolean;
      Tick: UInt64; var Detected: TDetectionKinds);
  end;

function CaptureAttestedFile(Module: HMODULE;
  out Identity: TAttestedFileIdentity): Boolean;
function AttestationCandidate(const Baseline, Current: TAttestedFileIdentity;
  Confirmations: Integer; IndependentEvidence: Boolean): Boolean;

{$IFDEF NHW_NATIVE5E_TESTS}
function TestFileAttestationHardening(out Failure: string;
  out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses System.SysUtils, Cozy.NHW.PEView, Cozy.NHW.WinPointers;

const
  ATTEST_SCAN_MS = 15000;
  ATTEST_CANDIDATE_MS = 45000;
  ATTEST_COOLDOWN_MS = 60000;

{$IFDEF NHW_NATIVE5E_TESTS}
type
  TAttestCaptureHook = function(Module: HMODULE;
    out Identity: TAttestedFileIdentity): Boolean;
  TAttestModuleHook = function(Index: Integer): HMODULE;
var
  AttestCaptureHook: TAttestCaptureHook = nil;
  AttestModuleHook: TAttestModuleHook = nil;
{$ENDIF}

function AttestModule(Index: Integer): HMODULE;
begin
{$IFDEF NHW_NATIVE5E_TESTS}
  if Assigned(AttestModuleHook) then Exit(AttestModuleHook(Index));
{$ENDIF}
  case Index of
    0: Result := HMODULE(HInstance);
    1: Result := WinModule('ntdll.dll');
    2: Result := WinModule('kernel32.dll');
    3: Result := WinModule('kernelbase.dll');
  else Result := 0;
  end;
end;

function CaptureAttestedFile(Module: HMODULE;
  out Identity: TAttestedFileIdentity): Boolean;
var
  P: TPEView;
  Section: TSectionIdentity;
begin
  Identity := Default(TAttestedFileIdentity);
  Result := False;
  if Module = 0 then Exit; // nil must not silently refer to the main EXE
  Section := Default(TSectionIdentity);
  P := Default(TPEView);
  if not CaptureSectionIdentity(Module, Section) then Exit;
  if not Section.Valid or (Section.Base <> NativeUInt(Module)) then Exit;
  if not LoadPEView(NativeUInt(Module), P) then Exit;
  if (P.Base <> Section.Base) or (P.ImageSize = 0) then Exit;
  Identity.Valid := True;
  Identity.Base := Section.Base;
  Identity.PathFileID := Section.PathFileID;
  Identity.MappedNameHash := Section.MappedNameHash;
  Identity.PEImageSize := P.ImageSize;
  Result := True;
end;

function ReadAttestedFile(Module: HMODULE;
  out Identity: TAttestedFileIdentity): Boolean;
begin
  Identity := Default(TAttestedFileIdentity);
{$IFDEF NHW_NATIVE5E_TESTS}
  if Assigned(AttestCaptureHook) then
    Exit(AttestCaptureHook(Module, Identity));
{$ENDIF}
  Result := CaptureAttestedFile(Module, Identity);
end;

function SameAttestedIdentity(const A, B: TAttestedFileIdentity): Boolean;
begin
  Result := A.Valid and B.Valid and (A.Base = B.Base) and
    (A.PathFileID = B.PathFileID) and
    (A.MappedNameHash = B.MappedNameHash) and
    (A.PEImageSize = B.PEImageSize);
end;

function AttestationCandidate(const Baseline, Current: TAttestedFileIdentity;
  Confirmations: Integer; IndependentEvidence: Boolean): Boolean;
begin
  Result := Baseline.Valid and Current.Valid and
    (Baseline.Base = Current.Base) and IndependentEvidence and
    (Confirmations >= 2) and
    ((Baseline.PathFileID <> Current.PathFileID) or
     (Baseline.MappedNameHash <> Current.MappedNameHash) or
     (Baseline.PEImageSize <> Current.PEImageSize));
end;

constructor TFileAttestationMonitor.Create;
begin inherited Create; Reset; end;

procedure TFileAttestationMonitor.ClearCandidate(Index: Integer);
begin
  FLast[Index] := Default(TAttestedFileIdentity);
  FConfirm[Index] := 0;
  FSince[Index] := 0;
  FSeenAt[Index] := 0;
end;

procedure TFileAttestationMonitor.Reset;
var I: Integer;
begin
  FLastTick := 0;
  FLastReport := 0;
  for I := 0 to 3 do
  begin
    FBase[I] := Default(TAttestedFileIdentity);
    ClearCandidate(I);
  end;
end;

procedure TFileAttestationMonitor.Examine(Baseline,
  IndependentEvidence: Boolean; Tick: UInt64;
  var Detected: TDetectionKinds);
var
  Module: HMODULE;
  Current: TAttestedFileIdentity;
  I: Integer;
  Changed: Boolean;

  procedure AdvanceIdentityCandidate;
  begin
    if SameAttestedIdentity(FLast[I], Current) and (FConfirm[I] <> 0) and
       (Tick >= FSince[I]) and (Tick >= FSeenAt[I]) and
       (Tick - FSince[I] <= ATTEST_CANDIDATE_MS) then
    begin
      if (Tick > FSeenAt[I]) and (FConfirm[I] < 2) then Inc(FConfirm[I]);
    end
    else
    begin
      FLast[I] := Current;
      FSince[I] := Tick;
      FConfirm[I] := 1;
    end;
    FSeenAt[I] := Tick;
  end;

  procedure ReportAttestationChange;
  begin
    if Changed and ((FLastReport = 0) or
      ((Tick >= FLastReport) and (Tick - FLastReport >= ATTEST_COOLDOWN_MS))) then
    begin
      Include(Detected, dkFileAttestation);
      FLastReport := Tick;
    end;
  end;

begin
  if (FLastTick <> 0) and (Tick < FLastTick) then
  begin
    for I := 0 to 3 do ClearCandidate(I);
    FLastReport := 0; // preserve approved baselines on a clock discontinuity
  end;
  if (FLastTick <> 0) and (Tick >= FLastTick) and
    (Tick - FLastTick < ATTEST_SCAN_MS) then Exit;
  FLastTick := Tick;
  Changed := False;
  try
    for I := 0 to 3 do
    begin
      Module := AttestModule(I);
      if not ReadAttestedFile(Module, Current) then
      begin
        ClearCandidate(I);
        Continue; // a failure is NOT a successful consecutive observation
      end;
      if (Module = 0) or not Current.Valid or
         (Current.Base <> NativeUInt(Module)) or
         (Current.PEImageSize = 0) or (AttestModule(I) <> Module) then
      begin
        ClearCandidate(I);
        Continue;
      end;
      if not FBase[I].Valid or Baseline or
         (FBase[I].Base <> Current.Base) then
      begin
        FBase[I] := Current;
        ClearCandidate(I);
        Continue;
      end;
      if SameAttestedIdentity(FBase[I], Current) then
      begin
        ClearCandidate(I);
        Continue;
      end;
      // Compare the complete identity tuple, not a second lossy digest of it.
      // Candidates expire even if the scanner was not called during a gap.
      AdvanceIdentityCandidate;
      if AttestationCandidate(FBase[I], Current, FConfirm[I],
        IndependentEvidence) then Changed := True;
    end;
  except
    for I := 0 to 3 do ClearCandidate(I);
    raise; // no partial detection is published by this invocation
  end;
  ReportAttestationChange;
end;

{$IFDEF NHW_NATIVE5E_TESTS}
{$I Cozy.NHW.Native5E.FileAttestation.inc}
{$ENDIF}

end.
