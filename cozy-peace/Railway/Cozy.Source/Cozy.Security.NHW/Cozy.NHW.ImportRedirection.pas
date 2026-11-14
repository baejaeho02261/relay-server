unit Cozy.NHW.ImportRedirection;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows, Cozy.NHW.Logging;

type
  TImportRiskSnapshot = record
    Valid: Boolean;
    Total: Cardinal;
    PrivateExecutable: Cardinal;
    RiskDigest: UInt64;
  end;

  // After-loader import baseline; private executable memory alone is not a
  // proof of injection. Malformed/partial reads do not establish a baseline.
  TImportRedirectionMonitor = class
  private
    FPrimed: Boolean;
    FInitialRisk: Cardinal;
    FPendingDigest: UInt64;
    FPendingRisk: Cardinal;
    FPendingTick: UInt64;
    FConfirmations: Integer;
    FLastTick: UInt64;
    FLastIndependent: UInt64;
    FLastReport: UInt64;
    procedure ClearCandidate;
  public
    constructor Create;
    procedure Reset;
    procedure Examine(Baseline, HighExternalAccess: Boolean;
      Tick: UInt64; var Detected: TDetectionKinds);
  end;

function CaptureImportRisk(out Snapshot: TImportRiskSnapshot): Boolean;
function IsImportRedirectionCandidate(InitialRisk, CurrentRisk: Cardinal;
  StableSamples: Integer; IndependentEvidence: Boolean): Boolean;

{$IFDEF NHW_NATIVE5F_TESTS}
function TestImportHardening(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses System.SysUtils, System.Generics.Collections, Cozy.NHW.PEView,
  Cozy.NHW.NativeSafety;

const
  IMPORT_SCAN_MS = 7000;
  INDEPENDENT_WINDOW_MS = 30000;
  IMPORT_REPORT_COOLDOWN_MS = 60000;
  MAX_IMPORT_DESCRIPTORS = 256;
  MAX_IMPORT_SLOTS = 8192;

type
  TImportDescriptor = packed record
    OriginalThunk: Cardinal;
    Timestamp: Cardinal;
    ForwarderChain: Cardinal;
    DllName: Cardinal;
    FirstThunk: Cardinal;
  end;

{$IFDEF NHW_NATIVE5F_TESTS}
type
  TImportViewHook = function(out View: TPEView): Boolean;
  TImportReadHook = function(Address: NativeUInt; var Dest;
    Bytes: NativeUInt): Boolean;
  TImportDescribeHook = function(Address: NativeUInt;
    out Kind: TCodeLocation; out RegionBase: NativeUInt): Boolean;
  TImportCaptureHook = function(out Snapshot: TImportRiskSnapshot): Boolean;
var
  ImportViewHook: TImportViewHook = nil;
  ImportReadHook: TImportReadHook = nil;
  ImportDescribeHook: TImportDescribeHook = nil;
  ImportCaptureHook: TImportCaptureHook = nil;
{$ENDIF}

function ImportView(out View: TPEView): Boolean;
begin
  View := Default(TPEView);
{$IFDEF NHW_NATIVE5F_TESTS}
  if Assigned(ImportViewHook) then Exit(ImportViewHook(View));
{$ENDIF}
  Result := LoadPEView(NativeUInt(HInstance), View);
end;

function ImportRead(Address: NativeUInt; var Dest; Bytes: NativeUInt): Boolean;
begin
  Result := False;
  if not NHWAddressSpan(Address, Bytes) then Exit;
{$IFDEF NHW_NATIVE5F_TESTS}
  if Assigned(ImportReadHook) then Exit(ImportReadHook(Address, Dest, Bytes));
{$ENDIF}
  Result := LocalRead(Address, Dest, Bytes);
end;

function ImportDescribe(Address: NativeUInt; out Kind: TCodeLocation;
  out RegionBase: NativeUInt): Boolean;
begin
  Kind := clUnknown;
  RegionBase := 0;
{$IFDEF NHW_NATIVE5F_TESTS}
  if Assigned(ImportDescribeHook) then
    Exit(ImportDescribeHook(Address, Kind, RegionBase));
{$ENDIF}
  Result := DescribeCodeAddress(Address, Kind, RegionBase);
end;

function ImportTerminator(const D: TImportDescriptor): Boolean;
begin
  Result := (D.OriginalThunk = 0) and (D.Timestamp = 0) and
    (D.ForwarderChain = 0) and (D.DllName = 0) and (D.FirstThunk = 0);
end;

function SameImportDescriptor(const A, B: TImportDescriptor): Boolean;
begin
  Result := (A.OriginalThunk = B.OriginalThunk) and
    (A.Timestamp = B.Timestamp) and (A.ForwarderChain = B.ForwarderChain) and
    (A.DllName = B.DllName) and (A.FirstThunk = B.FirstThunk);
end;

function CaptureImportRisk(out Snapshot: TImportRiskSnapshot): Boolean;
var
  View, VerifyView: TPEView;
  Candidate: TImportRiskSnapshot;
  Dir, DescriptorAddress, SlotAddress, RegionBase: NativeUInt;
  DirBytes, DescCount, TotalSlots: Cardinal;
  Descriptor, VerifyDescriptor: TImportDescriptor;
  Descriptors: array[0..MAX_IMPORT_DESCRIPTORS - 1] of TImportDescriptor;
  DescriptorsRead: Integer;
  Dest: UInt64;
  Kind: TCodeLocation;
  EndFound, SlotEnd: Boolean;
  Cache: TDictionary<NativeUInt, TCodeLocation>;
  CachePage: NativeUInt;
  function ReadImportDirectory: Boolean;
  begin
    Result := False;
    if (View.Directory[1].RVA = 0) or
      not PEDataAddress(View, 1, SizeOf(TImportDescriptor), Dir, DirBytes) then Exit;
    DescCount := DirBytes div SizeOf(TImportDescriptor);
    if DescCount = 0 then Exit;
    if DescCount > MAX_IMPORT_DESCRIPTORS then DescCount := MAX_IMPORT_DESCRIPTORS;
    Result := True;
  end;

  function CollectImportSlots: Boolean;
  var
    I, J: Cardinal;
  begin
    Result := False;
    TotalSlots := 0;
    DescriptorsRead := 0;
    EndFound := False;
    Cache := TDictionary<NativeUInt, TCodeLocation>.Create;
    for I := 0 to DescCount - 1 do
    begin
      DescriptorAddress := Dir + NativeUInt(I) * SizeOf(Descriptor);
      if not ImportRead(DescriptorAddress, Descriptor, SizeOf(Descriptor)) then Exit;
      Descriptors[I] := Descriptor;
      Inc(DescriptorsRead);
      if ImportTerminator(Descriptor) then
      begin
        EndFound := True;
        Break;
      end;
      // FirstThunk=0 alone is NOT the all-zero terminating descriptor.
      if (Descriptor.FirstThunk = 0) or (Descriptor.DllName = 0) or
        (Descriptor.DllName >= View.ImageSize) then Exit;
      SlotEnd := False;
      for J := 0 to MAX_IMPORT_SLOTS do
      begin
        if UInt64(Descriptor.FirstThunk) + UInt64(J) * UInt64(8) >
          UInt64(High(Cardinal)) then Exit;
        if not PEAddress(View, Descriptor.FirstThunk + J * 8,
          SizeOf(Dest), SlotAddress) or
          not ImportRead(SlotAddress, Dest, SizeOf(Dest)) then Exit;
        if Dest = 0 then
        begin
          SlotEnd := True;
          Break;
        end;
        // The terminator after exactly MAX_IMPORT_SLOTS entries is allowed.
        if TotalSlots >= MAX_IMPORT_SLOTS then Exit;
        Inc(TotalSlots);
        CachePage := NativeUInt(Dest) and (not NativeUInt($FFF));
        if not Cache.TryGetValue(CachePage, Kind) then
        begin
          if not ImportDescribe(NativeUInt(Dest), Kind, RegionBase) then Exit;
          Cache.AddOrSetValue(CachePage, Kind);
        end;
        if Kind = clPrivate then
        begin
          Inc(Candidate.PrivateExecutable);
          Candidate.RiskDigest := PEHash(Candidate.RiskDigest,
            UInt64(Descriptor.FirstThunk) + UInt64(J) * UInt64(8));
          Candidate.RiskDigest := PEHash(Candidate.RiskDigest, Dest);
        end;
      end;
      if not SlotEnd then Exit;
    end;
    if not EndFound then Exit;
    Result := True;
  end;

  function VerifyImportCollection: Boolean;
  var
    I: Cardinal;
  begin
    Result := False;
    if not ImportView(VerifyView) or (VerifyView.Base <> View.Base) or
      (VerifyView.ImageSize <> View.ImageSize) or
      (VerifyView.Directory[1].RVA <> View.Directory[1].RVA) or
      (VerifyView.Directory[1].Size <> View.Directory[1].Size) then Exit;
    for I := 0 to Cardinal(DescriptorsRead) - 1 do
    begin
      if not ImportRead(Dir + NativeUInt(I) * SizeOf(Descriptor),
        VerifyDescriptor, SizeOf(VerifyDescriptor)) or
        not SameImportDescriptor(Descriptors[I], VerifyDescriptor) then Exit;
    end;
    Result := True;
  end;

begin
  Snapshot := Default(TImportRiskSnapshot);
  Candidate := Default(TImportRiskSnapshot);
  Result := False;
  Cache := nil;
  FillChar(Descriptors, SizeOf(Descriptors), 0);
  Descriptor := Default(TImportDescriptor);
  VerifyDescriptor := Default(TImportDescriptor);
  Dest := 0;
  try
    if not ImportView(View) then Exit;
    Candidate.RiskDigest := UInt64($CBF29CE484222325);
    if (View.Directory[1].RVA = 0) and (View.Directory[1].Size = 0) then
    begin
      if not ImportView(VerifyView) or (VerifyView.Base <> View.Base) or
        (VerifyView.ImageSize <> View.ImageSize) or
        (VerifyView.Directory[1].RVA <> 0) or
        (VerifyView.Directory[1].Size <> 0) then Exit;
      Candidate.Valid := True;
      Snapshot := Candidate;
      Exit(True);
    end;
    if not ReadImportDirectory then Exit;
    if not CollectImportSlots then Exit;
    if not VerifyImportCollection then Exit;
    Candidate.Total := TotalSlots;
    Candidate.Valid := True;
    Snapshot := Candidate; // publish only a complete, terminated collection
    Result := True;
  finally
    Cache.Free;
    if not Result then Snapshot := Default(TImportRiskSnapshot);
  end;
end;

function ReadImportRisk(out Snapshot: TImportRiskSnapshot): Boolean;
begin
  Snapshot := Default(TImportRiskSnapshot);
{$IFDEF NHW_NATIVE5F_TESTS}
  if Assigned(ImportCaptureHook) then Exit(ImportCaptureHook(Snapshot));
{$ENDIF}
  Result := CaptureImportRisk(Snapshot);
end;

function IsImportRedirectionCandidate(InitialRisk, CurrentRisk: Cardinal;
  StableSamples: Integer; IndependentEvidence: Boolean): Boolean;
begin
  Result := (CurrentRisk > InitialRisk) and
    (StableSamples >= 2) and IndependentEvidence;
end;

constructor TImportRedirectionMonitor.Create;
begin inherited Create; Reset; end;

procedure TImportRedirectionMonitor.ClearCandidate;
begin
  FPendingDigest := 0;
  FPendingRisk := 0;
  FPendingTick := 0;
  FConfirmations := 0;
end;

procedure TImportRedirectionMonitor.Reset;
begin
  FPrimed := False;
  FInitialRisk := 0;
  ClearCandidate;
  FLastTick := 0;
  FLastIndependent := 0;
  FLastReport := 0;
end;

procedure TImportRedirectionMonitor.Examine(Baseline,
  HighExternalAccess: Boolean; Tick: UInt64; var Detected: TDetectionKinds);
var
  Snap: TImportRiskSnapshot;
  Independent: Boolean;
begin
  if (FLastTick <> 0) and (Tick < FLastTick) then
  begin
    ClearCandidate;
    FLastIndependent := 0;
    FLastReport := 0;
  end;
  if Baseline or ((FConfirmations <> 0) and
    NHWExpired(FPendingTick, Tick, INDEPENDENT_WINDOW_MS)) then ClearCandidate;
  Independent := HighExternalAccess or
    ((Detected * [dkIAT, dkExportTable, dkExportTarget,
      dkResolution, dkPECodeIntegrity]) <> []);
  if Independent then FLastIndependent := Tick;
  if (FLastTick <> 0) and (Tick >= FLastTick) and
    (Tick - FLastTick < IMPORT_SCAN_MS) then Exit;
  FLastTick := Tick;
  try
    if not ReadImportRisk(Snap) or not Snap.Valid or
      (Snap.PrivateExecutable > Snap.Total) then
    begin ClearCandidate; Exit; end;
  except
    ClearCandidate;
    raise;
  end;
  if not FPrimed or Baseline then
  begin
    FPrimed := True;
    FInitialRisk := Snap.PrivateExecutable;
    ClearCandidate;
    Exit;
  end;
  if Snap.PrivateExecutable <= FInitialRisk then
  begin ClearCandidate; Exit; end;
  if (FConfirmations > 0) and (Snap.RiskDigest = FPendingDigest) and
    (Snap.PrivateExecutable = FPendingRisk) then
  begin
    if FConfirmations < 2 then Inc(FConfirmations);
  end
  else
  begin
    FPendingDigest := Snap.RiskDigest;
    FPendingRisk := Snap.PrivateExecutable;
    FPendingTick := Tick;
    FConfirmations := 1;
  end;
  if IsImportRedirectionCandidate(FInitialRisk, Snap.PrivateExecutable,
    FConfirmations, (FLastIndependent <> 0) and
    (Tick >= FLastIndependent) and
    (Tick - FLastIndependent <= INDEPENDENT_WINDOW_MS)) and
    ((FLastReport = 0) or ((Tick >= FLastReport) and
    (Tick - FLastReport >= IMPORT_REPORT_COOLDOWN_MS))) then
  begin
    Include(Detected, dkImportRedirect);
    FLastReport := Tick;
  end;
end;

{$IFDEF NHW_NATIVE5F_TESTS}
{$I Cozy.NHW.Native5F.Import.inc}
{$ENDIF}

end.
