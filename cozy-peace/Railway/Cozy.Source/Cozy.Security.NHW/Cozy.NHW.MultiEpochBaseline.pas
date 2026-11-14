unit Cozy.NHW.MultiEpochBaseline;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows;

const
  NHW_MAX_EPOCH_MODULES = 512;

type
  TModuleEpochView = record
    Valid: Boolean;
    Count: Cardinal;
    Bases: array[0..NHW_MAX_EPOCH_MODULES - 1] of NativeUInt;
  end;

  // v72: a change in an ordinary DLL inventory is a new NORMAL baseline,
  // not an attack. Incomplete inventories never advance the epoch.
  TMultiEpochBaseline = class
  private
    FAccepted, FPending: TModuleEpochView;
    FPrimed: Boolean;
    FPendingSamples: Integer;
    FEpoch: Cardinal;
    FLastChange, FLastValid: UInt64;
    FStable: Boolean;
    FPendingTick: UInt64;
    FNeedsRecovery: Boolean;
    procedure InvalidatePending;
  public
    constructor Create;
    procedure Reset;
    procedure Observe(OwnTarget, Baseline: Boolean; Tick: UInt64);
    procedure FeedSample(const Sample: TModuleEpochView; Tick: UInt64);
    property Epoch: Cardinal read FEpoch;
    property Stable: Boolean read FStable;
  end;

function ReadModuleEpochView(out View: TModuleEpochView): Boolean;
function SameModuleEpoch(const A, B: TModuleEpochView): Boolean;
{$IFDEF NHW_NATIVE5H_TESTS}
function TestMultiEpochHardening(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses Cozy.NHW.WinPointers {$IFDEF NHW_NATIVE5H_TESTS}, System.SysUtils{$ENDIF};

type
  TEnumModules = function(Process: THandle; Modules: Pointer;
    BufferBytes: Cardinal; out Needed: Cardinal): BOOL; stdcall;

var
  FnEnum: TEnumModules = nil;
  TriedEnum: Boolean = False;

procedure ResolveEnum;
var K, P: HMODULE;
begin
  if TriedEnum then Exit;
  TriedEnum := True;
  K := WinModule('kernel32.dll');
  FnEnum := TEnumModules(WinExport(K, 'K32EnumProcessModules'));
  if Assigned(FnEnum) then Exit;
  P := WinLoadLibrary('psapi.dll');
  FnEnum := TEnumModules(WinExport(P, 'EnumProcessModules'));
end;

function ValidModuleEpoch(const View: TModuleEpochView): Boolean;
var I: Integer;
begin
  Result := False;
  if not View.Valid or (View.Count = 0) or
     (View.Count > NHW_MAX_EPOCH_MODULES) then Exit;
  for I := 0 to Integer(View.Count) - 1 do
  begin
    if View.Bases[I] = 0 then Exit;
    if I > 0 then
      if View.Bases[I] <= View.Bases[I-1] then Exit;
  end;
  Result := True;
end;

function ReadModuleEpochView(out View: TModuleEpochView): Boolean;
var
  Bases: array[0..NHW_MAX_EPOCH_MODULES - 1] of HMODULE;
  Needed: Cardinal;
  Count, I, J: Integer;
  InsertBase: NativeUInt;
  Candidate: TModuleEpochView;
begin
  View := Default(TModuleEpochView);
  Candidate := Default(TModuleEpochView);
  Result := False;
  ResolveEnum;
  if not Assigned(FnEnum) then Exit;
  FillChar(Bases, SizeOf(Bases), 0);
  Needed := 0;
  if not FnEnum(WinCurrentProcess, @Bases[0], SizeOf(Bases), Needed) or
     (Needed = 0) or (Needed > Cardinal(SizeOf(Bases))) or
     ((Needed mod SizeOf(HMODULE)) <> 0) then Exit;
  Count := Integer(Needed div SizeOf(HMODULE));
  if (Count <= 0) or (Count > NHW_MAX_EPOCH_MODULES) then Exit;
  Candidate.Count := Cardinal(Count);
  for I := 0 to Count - 1 do Candidate.Bases[I] := NativeUInt(Bases[I]);
  for I := 1 to Count - 1 do
  begin
    InsertBase := Candidate.Bases[I];
    J := I;
    while J > 0 do
    begin
      if Candidate.Bases[J-1] <= InsertBase then Break;
      Candidate.Bases[J] := Candidate.Bases[J-1];
      Dec(J);
    end;
    Candidate.Bases[J] := InsertBase;
  end;
  Candidate.Valid := True;
  if not ValidModuleEpoch(Candidate) then Exit;
  View := Candidate; // Publish only a complete structurally valid inventory.
  Result := True;
end;

function SameModuleEpoch(const A, B: TModuleEpochView): Boolean;
var I: Integer;
begin
  Result := False;
  if not ValidModuleEpoch(A) or not ValidModuleEpoch(B) then Exit;
  if A.Count <> B.Count then Exit;
  for I := 0 to Integer(A.Count) - 1 do
    if A.Bases[I] <> B.Bases[I] then Exit;
  Result := True;
end;

constructor TMultiEpochBaseline.Create;
begin inherited Create; Reset; end;

procedure TMultiEpochBaseline.Reset;
begin
  FAccepted := Default(TModuleEpochView);
  FPending := Default(TModuleEpochView);
  FPrimed := False;
  FPendingSamples := 0;
  FPendingTick := 0;
  FEpoch := 0;
  FLastChange := 0;
  FLastValid := 0;
  FStable := False;
  FNeedsRecovery := False;
end;

procedure TMultiEpochBaseline.InvalidatePending;
begin
  FPending := Default(TModuleEpochView);
  FPendingSamples := 0;
  FPendingTick := 0;
  FStable := False;
  FNeedsRecovery := True;
  // Keep accepted inventory/epoch: a failed read is not a new normal baseline.
end;

procedure TMultiEpochBaseline.FeedSample(const Sample: TModuleEpochView;
  Tick: UInt64);
begin
  if not ValidModuleEpoch(Sample) then
  begin InvalidatePending; Exit; end;
  if FPrimed then
  begin
    if FNeedsRecovery or (Tick < FLastValid) or
       (Tick - FLastValid > 30000) then
    begin
      InvalidatePending;
      FLastChange := Tick;
    end;
  end;
  FLastValid := Tick;
  FNeedsRecovery := False;
  if not FPrimed then
  begin
    FAccepted := Sample;
    FPrimed := True;
    FEpoch := 1;
    FLastChange := Tick;
    FStable := False;
    Exit;
  end;
  if SameModuleEpoch(Sample, FAccepted) then
  begin
    FPendingSamples := 0;
    FPendingTick := 0;
    FPending := Default(TModuleEpochView);
    FStable := (Tick >= FLastChange) and (Tick - FLastChange >= 3000);
    Exit;
  end;
  FStable := False;
  if SameModuleEpoch(Sample, FPending) then
  begin
    // Same-time duplicate callbacks do not advance a two-observation candidate.
    if (Tick > FPendingTick) and (FPendingSamples < 2) then
      Inc(FPendingSamples);
  end
  else
  begin
    FPending := Sample;
    FPendingSamples := 1;
  end;
  FPendingTick := Tick;
  if FPendingSamples >= 2 then
  begin
    FAccepted := Sample;
    FPending := Default(TModuleEpochView);
    FPendingSamples := 0;
    FPendingTick := 0;
    if FEpoch = High(Cardinal) then FEpoch := 1 else Inc(FEpoch);
    FLastChange := Tick;
  end;
end;

procedure TMultiEpochBaseline.Observe(OwnTarget, Baseline: Boolean;
  Tick: UInt64);
var Sample: TModuleEpochView;
begin
  if not OwnTarget then begin Reset; Exit; end;
  try
    if not ReadModuleEpochView(Sample) then
    begin InvalidatePending; Exit; end;
    FeedSample(Sample, Tick);
    if Baseline then FStable := False;
  except
    InvalidatePending;
    raise;
  end;
end;

{$IFDEF NHW_NATIVE5H_TESTS}
{$I Cozy.NHW.Native5H.MultiEpoch.inc}
{$ENDIF}
end.
