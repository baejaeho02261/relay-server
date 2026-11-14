unit Cozy.NHW.ThreadStackProvenance;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows, Cozy.NHW.Logging;

type
  // v56 stays current-thread only. No suspension, remote stack reads,
  // or thread-context changes. A failed frame query is an unknown sample.
  TThreadStackProvenanceMonitor = class
  private
    FLastTick: UInt64;
    FLastEvidence: UInt64;
    FLastReport: UInt64;
    FLastObservation: UInt64;
    FPreviousRegion: NativeUInt;
    FConfirmations: Integer;
    procedure ClearCandidate;
    function EvidenceRecent(Tick: UInt64): Boolean;
    procedure UpdateCandidate(Region, Tick: UInt64);
    function ReportDue(Tick: UInt64): Boolean;
  public
    constructor Create;
    procedure Reset;
    procedure Examine(Baseline, ExternalAccess: Boolean;
      Tick: UInt64; var Detected: TDetectionKinds);
  end;

function CaptureCurrentStackOrigin(out SuspiciousRegion: NativeUInt): Boolean;
function StackOriginCandidate(Region: NativeUInt;
  StableSamples: Integer; IndependentEvidence: Boolean): Boolean;

{$IFDEF NHW_NATIVE5E_TESTS}
function TestThreadStackHardening(out Failure: string;
  out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses System.SysUtils, Cozy.NHW.PEView, Cozy.NHW.WinPointers;

const
  STACK_ORIGIN_SCAN_MS = 6000;
  STACK_ORIGIN_EVIDENCE_MS = 30000;
  STACK_ORIGIN_COOLDOWN_MS = 60000;
  MAX_BACKTRACE_FRAMES = 24;

type
  TBackTrace = function(FramesToSkip, FramesToCapture: Cardinal;
    BackTrace: Pointer; Hash: Pointer): Word; stdcall;
  TStackFrameArray = array[0..MAX_BACKTRACE_FRAMES-1] of Pointer;

var
  BackTraceFn: TBackTrace = nil;
  BackTraceResolved: Boolean = False;

{$IFDEF NHW_NATIVE5E_TESTS}
type
  TStackDescribeHook = function(Address: NativeUInt; out Kind: TCodeLocation;
    out Base: NativeUInt): Boolean;
var
  StackDescribeHook: TStackDescribeHook = nil;
{$ENDIF}

function DescribeStackFrame(Address: NativeUInt; out Kind: TCodeLocation;
  out Base: NativeUInt): Boolean;
begin
  Kind := clUnknown;
  Base := 0;
{$IFDEF NHW_NATIVE5E_TESTS}
  if Assigned(StackDescribeHook) then
    Exit(StackDescribeHook(Address, Kind, Base));
{$ENDIF}
  Result := DescribeCodeAddress(Address, Kind, Base);
end;

procedure ResolveBackTrace;
var K: HMODULE;
begin
  if BackTraceResolved then Exit;
  K := WinModule('kernel32.dll');
  BackTraceFn := TBackTrace(WinExport(K, 'RtlCaptureStackBackTrace'));
  if not Assigned(BackTraceFn) then
  begin
    K := WinModule('ntdll.dll');
    BackTraceFn := TBackTrace(WinExport(K, 'RtlCaptureStackBackTrace'));
  end;
  BackTraceResolved := True;
end;

function CaptureBackTraceFrames(out Frames: TStackFrameArray;
  out Count: Integer): Boolean;
var
  RawCount: Word;
begin
  Result := False;
  Count := 0;
  FillChar(Frames, SizeOf(Frames), 0);
  ResolveBackTrace;
  if not Assigned(BackTraceFn) then Exit;
  RawCount := BackTraceFn(2, MAX_BACKTRACE_FRAMES, @Frames[0], nil);
  if (RawCount = 0) or (Integer(RawCount) > Length(Frames)) then Exit;
  Count := Integer(RawCount);
  Result := True;
end;

function ClassifyStackFrames(const Frames: TStackFrameArray; Count: Integer;
  out SuspiciousRegion: NativeUInt): Boolean;
var
  I: Integer;
  Kind: TCodeLocation;
  Base, Candidate: NativeUInt;
begin
  Result := False;
  SuspiciousRegion := 0;
  Candidate := 0;
  for I := 0 to Count - 1 do
  begin
    if Frames[I] = nil then Exit;
    if not DescribeStackFrame(NativeUInt(Frames[I]), Kind, Base) then Exit;
    if (Kind = clUnknown) or (Base = 0) then Exit;
    if (Kind = clPrivate) and (Candidate = 0) then Candidate := Base;
  end;
  SuspiciousRegion := Candidate;
  Result := True;
end;

function CaptureCurrentStackOrigin(out SuspiciousRegion: NativeUInt): Boolean;
var
  Frames: TStackFrameArray;
  Count: Integer;
begin
  SuspiciousRegion := 0;
  if not CaptureBackTraceFrames(Frames, Count) then Exit(False);
  Result := ClassifyStackFrames(Frames, Count, SuspiciousRegion);
end;

function StackOriginCandidate(Region: NativeUInt;
  StableSamples: Integer; IndependentEvidence: Boolean): Boolean;
begin
  Result := (Region <> 0) and (StableSamples >= 2) and
    IndependentEvidence;
end;

constructor TThreadStackProvenanceMonitor.Create;
begin inherited Create; Reset; end;

procedure TThreadStackProvenanceMonitor.ClearCandidate;
begin
  FLastObservation := 0;
  FPreviousRegion := 0;
  FConfirmations := 0;
end;

procedure TThreadStackProvenanceMonitor.Reset;
begin
  FLastTick := 0;
  FLastEvidence := 0;
  FLastReport := 0;
  ClearCandidate;
end;

function TThreadStackProvenanceMonitor.EvidenceRecent(Tick: UInt64): Boolean;
begin
  Result := (FLastEvidence <> 0) and (Tick >= FLastEvidence) and
    (Tick - FLastEvidence <= STACK_ORIGIN_EVIDENCE_MS);
end;

procedure TThreadStackProvenanceMonitor.UpdateCandidate(Region, Tick: UInt64);
begin
  if (Region <> 0) and (Region = FPreviousRegion) and
     (FConfirmations <> 0) and (Tick > FLastObservation) and
     (Tick - FLastObservation <= STACK_ORIGIN_EVIDENCE_MS) then
  begin
    if FConfirmations < 3 then Inc(FConfirmations);
  end
  else
  begin
    FPreviousRegion := Region;
    if Region <> 0 then FConfirmations := 1
    else FConfirmations := 0;
  end;
  FLastObservation := Tick;
end;

function TThreadStackProvenanceMonitor.ReportDue(Tick: UInt64): Boolean;
begin
  Result := (FLastReport = 0) or
    ((Tick >= FLastReport) and
     (Tick - FLastReport >= STACK_ORIGIN_COOLDOWN_MS));
end;

procedure TThreadStackProvenanceMonitor.Examine(Baseline,
  ExternalAccess: Boolean; Tick: UInt64;
  var Detected: TDetectionKinds);
var Region: NativeUInt;
begin
  if (FLastTick <> 0) and (Tick < FLastTick) then Reset;
  if ExternalAccess or ((Detected * [dkExecutionProvenance,
    dkPrivateThread, dkStackExecute, dkExecutableLifecycle]) <> []) then
    FLastEvidence := Tick;
  if (FLastTick <> 0) and (Tick >= FLastTick) and
    (Tick - FLastTick < STACK_ORIGIN_SCAN_MS) then Exit;
  FLastTick := Tick;
  try
    if not CaptureCurrentStackOrigin(Region) or Baseline then
    begin
      ClearCandidate;
      Exit;
    end;
  except
    ClearCandidate;
    raise;
  end;
  UpdateCandidate(Region, Tick);
  if StackOriginCandidate(Region, FConfirmations, EvidenceRecent(Tick)) and
     ReportDue(Tick) then
  begin
    Include(Detected, dkThreadStackOrigin);
    FLastReport := Tick;
  end;
end;

{$IFDEF NHW_NATIVE5E_TESTS}
{$I Cozy.NHW.Native5E.ThreadStack.inc}
{$ENDIF}

end.
