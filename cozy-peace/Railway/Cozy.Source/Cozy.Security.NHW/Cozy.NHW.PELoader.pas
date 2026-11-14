unit Cozy.NHW.PELoader;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  Cozy.NHW.Logging,
  Cozy.NHW.PERules;

type
  TPELoaderMonitor = class
  private
    FHeader: TPEWatchCell;
    FSections: TPEWatchCell;
    FRelocations: TPEWatchCell;
    FTLS: TPEWatchCell;
    FLoadConfig: TPEWatchCell;
    FDirectories: TPEWatchCell;
    FLastTick: UInt64;
    procedure InvalidateCandidates;
  public
    constructor Create;
    procedure Reset;
    procedure Examine(Baseline: Boolean; Tick: UInt64;
      var Detected: TDetectionKinds);
  end;

{$IFDEF NHW_NATIVE10M_TESTS}
function TestPELoader10M(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  Cozy.NHW.PENative{$IFDEF NHW_NATIVE10M_TESTS}, System.SysUtils{$ENDIF};

{$IFDEF NHW_NATIVE10M_TESTS}
{$I Cozy.NHW.Native10M.PELoader.Hooks.inc}
{$ENDIF}

const
  PE_CHECK_INTERVAL_MS = 2500;

constructor TPELoaderMonitor.Create;
begin
  inherited Create;
  Reset;
end;

procedure TPELoaderMonitor.Reset;
begin
  FHeader := Default(TPEWatchCell);
  FSections := Default(TPEWatchCell);
  FRelocations := Default(TPEWatchCell);
  FTLS := Default(TPEWatchCell);
  FLoadConfig := Default(TPEWatchCell);
  FDirectories := Default(TPEWatchCell);
  FLastTick := 0;
end;

procedure BreakPEObservation(var Cell: TPEWatchCell);
begin
  Cell.Fingerprint.CandidateCount := 0;
  if not Cell.Fingerprint.AlreadyReported then
    Cell.Fingerprint.Candidate := Cell.Fingerprint.Baseline;
  Cell.Invalid.Consecutive := 0;
  // Do not clear HasBaseline, Baseline or already-reported suppression on UNKNOWN.
end;

function ObservePEFeature(var Cell: TPEWatchCell;
  const Feature: TPEFeature; Baseline: Boolean): Boolean;
begin
  if not Feature.Available then
  begin
    BreakPEObservation(Cell);
    Exit(False);
  end;
  // Invalid metadata and changed valid metadata are different candidates.
  if not Feature.Valid then
  begin
    Cell.Fingerprint.CandidateCount := 0;
    if not Cell.Fingerprint.AlreadyReported then
      Cell.Fingerprint.Candidate := Cell.Fingerprint.Baseline;
  end;
  Result := PEObserve(Cell, Feature, Baseline);
end;

procedure TPELoaderMonitor.InvalidateCandidates;
begin
  BreakPEObservation(FHeader);
  BreakPEObservation(FSections);
  BreakPEObservation(FRelocations);
  BreakPEObservation(FTLS);
  BreakPEObservation(FLoadConfig);
  BreakPEObservation(FDirectories);
end;

function CaptureLoaderImage(Monitor: TPELoaderMonitor;
  out Image: TPEImageSnapshot): Boolean;
begin
  Result := False;
  try
    if not CapturePEImage(Image) then
    begin
      Monitor.InvalidateCandidates;
      Exit;
    end;
    Result := True;
  except
    Monitor.InvalidateCandidates;
    raise;
  end;
end;

procedure ApplyLoaderImage(Monitor: TPELoaderMonitor;
  const Image: TPEImageSnapshot; Baseline: Boolean;
  var Detected: TDetectionKinds);
begin
  if ObservePEFeature(Monitor.FHeader, Image.Header, Baseline) then
    Include(Detected, dkPEHeader);
  if ObservePEFeature(Monitor.FSections, Image.Sections, Baseline) then
    Include(Detected, dkSectionMapping);
  if ObservePEFeature(Monitor.FRelocations, Image.Relocations, Baseline) then
    Include(Detected, dkRelocation);
  if ObservePEFeature(Monitor.FTLS, Image.TLSDirectory, Baseline) then
    Include(Detected, dkTLSDirectory);
  if ObservePEFeature(Monitor.FLoadConfig, Image.LoadConfig, Baseline) then
    Include(Detected, dkLoadConfig);
  if ObservePEFeature(Monitor.FDirectories, Image.Directories, Baseline) then
    Include(Detected, dkDirectoryBounds);
end;

procedure TPELoaderMonitor.Examine(Baseline: Boolean; Tick: UInt64;
  var Detected: TDetectionKinds);
var Image: TPEImageSnapshot;
begin
  if not Baseline and (FLastTick <> 0) and (Tick >= FLastTick) and
     ((Tick - FLastTick) < PE_CHECK_INTERVAL_MS) then Exit;
  FLastTick := Tick;
  if not CaptureLoaderImage(Self, Image) then Exit;
  ApplyLoaderImage(Self, Image, Baseline, Detected);
end;

{$IFDEF NHW_NATIVE10M_TESTS}
{$I Cozy.NHW.Native10M.PELoader.inc}
{$ENDIF}

end.
