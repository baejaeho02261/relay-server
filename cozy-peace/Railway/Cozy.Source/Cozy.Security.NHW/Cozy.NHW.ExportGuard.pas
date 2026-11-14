unit Cozy.NHW.ExportGuard;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  Cozy.NHW.Logging,
  Cozy.NHW.ExportRules;

type
  TExportGuardMonitor = class
  private
    FWatch: TExportWatch;
    FBases: array[0..3] of NativeUInt;
    FLastTick: UInt64;
    FReady: Boolean;
    procedure ResetWatch;
    procedure BreakCandidates;
  public
    constructor Create;
    procedure Reset;
    procedure Examine(Baseline: Boolean; Tick: UInt64;
      var Detected: TDetectionKinds);
  end;

{$IFDEF NHW_NATIVE10N_TESTS}
function TestExportGuard10N(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  {$IFDEF NHW_NATIVE10N_TESTS} System.SysUtils, {$ENDIF}
  Cozy.NHW.WinPointers,
  Cozy.NHW.PERules,
  Cozy.NHW.ExportNative;

const
  CHECK_MS = 3500;

constructor TExportGuardMonitor.Create;
begin
  inherited Create;
  Reset;
end;

procedure TExportGuardMonitor.ResetWatch;
begin
  FWatch := Default(TExportWatch);
  FLastTick := 0;
end;

procedure TExportGuardMonitor.BreakCandidates;
begin
  PEObservationGap(FWatch.Table);
  PEObservationGap(FWatch.Forwarder);
  PEObservationGap(FWatch.ApiSet);
  DelayImportObservationGap(FWatch);
  PEObservationGap(FWatch.Target);
  PEObservationGap(FWatch.Resolution);
end;

procedure TExportGuardMonitor.Reset;
begin
  ResetWatch;
  // Query only pre-existing mapped modules. Do not LoadLibrary or mutate the
  // target. Image-base identities are fixed for one monitor lifetime.
  FBases[0] := NativeUInt(HInstance);
  FBases[1] := NativeUInt(WinModule('ntdll.dll'));
  FBases[2] := NativeUInt(WinModule('kernel32.dll'));
  FBases[3] := NativeUInt(WinModule('kernelbase.dll'));
  FReady := (FBases[1] <> 0) and (FBases[2] <> 0);
end;

function CaptureGuardSnapshot(Monitor: TExportGuardMonitor;
  out Snap: TExportSnapshot): Boolean;
begin
  Result := False;
  try
    if not CaptureExportSnapshot(Monitor.FBases, Snap) then
    begin
      Monitor.BreakCandidates;
      Exit;
    end;
    Result := True;
  except
    Monitor.BreakCandidates;
    raise;
  end;
end;

procedure ApplyGuardSnapshot(Monitor: TExportGuardMonitor;
  const Snap: TExportSnapshot; Baseline: Boolean;
  var Detected: TDetectionKinds);
var
  NewTable, NewForwarder, NewApiSet, NewDelay: Boolean;
  NewTarget, NewResolution: Boolean;
begin
  NewTable := PEObserve(Monitor.FWatch.Table, Snap.Table, Baseline);
  NewForwarder := PEObserve(Monitor.FWatch.Forwarder, Snap.Forwarder, Baseline);
  NewApiSet := PEObserve(Monitor.FWatch.ApiSet, Snap.ApiSet, Baseline);
  NewDelay := False;
  if not Snap.DelayImport.Available or not Snap.DelayImport.Valid then
    DelayImportObservationGap(Monitor.FWatch)
  else
    NewDelay := ObserveDelayImportSlots(Monitor.FWatch, Snap.DelaySlots, Baseline);
  NewTarget := PEObserve(Monitor.FWatch.Target, Snap.Target, Baseline);
  NewResolution := PEObserve(Monitor.FWatch.Resolution, Snap.Resolution, Baseline);
  if NewTable then Include(Detected, dkExportTable);
  if NewForwarder then Include(Detected, dkExportForwarder);
  if NewApiSet then Include(Detected, dkAPISet);
  if NewDelay then Include(Detected, dkDelayImport);
  if NewTarget then Include(Detected, dkExportTarget);
  if NewResolution or (NewTable and NewTarget) then
    Include(Detected, dkResolution);
end;

procedure TExportGuardMonitor.Examine(Baseline: Boolean; Tick: UInt64;
  var Detected: TDetectionKinds);
var Snap: TExportSnapshot;
begin
  if not FReady then
  begin
    BreakCandidates;
    Exit;
  end;
  if not Baseline and (FLastTick <> 0) and (Tick >= FLastTick) and
     (Tick - FLastTick < CHECK_MS) then Exit;
  FLastTick := Tick;
  if not CaptureGuardSnapshot(Self, Snap) then Exit;
  ApplyGuardSnapshot(Self, Snap, Baseline, Detected);
end;

{$IFDEF NHW_NATIVE10N_TESTS}
{$I Cozy.NHW.Native10N.ExportGuard.inc}
{$ENDIF}

end.
