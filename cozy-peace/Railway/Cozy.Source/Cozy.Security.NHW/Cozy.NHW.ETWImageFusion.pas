unit Cozy.NHW.ETWImageFusion;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  Cozy.NHW.ETWTypes,
  Cozy.NHW.Logging;

type
  // v40: image-load events are commonplace and never warnings by themselves.
  // Fusion requires independent external access and origin anomalies.
  TETWImageFusionMonitor = class
  private
    FLastLoadTick: UInt64;
    FLastExternalTick: UInt64;
    FLastThreadTick: UInt64;
    FLastReport: UInt64;
    FTargetPID: Cardinal;
    FLastExamineTick: UInt64;
    FEvidenceFloorTick: UInt64;
    FHaveEvidenceFloor: Boolean;
    procedure BreakEvidence(Tick: UInt64);
  public
    constructor Create;
    procedure Reset;
    procedure Examine(const Events: TKernelEventList; TargetPID: Cardinal;
      Baseline, TraceLost, HighExternalAccess: Boolean;
      Tick: UInt64; var Detected: TDetectionKinds);
  end;

{$IFDEF NHW_NATIVE5I_TESTS}
function TestETWImage5I(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  Cozy.NHW.SignalCorrelation
{$IFDEF NHW_NATIVE5I_TESTS}
  , System.SysUtils
{$ENDIF}
  ;

const
  IMAGE_WINDOW_MS = 8000;
  IMAGE_COOLDOWN_MS = 20000;

constructor TETWImageFusionMonitor.Create;
begin
  inherited Create;
  Reset;
end;

procedure TETWImageFusionMonitor.Reset;
begin
  FLastLoadTick := 0;
  FLastExternalTick := 0;
  FLastThreadTick := 0;
  FLastReport := 0;
  FTargetPID := 0;
  FLastExamineTick := 0;
  FEvidenceFloorTick := 0;
  FHaveEvidenceFloor := False;
end;

procedure TETWImageFusionMonitor.BreakEvidence(Tick: UInt64);
begin
  FLastLoadTick := 0;
  FLastExternalTick := 0;
  FLastThreadTick := 0;
  FEvidenceFloorTick := Tick;
  FHaveEvidenceFloor := True;
  // Keep the report cooldown: a coverage failure is not a new incident.
end;

procedure TETWImageFusionMonitor.Examine(const Events: TKernelEventList;
  TargetPID: Cardinal; Baseline, TraceLost, HighExternalAccess: Boolean;
  Tick: UInt64; var Detected: TDetectionKinds);

  procedure ObserveImageLoads;
  var
    E: TKernelEvent;
  begin
    for E in Events do
      if (E.Kind = keImageLoad) and (E.PID = TargetPID) and
         (E.Tick <> 0) and (E.Tick <= Tick) and
         (Tick - E.Tick <= IMAGE_WINDOW_MS) and
         (not FHaveEvidenceFloor or (E.Tick > FEvidenceFloorTick)) and
         (E.Tick > FLastLoadTick) then
        FLastLoadTick := E.Tick; // batch order cannot move evidence backwards
  end;

  procedure ObserveIndependentEvidence;
  begin
    if HighExternalAccess then FLastExternalTick := Tick;
    if (Detected * [dkRemoteThread, dkPrivateThread]) <> [] then
      FLastThreadTick := Tick;
  end;

  procedure ReportFusionIfDue;
  begin
    if RecentSignal(FLastLoadTick, Tick, IMAGE_WINDOW_MS) and
       RecentSignal(FLastExternalTick, Tick, IMAGE_WINDOW_MS) and
       RecentSignal(FLastThreadTick, Tick, IMAGE_WINDOW_MS) and
       ((FLastReport = 0) or
        not RecentSignal(FLastReport, Tick, IMAGE_COOLDOWN_MS)) then
    begin
      Include(Detected, dkETWImageFusion);
      FLastReport := Tick;
    end;
  end;
begin
  if TargetPID = 0 then begin Reset; Exit; end;
  if Baseline or ((FTargetPID <> 0) and (FTargetPID <> TargetPID)) or
     ((FLastExamineTick <> 0) and (Tick < FLastExamineTick)) then
  begin
    Reset;
    FTargetPID := TargetPID;
    FLastExamineTick := Tick;
    BreakEvidence(Tick);
    Exit;
  end;
  FTargetPID := TargetPID;
  FLastExamineTick := Tick;
  if TraceLost or (Events = nil) then
  begin
    BreakEvidence(Tick);
    Exit;
  end;
  if FHaveEvidenceFloor and (Tick <= FEvidenceFloorTick) then Exit;
  try
    ObserveImageLoads;
    ObserveIndependentEvidence;
    ReportFusionIfDue;
  except
    BreakEvidence(Tick);
    raise;
  end;
end;

{$IFDEF NHW_NATIVE5I_TESTS}
{$I Cozy.NHW.Native5I.ETWImage.inc}
{$ENDIF}

end.
