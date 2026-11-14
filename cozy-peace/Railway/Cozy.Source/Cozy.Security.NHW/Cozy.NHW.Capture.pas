unit Cozy.NHW.Capture;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Generics.Collections,
  Cozy.NHW.CaptureNative,
  Cozy.NHW.CaptureRules,
  Cozy.NHW.Logging;

type
  TCaptureMonitor = class
  private
    FProcesses: TCaptureProcessList;
    FSeen: TDictionary<string, TCaptureSignals>;
    FListeners: TCapturePIDSet;
    FIndex: Integer;
    FNextRefresh: UInt64;
    FLastStatus: UInt64;
    FPrimed: Boolean;
    FSnapshotValid: Boolean;
    FDrivers: TCaptureFamilies;
    FListenersValid: Boolean;
    procedure Refresh(Tick: UInt64);
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure Examine(Tick: UInt64; var Detected: TDetectionKinds);
  end;

{$IFDEF NHW_NATIVE5L_TESTS}
function TestCapture5L(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  Cozy.NHW.WinPointers;

const
  PROCESS_REFRESH_MS = 12000;
  DRIVER_REFRESH_MS = 12000;
  PROCESS_BUDGET_PER_TICK = 12;
  // Time budget prevents high PID counts from swamping v27's 500-ms loop.
  SCAN_WORK_BUDGET_MS = 80;

{$IFDEF NHW_NATIVE5L_TESTS}
{$I Cozy.NHW.Native5L.Capture.Hooks.inc}
{$ENDIF}

constructor TCaptureMonitor.Create;
begin
  inherited Create;
  FProcesses := TCaptureProcessList.Create;
  FSeen := TDictionary<string, TCaptureSignals>.Create;
  FListeners := TCapturePIDSet.Create;
  Reset;
end;

destructor TCaptureMonitor.Destroy;
begin
  FListeners.Free;
  FSeen.Free;
  FProcesses.Free;
  inherited Destroy;
end;

procedure TCaptureMonitor.Reset;
begin
  FProcesses.Clear;
  FSeen.Clear;
  FListeners.Clear;
  FIndex := 0;
  FNextRefresh := 0;
  FLastStatus := 0;
  FPrimed := False;
  FSnapshotValid := False;
  FListenersValid := False;
  FDrivers := [];
end;

procedure TCaptureMonitor.Refresh(Tick: UInt64);
var
  Complete: Boolean;
begin
  Complete := RefreshCaptureProcesses(FProcesses);
  if not Complete then Exit; // no false first-baseline on failed discovery
  FSnapshotValid := True;
  FIndex := 0;
  FNextRefresh := Tick + PROCESS_REFRESH_MS;
end;

procedure TCaptureMonitor.Examine(Tick: UInt64;
  var Detected: TDetectionKinds);
var
  P: TCaptureProcessInfo;
  Families: TCaptureFamilies;
  Image: string;
  Created: UInt64;
  T0, WorkTick: UInt64;
  N: Integer;
  procedure RefreshCaptureInputs;
  begin
    // Do not restart a long process sweep before it reaches the final PID.
    // Otherwise the first baseline might never complete on busy systems.
    if (not FSnapshotValid) or
       ((FIndex >= FProcesses.Count) and (Tick >= FNextRefresh)) then
      Refresh(Tick);

    if (FLastStatus = 0) or (Tick >= FLastStatus + DRIVER_REFRESH_MS) then
    begin
      FDrivers := CaptureDriverFamilies;
      FListenersValid := RefreshProxyListeners(FListeners);
      FLastStatus := Tick;
    end;
  end;

  function TryInspectCurrentProcess(out Image: string; out Created: UInt64;
    out Families: TCaptureFamilies): Boolean;
  begin
    Result := False;
    Families := [];
    if not InspectCaptureModules(P.PID, Image, Created, Families) then
      Exit; // no inference from inaccessible or partial module lists
    if not SameText(ExtractFileName(Image), P.Name) then
      Exit; // PID changed or process snapshot no longer matches
    Result := True;
  end;

  procedure ApplyCurrentSignals;
  var
    Key: string;
    Current, Old, NewSignals: TCaptureSignals;
    Listening: Boolean;
    S: TCaptureSignal;
  begin
    Listening := FListenersValid and FListeners.ContainsKey(P.PID);
    Current := ClassifyCapture(P.Name, Image, Families, FDrivers, Listening);
    if Current <> [] then
    begin
      Key := IntToStr(P.PID) + ':' + IntToStr(Int64(Created));
      if not FSeen.TryGetValue(Key, Old) then Old := [];
      NewSignals := Current - Old;
      FSeen.AddOrSetValue(Key, Old + Current);
      if FPrimed and (NewSignals <> []) then
      begin
        for S := Low(TCaptureSignal) to High(TCaptureSignal) do
          if S in NewSignals then
            case S of
              csClient: Include(Detected, dkCaptureClient);
              csLibrary: Include(Detected, dkCaptureLibrary);
              csDriver: Include(Detected, dkCaptureDriver);
              csProxy: Include(Detected, dkCaptureProxy);
              csCorrelation: Include(Detected, dkCaptureCorrelation);
            end;
      end;
    end;
  end;

begin
  RefreshCaptureInputs;

  T0 := WinTick64;
  N := 0;
  while FIndex < FProcesses.Count do
  begin
    // Budget attempts, not successful inspections. Every Continue returns
    // through these guards, including inaccessible and stale PID entries.
    if N >= PROCESS_BUDGET_PER_TICK then Break;
    WorkTick := WinTick64;
    if WorkTick < T0 then Break;
    if WorkTick - T0 >= SCAN_WORK_BUDGET_MS then Break;
    P := FProcesses[FIndex];
    Inc(FIndex);
    Inc(N);
    if P.PID = WinCurrentProcessId then Continue;

    if not TryInspectCurrentProcess(Image, Created, Families) then Continue;

    ApplyCurrentSignals;
  end;
  if FSnapshotValid and (FIndex >= FProcesses.Count) then
    FPrimed := True;
end;

{$IFDEF NHW_NATIVE5L_TESTS}
{$I Cozy.NHW.Native5L.Capture.inc}
{$ENDIF}

end.
