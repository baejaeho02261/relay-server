var
  Capture5LClock, Capture5LCost: UInt64;
  Capture5LCalls, Capture5LMode, Capture5LClockReads: Integer;
  Capture5LBackwards: Boolean;
function WinTick64: UInt64;
begin
  Inc(Capture5LClockReads);
  Result := Capture5LClock;
  if Capture5LBackwards and (Capture5LClockReads = 2) then Result := 900;
end;
function WinCurrentProcessId: Cardinal;
begin Result := 1; end;
function RefreshCaptureProcesses(List: TCaptureProcessList): Boolean;
begin Result := False; end;
function CaptureDriverFamilies: TCaptureFamilies;
begin Result := []; end;
function RefreshProxyListeners(OutPIDs: TCapturePIDSet): Boolean;
begin OutPIDs.Clear; Result := True; end;
function InspectCaptureModules(PID: Cardinal; out ImagePath: string;
  out CreateTime: UInt64; out Families: TCaptureFamilies): Boolean;
begin
  Inc(Capture5LCalls); Inc(Capture5LClock, Capture5LCost);
  ImagePath := 'C:\app.exe'; CreateTime := UInt64(PID) + 100;
  Families := [];
  Result := Capture5LMode <> 0;
  if Capture5LMode = 2 then ImagePath := 'C:\other.exe';
end;
