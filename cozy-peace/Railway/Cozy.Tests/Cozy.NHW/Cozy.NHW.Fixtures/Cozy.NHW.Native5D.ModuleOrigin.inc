var
  OriginTestModules: array[0..2] of HMODULE;
  OriginTestCount, OriginTestEnumCalls, OriginTestEnumMode: Integer;
  OriginTestNameCalls: Integer;
  OriginTestMissingName: NativeUInt;
  OriginTestAllTemp: Boolean;
  OriginTestLongPath: string;
function OriginTestEnum(Process: THandle; Modules: Pointer;
  Bytes: Cardinal; out Needed: Cardinal): BOOL; stdcall;
var I: Integer; Item: ^HMODULE;
begin
  Inc(OriginTestEnumCalls);
  Needed := Cardinal(OriginTestCount * SizeOf(HMODULE));
  if OriginTestEnumMode = 1 then Exit(False);
  if OriginTestEnumMode = 2 then begin Inc(Needed); Exit(True); end;
  if OriginTestEnumMode = 3 then begin Needed := Bytes + 8; Exit(True); end;
  Item := Modules;
  for I := 0 to OriginTestCount - 1 do
  begin
    Item^ := OriginTestModules[I];
    if (OriginTestEnumMode = 4) and ((OriginTestEnumCalls mod 2) = 0) and
       (I = OriginTestCount - 1) then Item^ := HMODULE($300000);
    Inc(Item);
  end;
  Result := True;
end;
function OriginTestModuleName(Module: HMODULE; Buffer: PWideChar;
  Chars: Cardinal): Cardinal; stdcall;
var V: string; N: Cardinal;
begin
  Inc(OriginTestNameCalls);
  if NativeUInt(Module) = OriginTestMissingName then Exit(0);
  if OriginTestLongPath <> '' then V := OriginTestLongPath
  else if OriginTestAllTemp or (Module = HMODULE($200000)) then V := 'C:\Temp\item.dll'
  else V := 'C:\Windows\System32\item.dll';
  N := Cardinal(Length(V));
  if N >= Chars then
  begin
    if Chars > 1 then Move(PWideChar(V)^, Buffer^, (Chars - 1) * SizeOf(WideChar));
    Exit(Chars);
  end;
  if N > 0 then Move(PWideChar(V)^, Buffer^, N * SizeOf(WideChar));
  Buffer[N] := #0;
  Result := N;
end;
function OriginTestMappedName(Process: THandle; Address: Pointer;
  Buffer: PWideChar; Chars: Cardinal): Cardinal; stdcall;
const V: string = '\Device\HarddiskVolume1\Windows\System32\item.dll';
var N: Cardinal;
begin
  N := Cardinal(Length(V));
  if N >= Chars then Exit(Chars);
  Move(PWideChar(V)^, Buffer^, N * SizeOf(WideChar));
  Buffer[N] := #0;
  Result := N;
end;
function OriginTestVerify(Owner: HWND; Action: Pointer; Data: Pointer): LongInt; stdcall;
begin Result := 1; end; // unsigned; never sufficient on its own
function TestModuleOriginHardening(out Failure: string; out Checks: Integer): Boolean;
var
  EFn: TEnumProcessModulesFn; NFn: TGetModuleFileNameWFn;
  MFn: TGetMappedFileNameWFn; VFn: TWinVerifyTrustFn; ResolvedBefore: Boolean;
  M: TModuleOriginMonitor; Detected: TDetectionKinds;
  Info: TModuleOriginState; Inventory: TArray<HMODULE>; V: string;
  procedure Check(Value: Boolean; const Name: string);
  begin Inc(Checks); if not Value then raise Exception.Create(Name); end;
  procedure Sweep(Tick: UInt64; Baseline: Boolean = False);
  begin
    OriginTestEnumCalls := 0;
    Detected := [dkPrivateThread];
    M.Examine(Baseline, True, Tick, Detected);
  end;
begin
  Result := False; Failure := ''; Checks := 0; M := nil;
  EFn := FEnum; NFn := FModuleFileName; MFn := FMappedName;
  VFn := FVerify; ResolvedBefore := FResolved;
  try
    try
      FResolved := True; FEnum := OriginTestEnum; FModuleFileName := OriginTestModuleName;
      FMappedName := OriginTestMappedName; FVerify := OriginTestVerify;
      OriginTestCount := 1; OriginTestModules[0] := HMODULE($100000);
      OriginTestModules[1] := HMODULE($200000); OriginTestEnumMode := 0;
      OriginTestMissingName := 0; OriginTestAllTemp := False; OriginTestLongPath := '';
      OriginTestEnumCalls := 0;
      Check(ReadModuleInventory(Inventory) and (Length(Inventory) = 1), 'valid inventory');
      OriginTestEnumMode := 2;
      Check(not ReadModuleInventory(Inventory), 'misaligned inventory byte count');
      Check(Length(Inventory) = 0, 'incomplete inventory discarded');
      OriginTestEnumMode := 3;
      Check(not ReadModuleInventory(Inventory), 'oversized inventory rejected');
      OriginTestEnumMode := 0; OriginTestCount := 2; OriginTestModules[1] := OriginTestModules[0];
      Check(not ReadModuleInventory(Inventory), 'duplicate module bases rejected');
      OriginTestModules[1] := HMODULE($200000); OriginTestCount := 1;
      OriginTestNameCalls := 0;
      OriginTestLongPath := 'C:\' + StringOfChar('a', 1400) + '.dll';
      V := ReadModuleName(OriginTestModules[0]);
      Check(V = OriginTestLongPath, 'long path grown without truncation');
      Check(OriginTestNameCalls = 2, 'bounded retry for long name');
      OriginTestLongPath := 'C:\broken' + #0 + '.dll';
      Check(ReadModuleName(OriginTestModules[0]) = '', 'embedded zero name rejected');
      OriginTestLongPath := '';
      M := TModuleOriginMonitor.Create;
      Sweep(10000, True);
      Check((M.FModules.Count = 1) and M.FPrimed, 'baseline committed');
      OriginTestMissingName := $100000;
      Sweep(16000);
      Check(M.FModules.ContainsKey($100000), 'failed name does not unload module');
      Info := M.FModules[$100000];
      Check(Info.ModulePath <> '', 'last known path retained');
      Check(Info.SuspectSamples = 0, 'unknown sample breaks confirmation');
      OriginTestMissingName := 0; Sweep(22000);
      Check(not (dkModuleOrigin in Detected), 'recovered baseline not new module');
      OriginTestCount := 2; Sweep(28000);
      Info := M.FModules[$200000];
      Check(Info.PendingCandidate and (Info.SuspectSamples = 1), 'new suspicious candidate tracked');
      Check(not (dkModuleOrigin in Detected), 'single candidate insufficient');
      OriginTestMissingName := $200000; Sweep(34000);
      Info := M.FModules[$200000];
      Check((Info.SuspectSamples = 0) and Info.PendingCandidate, 'gap preserves candidate not confirmation');
      OriginTestMissingName := 0; Sweep(40000);
      Check(not (dkModuleOrigin in Detected), 'one post-gap sample insufficient');
      Sweep(46000);
      Check(dkModuleOrigin in Detected, 'two post-gap samples with external evidence detect');
      OriginTestEnumMode := 1; Sweep(52000);
      Check((M.FModules.Count = 2) and M.FContinuityBroken, 'failed inventory preserves module state');
      OriginTestEnumMode := 4; Sweep(58000);
      Check(M.FModules.ContainsKey($200000) and not M.FModules.ContainsKey($300000), 'changed second view not committed');
      Check(not (dkModuleOrigin in Detected), 'changing inventory has no staged detection');
      OriginTestEnumMode := 0; OriginTestCount := 1; Sweep(64000);
      Check(not M.FModules.ContainsKey($200000), 'two complete views confirm disappearance');
      OriginTestCount := 2; Sweep(70000);
      Info := M.FModules[$200000];
      Check(Info.PendingCandidate and not Info.Reported, 'real reappearance gets fresh state');
      M.Reset; OriginTestCount := 1; OriginTestAllTemp := True;
      OriginTestMissingName := $100000; Sweep(100000, True);
      Info := M.FModules[$100000];
      Check((Info.ModulePath = '') and not Info.PendingCandidate, 'baseline placeholder is not new');
      OriginTestMissingName := 0; Sweep(106000); Sweep(112000);
      Check(not (dkModuleOrigin in Detected), 'late baseline name not classified as fresh load');
      Check(not ModuleOriginCandidate('C:\Temp\a.dll', '\Device\x\a.dll', False, False, True), 'unknown signature not untrusted');
      Check(not ModuleOriginCandidate('C:\Temp\a.dll', '\Device\x\a.dll', True, True, True), 'trusted signature not candidate');
      Result := True;
    except on E: Exception do Failure := E.Message; end;
  finally
    M.Free;
    FEnum := EFn; FModuleFileName := NFn; FMappedName := MFn;
    FVerify := VFn; FResolved := ResolvedBefore;
    OriginTestLongPath := '';
  end;
end;
