var
  TestTcpCalls, TestTcpMode: Integer;
function TestTcpTable(Buffer: Pointer; var Size: Cardinal;
  Order: BOOL; AF, TableKind, Reserved: Cardinal): Cardinal; stdcall;
begin
  if Buffer = nil then begin Size := 4; Exit(ERROR_INSUFFICIENT_BUFFER); end;
  Inc(TestTcpCalls);
  if (TestTcpMode = 1) or ((TestTcpMode = 2) and (TestTcpCalls = 1)) then
  begin Inc(Size, 24); Exit(ERROR_INSUFFICIENT_BUFFER); end;
  if TestTcpMode = 3 then begin Inc(Size, 1); Exit(0); end;
  if TestTcpMode = 4 then Exit(ERROR_INSUFFICIENT_BUFFER);
  PCardinal(Buffer)^ := 0;
  Size := 4;
  Result := 0;
end;
function TestCaptureNativeHardening(out Failure: string; out Checks: Integer): Boolean;
var
  B: TBytes;
  L: TCaptureProcessList;
  PIDs: TCapturePIDSet;
  P: ^TProcessPrefix;
  Row: PTcpRowNative;
  SavedTCP: TGetTCPTable;
  SavedKernel, SavedServices, SavedTcpReady: Boolean;
  procedure Check(V: Boolean; const Name: string);
  begin Inc(Checks); if not V then raise Exception.Create(Name); end;
  procedure ProcessData;
  begin
    SetLength(B, 96); FillChar(B[0], Length(B), 0);
    P := Pointer(@B[0]); P^.UniqueProcessId := THandle(123);
    P^.ImageName.Buffer := PWideChar(@B[88]);
    P^.ImageName.Length := 2; P^.ImageName.MaximumLength := 4;
    PWord(@B[88])^ := Ord('X');
  end;
  procedure TcpMode(N: Integer);
  begin TestTcpMode := N; TestTcpCalls := 0; end;
begin
  Result := False; Failure := ''; Checks := 0;
  L := TCaptureProcessList.Create; PIDs := TCapturePIDSet.Create;
  SavedTCP := GetTCPPtr; SavedKernel := KernelResolved;
  SavedServices := ServicesResolved; SavedTcpReady := TcpResolved;
  try
    try
      ProcessData;
      Check(ParseCaptureProcesses(B, L) and (L.Count = 1), 'valid process record');
      Check((L[0].PID = 123) and (L[0].Name = 'X'), 'bounded process name');
      P^.NextEntryOffset := 96;
      Check(not ParseCaptureProcesses(B, L), 'next record header missing');
      Check(L.Count = 0, 'partial process list discarded');
      P^.NextEntryOffset := 1;
      Check(not ParseCaptureProcesses(B, L), 'unaligned process offset');
      ProcessData; P^.ImageName.Buffer := PWideChar(@B[0]);
      Check(not ParseCaptureProcesses(B, L), 'name overlaps header');
      ProcessData; P^.ImageName.Length := 3;
      Check(not ParseCaptureProcesses(B, L), 'odd process name bytes');
      ProcessData; P^.ImageName.MaximumLength := 0;
      Check(not ParseCaptureProcesses(B, L), 'length exceeds max length');
      ProcessData; P^.UniqueProcessId := THandle(UInt64(High(Cardinal)) + 1);
      Check(not ParseCaptureProcesses(B, L), 'oversized PID');
      ProcessData; PWord(@B[88])^ := 0;
      Check(not ParseCaptureProcesses(B, L), 'NUL process name');
      Check(not ParseCaptureProcesses(B, nil), 'nil process collection');
      B := nil; Check(not ParseCaptureProcesses(B, L), 'empty process response');
      SetLength(B, 28); FillChar(B[0], Length(B), 0);
      PCardinal(@B[0])^ := 1; Row := Pointer(@B[4]);
      Row^.State := 2; Row^.OwnerPID := 123;
      Check(ParseCaptureListeners(B, 28, PIDs) and PIDs.ContainsKey(123), 'listener parsed');
      Check(not ParseCaptureListeners(B, 29, PIDs), 'returned bytes beyond allocation');
      Check(PIDs.Count = 0, 'listener failure clears output');
      PCardinal(@B[0])^ := 2;
      Check(not ParseCaptureListeners(B, 28, PIDs), 'listener count overflow');
      PCardinal(@B[0])^ := 1; Row^.State := 5;
      Check(not ParseCaptureListeners(B, 28, PIDs), 'non-listener row rejected');
      PCardinal(@B[0])^ := 0;
      Check(ParseCaptureListeners(B, 4, PIDs) and (PIDs.Count = 0), 'valid empty table');
      GetTCPPtr := TestTcpTable;
      KernelResolved := True; ServicesResolved := True; TcpResolved := True;
      TcpMode(2); Check(RefreshProxyListeners(PIDs), 'growing TCP table retry');
      Check(TestTcpCalls = 2, 'TCP retried once');
      TcpMode(1); Check(not RefreshProxyListeners(PIDs), 'unbounded TCP growth rejected');
      Check((TestTcpCalls = 3) and (PIDs.Count = 0), 'TCP retry cap');
      TcpMode(3); Check(not RefreshProxyListeners(PIDs), 'TCP success cannot exceed capacity');
      TcpMode(4); Check(not RefreshProxyListeners(PIDs), 'TCP non-progress retry refused');
      Check(TestTcpCalls = 1, 'non-progress query called once');
      Result := True;
    except on E: Exception do Failure := E.Message; end;
  finally
    GetTCPPtr := SavedTCP; KernelResolved := SavedKernel;
    ServicesResolved := SavedServices; TcpResolved := SavedTcpReady;
    L.Free; PIDs.Free;
  end;
end;
