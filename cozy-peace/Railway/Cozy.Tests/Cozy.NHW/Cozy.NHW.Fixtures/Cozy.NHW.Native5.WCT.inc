var
  TestWCTErrorCode: Cardinal;
  TestWCTOpens, TestWCTGets, TestWCTCloses, TestWCTMode: Integer;

procedure TestSetWCTError(Code: Cardinal); stdcall;
begin TestWCTErrorCode := Code; end;
function TestOpenWCT(Flags: Cardinal; Callback: TWCTCallback): THandle; stdcall;
begin
  Inc(TestWCTOpens);
  if (Flags <> 1) or not Assigned(Callback) then Exit(0);
  Result := 1234;
end;
function TestGetWCT(Session: THandle; Context: NativeUInt;
  Flags, ThreadId: Cardinal; Count: PCardinal;
  Nodes: PWaitChainNode; Cycle: PWindowsBool): BOOL; stdcall;
begin
  Inc(TestWCTGets);
  if TestWCTMode = 0 then
  begin
    Count^ := 11; Nodes^.ObjectType := 8; Cycle^ := True;
    TestWCTErrorCode := ERROR_IO_PENDING;
    Exit(False);
  end;
  if TestWCTMode = 1 then Count^ := WCT_MAX_NODE_COUNT + 1
  else Count^ := 1;
  Result := True;
end;
procedure TestCloseWCT(Session: THandle); stdcall;
begin Inc(TestWCTCloses); end;
procedure TestCallbackWCT(Session: THandle; Context: NativeUInt;
  CallbackStatus: Cardinal; NodeCount: PCardinal;
  Nodes: PWaitChainNode; IsCycle: PWindowsBool); stdcall;
begin end;

function TestWCTNativeHardening(out Failure: string; out Checks: Integer): Boolean;
var
  Saved: TWCTAPI;
  Count: Cardinal;
  Nodes: array[0..WCT_MAX_NODE_COUNT-1] of TWaitChainNode;
  Cycle: BOOL;
  procedure Check(Value: Boolean; const Name: string);
  begin
    Inc(Checks);
    if not Value then raise Exception.Create(Name);
  end;
begin
  Checks := 0; Failure := ''; Result := False;
  Saved := APIs;
  try
    try
      APIs.OpenSession := TestOpenWCT;
      APIs.GetChain := TestGetWCT;
      APIs.CloseSession := TestCloseWCT;
      APIs.SetError := TestSetWCTError;
      TestWCTOpens := 0; TestWCTGets := 0; TestWCTCloses := 0;
      TestWCTMode := 0; TestWCTErrorCode := 0;
      FillChar(Nodes, SizeOf(Nodes), 0); Count := 16; Cycle := False;
      Check(WCTAvailable, 'WCT ABI');
      Check(WCTOpen(nil) = 0, 'nil callback rejected');
      Check((TestWCTErrorCode = ERROR_INVALID_PARAMETER) and (TestWCTOpens = 0), 'nil callback does not call API');
      Check(WCTOpen(@TestCallbackWCT) = 1234, 'async open retained');
      Check(not WCTRequestValid(0, 0, 1, @Count, @Nodes[0], @Cycle), 'invalid session');
      Check(not WCTRequestValid(1234, 8, 1, @Count, @Nodes[0], @Cycle), 'unknown flags');
      Check(not WCTRequestValid(1234, 0, 0, @Count, @Nodes[0], @Cycle), 'zero thread');
      Check(not WCTRequestValid(1234, 0, 1, nil, @Nodes[0], @Cycle), 'nil count');
      Check(not WCTRequestValid(1234, 0, 1, @Count, nil, @Cycle), 'nil nodes');
      Check(not WCTRequestValid(1234, 0, 1, @Count, @Nodes[0], nil), 'nil cycle');
      Count := 0;
      Check(not WCTGet(1234, 0, 0, 1, @Count, @Nodes[0], @Cycle), 'zero capacity');
      Count := 17;
      Check(not WCTGet(1234, 0, 0, 1, @Count, @Nodes[0], @Cycle), 'oversized capacity');
      Check(TestWCTGets = 0, 'invalid requests never submitted');
      Count := 16;
      Check(not WCTRequestValid(1234, 0, 1, @Count,
        PWaitChainNode(High(NativeUInt)-NativeUInt(4)), @Cycle), 'node range overflow');
      Check(not WCTGet(1234, 5, 5, 1, @Count, @Nodes[0], @Cycle), 'async pending remains false');
      Check(TestWCTErrorCode = ERROR_IO_PENDING, 'pending error preserved');
      Check((Count = 11) and (Nodes[0].ObjectType = 8) and Cycle, 'pending outputs not cleared');
      TestWCTMode := 1; Count := 16;
      Check(not WCTGet(1234, 0, 0, 1, @Count, @Nodes[0], @Cycle), 'bad successful count rejected');
      Check(TestWCTErrorCode = ERROR_INVALID_DATA, 'bad count error');
      TestWCTMode := 2; Count := 16;
      Check(WCTGet(1234, 0, 0, 1, @Count, @Nodes[0], @Cycle) and (Count = 1), 'bounded success');
      WCTClose(0); Check(TestWCTCloses = 0, 'close zero no-op');
      WCTClose(1234); Check(TestWCTCloses = 1, 'native close dispatched');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    APIs := Saved;
  end;
end;
