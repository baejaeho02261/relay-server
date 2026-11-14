var
  TestNetMode, TestNetPageCalls, TestNetFreeCalls, TestNetCloseCalls: Integer;
  TestNetRouteMode, TestNetRouteCalls, TestNetRegMode, TestNetRegCalls: Integer;
  TestNetKey: TGUID;
  TestNetItems: array[0..WFP_PAGE_COUNT-1] of Pointer;

function TestNetMake(Engine: THandle; Template: Pointer;
  var EnumHandle: THandle): Cardinal; stdcall;
begin EnumHandle := 55; Result := 0; end;
function TestNetPage(Engine, EnumHandle: THandle; Requested: Cardinal;
  var Entries: Pointer; var Returned: Cardinal): Cardinal; stdcall;
var I: Integer;
begin
  Inc(TestNetPageCalls);
  for I := 0 to High(TestNetItems) do TestNetItems[I] := @TestNetKey;
  Entries := @TestNetItems[0]; Returned := 1;
  case TestNetMode of
    1: Exit(5);
    2: Returned := WFP_PAGE_COUNT + 1;
    3: begin Entries := nil; Returned := 1; end;
    4: begin
         if TestNetPageCalls > 1 then Exit(5);
         Returned := WFP_PAGE_COUNT;
       end;
    5: Returned := WFP_PAGE_COUNT;
  end;
  Result := 0;
end;
function TestNetDestroy(Engine, EnumHandle: THandle): Cardinal; stdcall;
begin Inc(TestNetCloseCalls); Result := 0; end;
procedure TestNetFree(var P: Pointer); stdcall;
begin Inc(TestNetFreeCalls); P := nil; end;
function TestNetRoutes(Table: Pointer; var Size: Cardinal; Ordered: BOOL): Cardinal; stdcall;
var R: PIpForwardRow;
begin
  Inc(TestNetRouteCalls);
  if TestNetRouteMode = 1 then Exit(ERROR_NO_DATA_VALUE);
  if Table = nil then begin Size := 4; Exit(ERROR_INSUFFICIENT_BUFFER_VALUE); end;
  if TestNetRouteMode = 2 then begin Inc(Size, 64); Exit(ERROR_INSUFFICIENT_BUFFER_VALUE); end;
  if TestNetRouteMode = 3 then Exit(ERROR_INSUFFICIENT_BUFFER_VALUE);
  if Size < 60 then begin Size := 60; Exit(ERROR_INSUFFICIENT_BUFFER_VALUE); end;
  FillChar(Table^, Integer(Size), 0);
  PCardinal(Table)^ := 1;
  R := Pointer(NativeUInt(Table) + NativeUInt(4));
  R^.NextHop := 1; R^.IfIndex := 2; R^.Metric1 := 3;
  Size := 60;
  Result := 0;
end;
function TestNetRegistry(Key: THandle; ValueName: PWideChar;
  Reserved: Pointer; ValueType: PCardinal; Buffer: Pointer;
  BufferSize: PCardinal): LongInt; stdcall;
var S: string; V: Cardinal;
begin
  Inc(TestNetRegCalls);
  ValueType^ := REG_SZ_VALUE;
  if TestNetRegMode = 1 then Exit(ERROR_FILE_NOT_FOUND_VALUE);
  if TestNetRegMode = 2 then begin BufferSize^ := 3; Exit(0); end;
  if TestNetRegMode = 3 then begin BufferSize^ := REG_MAX_VALUE_BYTES + 2; Exit(ERROR_MORE_DATA_VALUE); end;
  if TestNetRegMode = 4 then
  begin
    V := 42;
    if Buffer <> nil then Move(V, Buffer^, 4);
    BufferSize^ := 4; // wrong kind for DWORD query
    Exit(0);
  end;
  if TestNetRegMode = 5 then
  begin
    ValueType^ := REG_DWORD_VALUE;
    BufferSize^ := 2;
    Exit(0);
  end;
  if Buffer = nil then begin BufferSize^ := 2; Exit(0); end;
  if BufferSize^ < 4 then begin BufferSize^ := 4; Exit(ERROR_MORE_DATA_VALUE); end;
  S := 'AB'; Move(PWideChar(S)^, Buffer^, 4);
  BufferSize^ := 4;
  Result := 0;
end;

function TestNetworkNativeHardening(out Failure: string; out Checks: Integer): Boolean;
var
  A, Saved: TNetworkAPI;
  Keys: TStringList;
  Data: TBytes;
  R: PIpForwardRow;
  C, V: Cardinal;
  S: string;
  procedure Check(Value: Boolean; const Name: string);
  begin
    Inc(Checks);
    if not Value then raise Exception.Create(Name);
  end;
  procedure PageMode(Mode: Integer);
  begin
    TestNetMode := Mode; TestNetPageCalls := 0;
    TestNetFreeCalls := 0; TestNetCloseCalls := 0;
  end;
  procedure RegMode(Mode: Integer);
  begin TestNetRegMode := Mode; TestNetRegCalls := 0; end;
  procedure RouteMode(Mode: Integer);
  begin TestNetRouteMode := Mode; TestNetRouteCalls := 0; end;
  procedure Bytes(const Text: string);
  begin
    SetLength(Data, Length(Text) * 2);
    if Length(Data) <> 0 then Move(PWideChar(Text)^, Data[0], Length(Data));
  end;
begin
  Checks := 0; Failure := ''; Result := False;
  Keys := TStringList.Create;
  Saved := APIs;
  try
    try
      A := Default(TNetworkAPI);
      A.WfpFree := TestNetFree;
      A.RegQuery := TestNetRegistry;
      PageMode(0);
      Check(ReadWFPKeys(A, 1, TestNetMake, TestNetPage, TestNetDestroy, Keys), 'WFP single page');
      Check((Keys.Count = 1) and (TestNetFreeCalls = 1) and (TestNetCloseCalls = 1), 'WFP resources released');
      PageMode(1);
      Check(not ReadWFPKeys(A, 1, TestNetMake, TestNetPage, TestNetDestroy, Keys), 'WFP error');
      Check((Keys.Count = 0) and (TestNetFreeCalls = 1), 'error allocation freed');
      PageMode(2);
      Check(not ReadWFPKeys(A, 1, TestNetMake, TestNetPage, TestNetDestroy, Keys), 'oversized WFP page');
      PageMode(3);
      Check(not ReadWFPKeys(A, 1, TestNetMake, TestNetPage, TestNetDestroy, Keys), 'missing WFP array');
      PageMode(4);
      Check(not ReadWFPKeys(A, 1, TestNetMake, TestNetPage, TestNetDestroy, Keys), 'second WFP page failure');
      Check((Keys.Count = 0) and (TestNetFreeCalls = 2), 'partial WFP result discarded');
      PageMode(5);
      Check(not ReadWFPKeys(A, 1, TestNetMake, TestNetPage, TestNetDestroy, Keys), 'WFP cap enforced');
      Check((Keys.Count = 0) and (TestNetPageCalls < 100), 'WFP cap is bounded');
      Check(not TakeWFPSnapshots(Keys, Keys, Keys), 'aliased outputs rejected');
      Check(not TakeWFPSnapshots(nil, Keys, Keys), 'nil output rejected');
      SetLength(Data, 64); FillChar(Data[0], Length(Data), 0);
      C := 1; Move(C, Data[0], 4);
      R := PIpForwardRow(@Data[4]);
      R^.NextHop := 1; R^.IfIndex := 2; R^.Metric1 := 3;
      Check(ParseDefaultRoutes(Data, 60, Keys) and (Keys.Count = 1), 'valid default route');
      Check(Keys[0] = '00000001:2:3', 'route format preserved');
      Check(not ParseDefaultRoutes(Data, 59, Keys) and (Keys.Count = 0), 'returned bytes limit');
      Check(not ParseDefaultRoutes(Data, 65, Keys), 'oversized route reply');
      R^.Dest := 1;
      Check(ParseDefaultRoutes(Data, 60, Keys) and (Keys.Count = 0), 'nondefault route omitted');
      C := 0; Move(C, Data[0], 4);
      Check(ParseDefaultRoutes(Data, 4, Keys), 'empty route table');
      C := High(Cardinal); Move(C, Data[0], 4);
      Check(not ParseDefaultRoutes(Data, 64, Keys), 'huge route count');
      APIs.IPv4Routes := TestNetRoutes;
      RouteMode(0);
      Check(TakeDefaultRouteSnapshot(Keys) and (Keys.Count = 1), 'route size-growth retry');
      Check(TestNetRouteCalls = 3, 'route retry count');
      RouteMode(1);
      Check(TakeDefaultRouteSnapshot(Keys) and (Keys.Count = 0), 'ERROR_NO_DATA is empty snapshot');
      RouteMode(2);
      Check(not TakeDefaultRouteSnapshot(Keys), 'route repeated growth bounded');
      Check(TestNetRouteCalls = NETWORK_MAX_RETRIES + 1, 'route max attempts');
      RouteMode(3);
      Check(not TakeDefaultRouteSnapshot(Keys) and (TestNetRouteCalls = 2), 'nongrowing route requirement');
      Bytes('AB'); Check(DecodeRegString(Data, 4, S) and (S = 'AB'), 'nonterminated registry text');
      Bytes('AB' + #0); Check(DecodeRegString(Data, 6, S) and (S = 'AB'), 'terminated registry text');
      Bytes('A' + #0 + 'B'); Check(not DecodeRegString(Data, 6, S) and (S = ''), 'embedded NUL registry text');
      Check(not DecodeRegString(Data, 5, S), 'odd registry bytes');
      Check(not DecodeRegString(Data, 8, S), 'registry length exceeds buffer');
      RegMode(0); Check(ReadRegString(A, 1, 'Test', S) and (S = 'AB'), 'registry size-growth retry');
      Check(TestNetRegCalls = 3, 'registry retry count');
      RegMode(1); Check(ReadRegString(A, 1, 'Test', S) and (S = ''), 'missing optional value');
      RegMode(2); Check(not ReadRegString(A, 1, 'Test', S), 'odd registry required size');
      RegMode(3); Check(not ReadRegString(A, 1, 'Test', S), 'registry cap');
      RegMode(4); V := 99;
      Check(not ReadRegDWORD(A, 1, 'Test', V) and (V = 0), 'DWORD wrong type clears output');
      RegMode(5);
      Check(not ReadRegDWORD(A, 1, 'Test', V) and (V = 0), 'DWORD wrong length');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    APIs := Saved;
    Keys.Free;
  end;
end;
