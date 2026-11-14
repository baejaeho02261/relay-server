
var
  Final12ReadMode: Integer;

function Final12HeapCopy(Address, Buffer: Pointer; Bytes: NativeUInt;
  out ReadBytes: NativeUInt): Boolean;
begin
  ReadBytes := 0;
  case Final12ReadMode of
    1: begin
         Move(Address^, Buffer^, Bytes div 2);
         ReadBytes := Bytes div 2;
         Exit(True); // apparent success, but incomplete length
       end;
    2: begin
         Move(Address^, Buffer^, Bytes);
         ReadBytes := Bytes;
         Exit(False); // full buffer does not override the failed status
       end;
    3: raise Exception.Create('synthetic copy failure');
  end;
  Move(Address^, Buffer^, Bytes);
  ReadBytes := Bytes;
  Result := True;
end;

function TestHeapTLSRulesFinal12(out Failure: string; out Checks: Integer): Boolean;
var
  Data: array[0..HEAP_TLS_CANARY_BYTES - 1] of Byte;
  Ticket: THeapTLSCallbackTicket;
  Good: Boolean;
  A, B: TArray<NativeUInt>;
  OldHook: THeapTLSCopyHook;
  procedure Check(Value: Boolean; const Why: string);
  begin Inc(Checks); if not Value then raise Exception.Create(Why); end;
begin
  Result := False; Failure := ''; Checks := 0;
  OldHook := HeapTLSCopyHook;
  try
    try
      HeapTLSCopyHook := Final12HeapCopy; Final12ReadMode := 0;
      FillHeapTLSCanary(@Data[0]);
      Check(TryHeapTLSCanaryIntact(@Data[0], Good) and Good, 'whole canary intact');
      Data[255] := Data[255] xor 1;
      Check(TryHeapTLSCanaryIntact(@Data[0], Good) and not Good, 'last byte mismatch');
      FillHeapTLSCanary(@Data[0]); Data[0] := Data[0] xor 1;
      Check(TryHeapTLSCanaryIntact(@Data[0], Good) and not Good, 'first byte mismatch');
      Final12ReadMode := 1; Good := True;
      Check(not TryHeapTLSCanaryIntact(@Data[0], Good), 'short successful read unknown');
      Check(not Good, 'unknown does not publish intact or corrupt decision');
      Final12ReadMode := 2;
      Check(not TryHeapTLSCanaryIntact(@Data[0], Good), 'failed status with bytes unknown');
      Check(not Good, 'failed status output cleared');
      Final12ReadMode := 3;
      Check(not TryHeapTLSCanaryIntact(@Data[0], Good), 'copy exception unknown');
      Check(not Good, 'exception output cleared');
      Final12ReadMode := 0;
      Check(not TryHeapTLSCanaryIntact(nil, Good), 'nil rejected');
      Check(not TryHeapTLSCanaryIntact(Pointer(High(NativeUInt)-10), Good), 'wrapped span rejected');
      Ticket := Default(THeapTLSCallbackTicket);
      Ticket.CallbackAddress := $12345000; Ticket.SlotIndex := 7;
      Ticket.Magic := HEAP_TLS_CALLBACK_MAGIC;
      Check(TryCallbackTicketIntact(@Ticket, $12345000, 7, Good) and Good, 'whole ticket intact');
      Ticket.Magic := 0;
      Check(TryCallbackTicketIntact(@Ticket, $12345000, 7, Good) and not Good, 'ticket mismatch');
      Ticket.Magic := HEAP_TLS_CALLBACK_MAGIC; Final12ReadMode := 1;
      Check(not TryCallbackTicketIntact(@Ticket, $12345000, 7, Good), 'short ticket unknown');
      Check(not Good, 'short ticket output false');
      Final12ReadMode := 2;
      Check(not TryCallbackTicketIntact(@Ticket, $12345000, 7, Good), 'failed ticket status');
      Final12ReadMode := 3;
      Check(not TryCallbackTicketIntact(@Ticket, $12345000, 7, Good), 'ticket exception');
      Final12ReadMode := 0;
      Check(not TryCallbackTicketIntact(nil, $12345000, 7, Good), 'nil ticket');
      A := nil; B := nil;
      Check(HeapTLSHeapsEqual(A, B), 'empty heap vectors');
      SetLength(A, 1); A[0] := $10000;
      Check(not HeapTLSHeapsEqual(A, B), 'heap vector length mismatch');
      B := Copy(A);
      Check(HeapTLSHeapsEqual(A, B), 'equal heap vectors');
      B[0] := $20000;
      Check(not HeapTLSHeapsEqual(A, B), 'heap vector value mismatch');
      Check(not HeapTLSRecent(100, 101, 10), 'future stamp rejected');
      Check(HeapTLSRecent(110, 100, 10), 'window inclusive');
      Result := True;
    except on E: Exception do Failure := E.Message; end;
  finally
    HeapTLSCopyHook := OldHook;
  end;
end;
