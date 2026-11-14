var
  Heap5LHeaps: TArray<NativeUInt>;
  Heap5LMode: Integer;
  Heap5LThread: Cardinal;
  Heap5LTls, Heap5LFls: Pointer;
  Heap5LTicketValid, Heap5LTicketIntact: Boolean;
  Heap5LCanaryValid, Heap5LCanaryIntact, Heap5LSlotRaise: Boolean;
function ResolveHeapTLSFunctions: Boolean;
begin Result := False; end; // Tests create no real TLS/FLS/heap probes.
function LocalThreadID: Cardinal;
begin Result := Heap5LThread; end;
function LocalHeapSnapshot(out Heaps: TArray<NativeUInt>): Boolean;
begin
  Heaps := nil;
  if Heap5LMode = 2 then raise EOutOfMemory.Create('synthetic heap snapshot allocation');
  Result := Heap5LMode = 1;
  if Result then Heaps := Copy(Heap5LHeaps, 0, Length(Heap5LHeaps));
end;
function LocalTlsGetValue(Index: Cardinal): Pointer;
begin Result := Heap5LTls; end;
function LocalFlsGetValue(Index: Cardinal): Pointer;
begin
  if Heap5LSlotRaise then raise Exception.Create('synthetic local slot read failure');
  Result := Heap5LFls;
end;
function TryCallbackTicketIntact(Ticket: PHeapTLSCallbackTicket;
  ExpectedCallback: NativeUInt; ExpectedSlot: Cardinal; out Intact: Boolean): Boolean;
begin Result := Heap5LTicketValid; Intact := Heap5LTicketIntact; end;
function TryHeapTLSCanaryIntact(Block: Pointer; out Intact: Boolean): Boolean;
begin Result := Heap5LCanaryValid; Intact := Heap5LCanaryIntact; end;
