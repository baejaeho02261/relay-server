program CozyNHW_HeapTLSRules_Tests;

{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Build with Windows 64-bit (dcc64).'}
{$ENDIF}

uses
  System.SysUtils,
  Cozy.NHW.HeapTLSRules in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.HeapTLSRules.pas';

procedure Check(Condition: Boolean);
begin
  if not Condition then raise Exception.Create('HeapTLS rules test failed');
end;

var
  A, B: TArray<NativeUInt>;
  Canary: array[0..HEAP_TLS_CANARY_BYTES-1] of Byte;
  Intact: Boolean;
  Ticket: THeapTLSCallbackTicket;
begin
  SetLength(A, 2);
  SetLength(B, 2);
  A[0] := $12000; A[1] := $55000;
  B[0] := $12000; B[1] := $55000;
  Check(HeapTLSHeapsEqual(A, B));
  B[1] := $55001;
  Check(not HeapTLSHeapsEqual(A, B));
  FillHeapTLSCanary(@Canary[0]);
  Check(TryHeapTLSCanaryIntact(@Canary[0], Intact) and Intact);
  Canary[25] := Canary[25] xor $40;
  Check(TryHeapTLSCanaryIntact(@Canary[0], Intact) and not Intact);
  Ticket.CallbackAddress := $12345;
  Ticket.SlotIndex := 4;
  Ticket.Reserved := 0;
  Ticket.Magic := HEAP_TLS_CALLBACK_MAGIC;
  Check(TryCallbackTicketIntact(@Ticket, $12345, 4, Intact) and Intact);
  Ticket.CallbackAddress := $54321;
  Check(TryCallbackTicketIntact(@Ticket, $12345, 4, Intact) and not Intact);
  Check(HeapTLSRecent(10000, 3000, 8000));
  Check(not HeapTLSRecent(11001, 3000, 8000));
  Writeln('PASS');
end.
