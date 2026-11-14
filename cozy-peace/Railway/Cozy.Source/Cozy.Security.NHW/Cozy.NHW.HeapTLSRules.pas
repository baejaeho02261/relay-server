unit Cozy.NHW.HeapTLSRules;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  System.SysUtils;

const
  HEAP_TLS_CANARY_BYTES = 256;
  HEAP_TLS_CALLBACK_MAGIC = UInt64($2D54A18FC3B61709);

type
  PHeapTLSCallbackTicket = ^THeapTLSCallbackTicket;
  THeapTLSCallbackTicket = record
    CallbackAddress: NativeUInt;
    SlotIndex: Cardinal;
    Reserved: Cardinal;
    Magic: UInt64;
  end;

procedure FillHeapTLSCanary(Block: Pointer);
// Returns False if the region cannot be read; in that case no detection.
function TryHeapTLSCanaryIntact(Block: Pointer; out Intact: Boolean): Boolean;
function TryCallbackTicketIntact(Ticket: PHeapTLSCallbackTicket;
  ExpectedCallback: NativeUInt; ExpectedSlot: Cardinal;
  out Intact: Boolean): Boolean;
function HeapTLSHeapsEqual(const A, B: TArray<NativeUInt>): Boolean;
function HeapTLSRecent(Tick, PreviousTick, WindowMS: UInt64): Boolean;

{$IFDEF NHW_FINAL12_TESTS}
function TestHeapTLSRulesFinal12(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses Cozy.NHW.WinPointers, Cozy.NHW.NativeSafety;

type
  THeapTLSReadMemory = function(Process: THandle; Address, Buffer: Pointer;
    Bytes: NativeUInt; var ReadBytes: NativeUInt): BOOL; stdcall;
{$IFDEF NHW_FINAL12_TESTS}
  THeapTLSCopyHook = function(Address, Buffer: Pointer; Bytes: NativeUInt;
    out ReadBytes: NativeUInt): Boolean;
var
  HeapTLSCopyHook: THeapTLSCopyHook = nil;
{$ENDIF}

function CopyHeapTLSBytes(Address, Buffer: Pointer; Bytes: NativeUInt): Boolean;
var
  ReadPtr: THeapTLSReadMemory;
  ReadBytes: NativeUInt;
  ReadOK: Boolean;
begin
  Result := False;
  if Buffer = nil then Exit;
  if not NHWAddressSpan(NativeUInt(Address), Bytes) then Exit;
  FillChar(Buffer^, Bytes, 0);
  ReadBytes := 0;
  ReadOK := False;
  try
{$IFDEF NHW_FINAL12_TESTS}
    if Assigned(HeapTLSCopyHook) then
      ReadOK := HeapTLSCopyHook(Address, Buffer, Bytes, ReadBytes)
    else
{$ENDIF}
    begin
      ReadPtr := THeapTLSReadMemory(WinExport(
        WinModule('kernel32.dll'), 'ReadProcessMemory'));
      if Assigned(ReadPtr) then
        ReadOK := ReadPtr(WinCurrentProcess, Address, Buffer, Bytes, ReadBytes);
    end;
    Result := ReadOK and (ReadBytes = Bytes);
  except
    // UNKNOWN: no partial bytes become a corruption result.
    Result := False;
  end;
  if not Result then FillChar(Buffer^, Bytes, 0);
end;

function ExpectedHeapTLSByte(Index: Integer): Byte;
begin
  Result := Byte((Index * 37 + $5A) and $FF);
end;

procedure FillHeapTLSCanary(Block: Pointer);
var
  I: Integer;
begin
  if Block = nil then Exit;
  for I := 0 to HEAP_TLS_CANARY_BYTES - 1 do
    PByte(NativeUInt(Block) + NativeUInt(I))^ := ExpectedHeapTLSByte(I);
end;

function TryHeapTLSCanaryIntact(Block: Pointer; out Intact: Boolean): Boolean;
var
  I: Integer;
  Sample: array[0..HEAP_TLS_CANARY_BYTES - 1] of Byte;
begin
  Intact := False;
  Result := False;
  FillChar(Sample, SizeOf(Sample), 0);
  if not CopyHeapTLSBytes(Block, @Sample[0], SizeOf(Sample)) then Exit;
  Intact := True;
  for I := Low(Sample) to High(Sample) do
    if Sample[I] <> ExpectedHeapTLSByte(I) then
    begin
      Intact := False;
      Break;
    end;
  Result := True;
end;

function TryCallbackTicketIntact(Ticket: PHeapTLSCallbackTicket;
  ExpectedCallback: NativeUInt; ExpectedSlot: Cardinal;
  out Intact: Boolean): Boolean;
var Sample: THeapTLSCallbackTicket;
begin
  Intact := False;
  Result := False;
  Sample := Default(THeapTLSCallbackTicket);
  if not CopyHeapTLSBytes(Ticket, @Sample, SizeOf(Sample)) then Exit;
  Intact := (Sample.CallbackAddress = ExpectedCallback) and
    (Sample.SlotIndex = ExpectedSlot) and
    (Sample.Magic = HEAP_TLS_CALLBACK_MAGIC);
  Result := True;
end;

function HeapTLSHeapsEqual(const A, B: TArray<NativeUInt>): Boolean;
var
  I: Integer;
begin
  Result := False;
  if Length(A) <> Length(B) then Exit;
  for I := 0 to High(A) do
    if A[I] <> B[I] then Exit;
  Result := True;
end;

function HeapTLSRecent(Tick, PreviousTick, WindowMS: UInt64): Boolean;
begin
  Result := (PreviousTick <> 0) and (Tick >= PreviousTick) and
    ((Tick - PreviousTick) <= WindowMS);
end;

{$IFDEF NHW_FINAL12_TESTS}
{$I Cozy.NHW.Final12.HeapTLSRules.inc}
{$ENDIF}

end.
