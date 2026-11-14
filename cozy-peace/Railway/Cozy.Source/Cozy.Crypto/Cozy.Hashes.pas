unit Cozy.Hashes;

{$I ..\Cozy.Configuration\Cozy.Metadata.inc}

{ Portable streaming SHA-512, XXH3-128 and all BLAKE3 modes.
  BLAKE3 always uses the canonical chunk tree, independent of update sizes.
  CRC/XXH are non-cryptographic signals, not authentication.
  SHA-512: FIPS 180-4. XXH3: xxHash v0.8.2. BLAKE3: official test vectors.
  Validation: Cozy.tests/Cozy.HashProbe.dpr and Relay Server/scripts/verify-native-hashes.py. }

{$IFDEF FPC}
  {$MODE DELPHI}
{$ENDIF}
{$B-}
{$Q-} { Modular additions/multiplications are required by both algorithms. }
{$R-}

interface

uses
{ Cozy central text imports. }
  Cozy.Strings.Crypto,

{$IFDEF FPC}
  SysUtils, Cozy.Hashes.XXH3, Cozy.Hashes.SHA512;
{$ELSE}
  System.SysUtils, Cozy.Hashes.XXH3, Cozy.Hashes.SHA512;
{$ENDIF}

type
  TXXHash3_128 = Cozy.Hashes.XXH3.TXXHash3_128;
  TSHA512Hasher = Cozy.Hashes.SHA512.TSHA512Hasher;
  THashCV = array[0..7] of UInt32;
  THashBlockWords = array[0..15] of UInt32;

  { A synchronous executor MUST join every started worker before returning or
    raising. Contexts and the input buffer are borrowed until it returns. }
  TBlake3Work = procedure(Context: Pointer);
  TBlake3Executor = procedure(Work: TBlake3Work;
    const Contexts: array of Pointer);

  { Check may run concurrently on bounded leaf workers. It must be thread-safe,
    non-blocking and must not raise. Context remains borrowed until ALL workers
    join. A signalled cancellation invalidates the current stream. }
  THashCancelCheck = function(Context: Pointer): Boolean;
  THashCancellation = record
    Check: THashCancelCheck;
    Context: Pointer;
  end;
  EHashCancelled = class(EInvalidOp);
  TBlake3CancellableExecutor = procedure(Work: TBlake3Work;
    const Contexts: array of Pointer; const Cancellation: THashCancellation);

  { Creation, Update, Finish, Reset and Free belong to the creating thread.
    Public operations reject a different owner or re-entry before any mutation.
    The owner must stay alive and must not Free during an operation/callback.
    No raw TObject reference can make arbitrary concurrent Free safe. Workers
    borrow only leaf records, never the hasher, and join before calls return. }
  TBlake3Hasher = class
  private
    FLength, FChunkCounter: UInt64;
    FChunkCV, FKeyCV: THashCV;
    FFlags: UInt32;
    FFailed: Boolean;
    FOwnerThread: Pointer;
    FInCall: Boolean;
    FBlock: array[0..63] of Byte;
    FBlockLength, FBlocksCompressed: Integer;
    { At most 54 pending subtrees for the supported 2^64-1 byte input. }
    FStack: array[0..53] of THashCV;
    FStackLength: Integer;
    procedure EnterCall;
    procedure LeaveCall;
    procedure ValidateUpdate(const Buffer; Count: NativeUInt; MaxWorkers: Integer);
    procedure UpdateCore(const Buffer; Count: NativeUInt;
      const Cancellation: THashCancellation);
    function UpdateParallelCore(const Buffer; Count: NativeUInt;
      Executor: TBlake3Executor; CancellableExecutor: TBlake3CancellableExecutor;
      const Cancellation: THashCancellation; MaxWorkers: Integer): NativeUInt;
    function FinishBytesCore(OutputLength: Integer; Seek: UInt64): TBytes;
    procedure Initialize(const Key: THashCV; Flags: UInt32);
    procedure ResetChunk(Counter: UInt64);
    procedure PushChunk(const ChunkCV: THashCV; TotalChunks: UInt64);
  public
    constructor Create;
    constructor CreateKeyed(const Key: TBytes);
    { Context is the exact UTF-8 byte sequence, never a platform codepage. }
    { Factory keeps the call syntax without a duplicate C++ constructor. }
    class function CreateDeriveKey(const ContextUTF8: TBytes): TBlake3Hasher;
    destructor Destroy; override;
    { Reset keeps this instance's original keyed/derive mode. }
    procedure Reset;
    procedure Update(const Buffer; Count: NativeUInt);
    { True chunk parallelism; canonical reduction order, keyed/derive/XOF safe.
      Returns chunks delegated to the executor; small updates remain serial. }
    function UpdateParallel(const Buffer; Count: NativeUInt;
      Executor: TBlake3Executor; MaxWorkers: Integer = 4): NativeUInt;
    function UpdateParallelCancellable(const Buffer; Count: NativeUInt;
      Executor: TBlake3CancellableExecutor; const Cancellation: THashCancellation;
      MaxWorkers: Integer = 4): NativeUInt;
    { Non-destructive XOF. OutputLength is in bytes; Seek is an output offset. }
    function FinishBytes(OutputLength: Integer = 32; Seek: UInt64 = 0): TBytes;
    function FinishHex(OutputLength: Integer = 32; Seek: UInt64 = 0): string;
  end;

  { Independent measurements of the same byte stream, not an authentication
    digest. Each field preserves its existing canonical lowercase hex format. }
  TIntegrityHashResult = record
    SHA512, XXH3_128, Blake3: string;
    Size: UInt64;
  end;

  { Bounded-memory, single-owner stream. Finish is a non-destructive snapshot;
    Update may continue afterwards. A failed component update invalidates the
    entire stream until Reset, preventing a partially advanced digest set.
    The creating thread exclusively owns the instance for its entire lifetime.
    Foreign-thread/reentrant calls are rejected; Free requires the owner to be
    idle after all synchronous calls return. Arbitrary concurrent Free is not
    supported. Independent instances may execute on independent threads. }
  TIntegrityHasher = class
  private
    FSHA512: TSHA512Hasher;
    FXXH3: TXXHash3_128;
    FBlake3: TBlake3Hasher;
    FSize: UInt64;
    FReady: Boolean;
    FOwnerThread: Pointer;
    FInCall: Boolean;
    procedure EnterCall;
    procedure LeaveCall;
    procedure RequireReady;
    procedure ResetCore;
    function UpdateCore(const Buffer; Count: NativeUInt;
      Executor: TBlake3Executor; CancellableExecutor: TBlake3CancellableExecutor;
      const Cancellation: THashCancellation; MaxWorkers: Integer): NativeUInt;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure Update(const Buffer; Count: NativeUInt);
    function UpdateParallel(const Buffer; Count: NativeUInt;
      Executor: TBlake3Executor; MaxWorkers: Integer = 4): NativeUInt;
    function UpdateParallelCancellable(const Buffer; Count: NativeUInt;
      Executor: TBlake3CancellableExecutor; const Cancellation: THashCancellation;
      MaxWorkers: Integer = 4): NativeUInt;
    function Finish: TIntegrityHashResult;
  end;

function IntegrityHashesBytes(const Data: TBytes): TIntegrityHashResult;

function XXHash3_128Bytes(const Data: TBytes): string;
function SHA512Bytes(const Data: TBytes): string;
function Blake3Bytes(const Data: TBytes): string;
function Blake3KeyedBytes(const Key, Data: TBytes; OutputLength: Integer = 32): TBytes;
function Blake3DeriveKeyBytes(const ContextUTF8, KeyMaterial: TBytes; OutputLength: Integer = 32): TBytes;

implementation

threadvar
  HashOwnerThreadMarker: Byte;

procedure CheckHashCancellation(const Cancellation: THashCancellation);
begin
  if Assigned(Cancellation.Check) and Cancellation.Check(Cancellation.Context) then
    raise EHashCancelled.Create(CozyText_Hashes_Hash_operation_cancelled_184f5b9d);
end;

const
  BlakeIV: THashCV = ($6A09E667, $BB67AE85, $3C6EF372, $A54FF53A,
    $510E527F, $9B05688C, $1F83D9AB, $5BE0CD19);
  ChunkStart: UInt32 = 1;
  ChunkEnd: UInt32 = 2;
  ParentFlag: UInt32 = 4;
  RootFlag: UInt32 = 8;
  KeyedHashFlag: UInt32 = 16;
  DeriveContextFlag: UInt32 = 32;
  DeriveMaterialFlag: UInt32 = 64;
  BlakeSchedule: array[0..6, 0..15] of Byte = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8),
    (3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1),
    (10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6),
    (12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4),
    (9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7),
    (11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13));
  HexDigits: string = CozyText_Hashes_0123456789abcdef_49c83f57;

type
  TBlakeOutput = record
    InputCV: THashCV;
    BlockWords: THashBlockWords;
    Counter: UInt64;
    BlockLength, Flags: UInt32;
  end;

function ReadLE32(Input: PByte): UInt32; inline;
var I: Integer;
begin
  Result := 0;
  for I := 0 to 3 do
  begin
    Result := Result or (UInt32(Input^) shl (I * 8));
    Inc(Input);
  end;
end;

function RotateRight32(Value: UInt32; Bits: Integer): UInt32; inline;
begin
  Result := (Value shr Bits) or (Value shl (32 - Bits));
end;

procedure BlakeMix(var A, B, C, D: UInt32; X, Y: UInt32); inline;
begin
  A := A + B + X;
  D := RotateRight32(D xor A, 16);
  C := C + D;
  B := RotateRight32(B xor C, 12);
  A := A + B + Y;
  D := RotateRight32(D xor A, 8);
  C := C + D;
  B := RotateRight32(B xor C, 7);
end;

procedure BlakeCompress(const CV: THashCV; const Words: THashBlockWords;
  Counter: UInt64; BlockLength, Flags: UInt32; out State: THashBlockWords);
var I, R: Integer;
begin
  for I := 0 to 7 do State[I] := CV[I];
  for I := 0 to 3 do State[I + 8] := BlakeIV[I];
  State[12] := UInt32(Counter);
  State[13] := UInt32(Counter shr 32);
  State[14] := BlockLength;
  State[15] := Flags;
  for R := 0 to 6 do
  begin
    BlakeMix(State[0], State[4], State[8], State[12],
      Words[BlakeSchedule[R, 0]], Words[BlakeSchedule[R, 1]]);
    BlakeMix(State[1], State[5], State[9], State[13],
      Words[BlakeSchedule[R, 2]], Words[BlakeSchedule[R, 3]]);
    BlakeMix(State[2], State[6], State[10], State[14],
      Words[BlakeSchedule[R, 4]], Words[BlakeSchedule[R, 5]]);
    BlakeMix(State[3], State[7], State[11], State[15],
      Words[BlakeSchedule[R, 6]], Words[BlakeSchedule[R, 7]]);
    BlakeMix(State[0], State[5], State[10], State[15],
      Words[BlakeSchedule[R, 8]], Words[BlakeSchedule[R, 9]]);
    BlakeMix(State[1], State[6], State[11], State[12],
      Words[BlakeSchedule[R, 10]], Words[BlakeSchedule[R, 11]]);
    BlakeMix(State[2], State[7], State[8], State[13],
      Words[BlakeSchedule[R, 12]], Words[BlakeSchedule[R, 13]]);
    BlakeMix(State[3], State[4], State[9], State[14],
      Words[BlakeSchedule[R, 14]], Words[BlakeSchedule[R, 15]]);
  end;
  for I := 0 to 7 do
  begin
    State[I] := State[I] xor State[I + 8];
    State[I + 8] := State[I + 8] xor CV[I];
  end;
end;

procedure BlakeWords(Input: PByte; out Words: THashBlockWords);
var I: Integer;
begin
  for I := 0 to 15 do
  begin
    Words[I] := ReadLE32(Input);
    Inc(Input, 4);
  end;
end;

procedure BlakeChainingValue(const Output: TBlakeOutput; out CV: THashCV);
var State: THashBlockWords; I: Integer;
begin
  BlakeCompress(Output.InputCV, Output.BlockWords, Output.Counter,
    Output.BlockLength, Output.Flags, State);
  for I := 0 to 7 do CV[I] := State[I];
  FillChar(State, SizeOf(State), 0);
end;

procedure BlakeParent(const Left, Right, Key: THashCV; Flags: UInt32; out Output: TBlakeOutput);
var I: Integer;
begin
  Output.InputCV := Key;
  for I := 0 to 7 do
  begin
    Output.BlockWords[I] := Left[I];
    Output.BlockWords[I + 8] := Right[I];
  end;
  Output.Counter := 0;
  Output.BlockLength := 64;
  Output.Flags := Flags or ParentFlag;
end;

procedure TBlake3Hasher.Initialize(const Key: THashCV; Flags: UInt32);
begin
  FKeyCV := Key; FFlags := Flags; FFailed := False;
  FLength := 0; FStackLength := 0;
  FillChar(FStack, SizeOf(FStack), 0);
  ResetChunk(0);
end;

constructor TBlake3Hasher.Create;
begin
  inherited Create;
  FOwnerThread := @HashOwnerThreadMarker;
  Initialize(BlakeIV, 0);
end;

constructor TBlake3Hasher.CreateKeyed(const Key: TBytes);
var I: Integer; KeyCV: THashCV;
begin
  inherited Create;
  FOwnerThread := @HashOwnerThreadMarker;
  if Length(Key) <> 32 then raise EArgumentException.Create(CozyText_Hashes_BLAKE3_key_must_be_32_bytes_bc7b4518);
  try
    for I := 0 to 7 do KeyCV[I] := ReadLE32(@Key[I * 4]);
    Initialize(KeyCV, KeyedHashFlag);
  finally FillChar(KeyCV, SizeOf(KeyCV), 0); end;
end;

class function TBlake3Hasher.CreateDeriveKey(const ContextUTF8: TBytes): TBlake3Hasher;
var ContextHasher: TBlake3Hasher; ContextKey: TBytes; KeyCV: THashCV; I: Integer;
begin
  ContextKey := nil;
  ContextHasher := TBlake3Hasher.Create;
  try
    ContextHasher.Initialize(BlakeIV, DeriveContextFlag);
    if Length(ContextUTF8) <> 0 then ContextHasher.Update(ContextUTF8[0], Length(ContextUTF8));
    ContextKey := ContextHasher.FinishBytes(32);
    for I := 0 to 7 do KeyCV[I] := ReadLE32(@ContextKey[I * 4]);
    Result := Self.Create;
    try
      Result.Initialize(KeyCV, DeriveMaterialFlag);
    except
      Result.Free;
      raise;
    end;
  finally
    if Length(ContextKey) <> 0 then FillChar(ContextKey[0], Length(ContextKey), 0);
    ContextKey := nil; FillChar(KeyCV, SizeOf(KeyCV), 0); ContextHasher.Free;
  end;
end;

destructor TBlake3Hasher.Destroy;
begin
  FillChar(FKeyCV, SizeOf(FKeyCV), 0); FillChar(FChunkCV, SizeOf(FChunkCV), 0);
  FillChar(FBlock, SizeOf(FBlock), 0); FillChar(FStack, SizeOf(FStack), 0);
  FLength := 0; FChunkCounter := 0; FFlags := 0; FBlockLength := 0;
  FBlocksCompressed := 0; FStackLength := 0;
  inherited;
end;

procedure TBlake3Hasher.EnterCall;
begin
  if FOwnerThread <> @HashOwnerThreadMarker then
    raise EInvalidOp.Create(CozyText_Hashes_BLAKE3_owner_thread_required_aaadae16);
  if FInCall then raise EInvalidOp.Create(CozyText_Hashes_BLAKE3_operation_already_active_e8fdb6d0);
  FInCall := True;
end;

procedure TBlake3Hasher.LeaveCall;
begin FInCall := False; end;

procedure TBlake3Hasher.ValidateUpdate(const Buffer; Count: NativeUInt; MaxWorkers: Integer);
begin
  if FFailed then raise EInvalidOp.Create(CozyText_Hashes_BLAKE3_stream_failed_8b61c9d6);
  if (MaxWorkers < 1) or (MaxWorkers > 4) then
    raise EArgumentException.Create(CozyText_Hashes_BLAKE3_workers_must_be_1_4_05cbc465);
  if Count = 0 then Exit;
  if @Buffer = nil then raise EArgumentException.Create(CozyText_Hashes_BLAKE3_hash_input_is_nil_98bc7188);
  if (Count - 1 > High(NativeUInt) - NativeUInt(@Buffer)) or
    (UInt64(Count) > High(UInt64) - FLength) then
    raise ERangeError.Create(CozyText_Hashes_BLAKE3_input_length_overflow_76e85319);
end;

procedure TBlake3Hasher.Reset;
begin
  EnterCall;
  try Initialize(FKeyCV, FFlags);
  finally LeaveCall; end;
end;

procedure TBlake3Hasher.Update(const Buffer; Count: NativeUInt);
var Cancellation: THashCancellation;
begin
  FillChar(Cancellation, SizeOf(Cancellation), 0);
  EnterCall;
  try
    ValidateUpdate(Buffer, Count, 1);
    try UpdateCore(Buffer, Count, Cancellation);
    except FFailed := True; raise; end;
  finally LeaveCall; end;
end;

procedure TBlake3Hasher.ResetChunk(Counter: UInt64);
begin
  FChunkCounter := Counter;
  FChunkCV := FKeyCV;
  FillChar(FBlock, SizeOf(FBlock), 0);
  FBlockLength := 0;
  FBlocksCompressed := 0;
end;

procedure TBlake3Hasher.PushChunk(const ChunkCV: THashCV; TotalChunks: UInt64);
var CV: THashCV; Output: TBlakeOutput;
begin
  CV := ChunkCV;
  { Each trailing zero in the completed chunk count merges a left subtree. }
  while (TotalChunks and 1) = 0 do
  begin
    if FStackLength = 0 then
      raise ERangeError.Create(CozyText_Hashes_Invalid_BLAKE3_tree_state_09870f1c);
    Dec(FStackLength);
    BlakeParent(FStack[FStackLength], CV, FKeyCV, FFlags, Output);
    FillChar(FStack[FStackLength], SizeOf(THashCV), 0);
    BlakeChainingValue(Output, CV);
    TotalChunks := TotalChunks shr 1;
  end;
  if FStackLength >= Length(FStack) then
    raise ERangeError.Create(CozyText_Hashes_BLAKE3_tree_capacity_exceeded_b10afae1);
  FStack[FStackLength] := CV;
  Inc(FStackLength);
  FillChar(CV, SizeOf(CV), 0); FillChar(Output, SizeOf(Output), 0);
end;

procedure TBlake3Hasher.UpdateCore(const Buffer; Count: NativeUInt;
  const Cancellation: THashCancellation);
var
  Input: PByte;
  Take: NativeUInt;
  Words, State: THashBlockWords;
  CV: THashCV;
  Output: TBlakeOutput;
  Flags: UInt32;
  I: Integer;
begin
  if FFailed then raise EInvalidOp.Create(CozyText_Hashes_BLAKE3_stream_failed_8b61c9d6);
  CheckHashCancellation(Cancellation);
  if Count = 0 then Exit;
  if (@Buffer = nil) or (Count - 1 > High(NativeUInt) - NativeUInt(@Buffer)) or
    (UInt64(Count) > High(UInt64) - FLength) then
    raise ERangeError.Create(CozyText_Hashes_BLAKE3_input_exceeds_2_64_1_bytes_78f05c30);
  Inc(FLength, UInt64(Count));
  Input := @Buffer;
  try
  while Count <> 0 do
  begin
    { One cancellation checkpoint per chunk, including the initial fragment. }
    if (FBlockLength = 0) or ((FBlocksCompressed = 15) and (FBlockLength = 64)) then
      CheckHashCancellation(Cancellation);
    { Keep the last block of the chunk until more input arrives: it may be
      the root, or need CHUNK_END even when its length is exactly 64. }
    if (FBlocksCompressed = 15) and (FBlockLength = 64) then
    begin
      Output.InputCV := FChunkCV;
      BlakeWords(@FBlock[0], Output.BlockWords);
      Output.Counter := FChunkCounter;
      Output.BlockLength := 64;
      Output.Flags := FFlags or ChunkEnd;
      BlakeChainingValue(Output, CV);
      PushChunk(CV, FChunkCounter + 1);
      ResetChunk(FChunkCounter + 1);
    end;
    if FBlockLength = 64 then
    begin
      BlakeWords(@FBlock[0], Words);
      Flags := FFlags;
      if FBlocksCompressed = 0 then Flags := Flags or ChunkStart;
      BlakeCompress(FChunkCV, Words, FChunkCounter, 64, Flags, State);
      for I := 0 to 7 do FChunkCV[I] := State[I];
      Inc(FBlocksCompressed);
      FillChar(FBlock, SizeOf(FBlock), 0);
      FBlockLength := 0;
    end;
    Take := 64 - FBlockLength;
    if Take > Count then Take := Count;
    Move(Input^, FBlock[FBlockLength], Take);
    Inc(FBlockLength, Integer(Take));
    Inc(Input, Take);
    Dec(Count, Take);
  end;
  finally
    FillChar(Words, SizeOf(Words), 0); FillChar(State, SizeOf(State), 0);
    FillChar(CV, SizeOf(CV), 0); FillChar(Output, SizeOf(Output), 0);
  end;
end;

type
  TBlakeCVBatch = array[0..1023] of THashCV;
  PBlakeCVBatch = ^TBlakeCVBatch;
  TBlakeLeafJob = record
    Input: PByte;
    Counter: UInt64;
    Key: THashCV;
    Flags: UInt32;
    First, Count: Integer;
    Values: PBlakeCVBatch;
    Cancellation: THashCancellation;
    Completed: Boolean;
  end;
  PBlakeLeafJob = ^TBlakeLeafJob;

procedure BlakeLeafWork(Context: Pointer);
var Job: PBlakeLeafJob; CV: THashCV; Words, State: THashBlockWords;
  I, B, W: Integer; Input: PByte; Flags: UInt32;
begin
  Job := PBlakeLeafJob(Context);
  Input := Job^.Input;
  try
    for I := 0 to Job^.Count - 1 do
    begin
      CheckHashCancellation(Job^.Cancellation);
      CV := Job^.Key;
      for B := 0 to 15 do
      begin
        BlakeWords(Input, Words);
        Flags := Job^.Flags;
        if B = 0 then Flags := Flags or ChunkStart;
        if B = 15 then Flags := Flags or ChunkEnd;
        BlakeCompress(CV, Words, Job^.Counter + UInt64(I), 64, Flags, State);
        for W := 0 to 7 do CV[W] := State[W];
        Inc(Input, 64);
      end;
      Job^.Values^[Job^.First + I] := CV;
    end;
    Job^.Completed := True;
  finally
    FillChar(CV, SizeOf(CV), 0); FillChar(Words, SizeOf(Words), 0);
    FillChar(State, SizeOf(State), 0);
  end;
end;

function TBlake3Hasher.UpdateParallel(const Buffer; Count: NativeUInt;
  Executor: TBlake3Executor; MaxWorkers: Integer): NativeUInt;
var Cancellation: THashCancellation;
begin
  FillChar(Cancellation, SizeOf(Cancellation), 0);
  EnterCall;
  try
    ValidateUpdate(Buffer, Count, MaxWorkers);
    try Result := UpdateParallelCore(Buffer, Count, Executor, nil, Cancellation, MaxWorkers);
    except FFailed := True; raise; end;
  finally LeaveCall; end;
end;

function TBlake3Hasher.UpdateParallelCancellable(const Buffer; Count: NativeUInt;
  Executor: TBlake3CancellableExecutor; const Cancellation: THashCancellation;
  MaxWorkers: Integer): NativeUInt;
begin
  EnterCall;
  try
    ValidateUpdate(Buffer, Count, MaxWorkers);
    try Result := UpdateParallelCore(Buffer, Count, nil, Executor, Cancellation, MaxWorkers);
    except FFailed := True; raise; end;
  finally LeaveCall; end;
end;

function TBlake3Hasher.UpdateParallelCore(const Buffer; Count: NativeUInt;
  Executor: TBlake3Executor; CancellableExecutor: TBlake3CancellableExecutor;
  const Cancellation: THashCancellation; MaxWorkers: Integer): NativeUInt;
var Input: PByte; Take, Chunks: NativeUInt; Used, Workers, I, First, N: Integer;
  Values: TBlakeCVBatch; Jobs: array[0..3] of TBlakeLeafJob;
  Contexts: array[0..3] of Pointer; Output: TBlakeOutput; CV: THashCV;
begin
  Result := 0;
  if FFailed then raise EInvalidOp.Create(CozyText_Hashes_BLAKE3_stream_failed_8b61c9d6);
  if (MaxWorkers < 1) or (MaxWorkers > 4) then
    raise EArgumentException.Create(CozyText_Hashes_BLAKE3_workers_must_be_1_4_05cbc465);
  CheckHashCancellation(Cancellation);
  if Count = 0 then Exit;
  if (@Buffer = nil) or (Count - 1 > High(NativeUInt) - NativeUInt(@Buffer)) or
    (UInt64(Count) > High(UInt64) - FLength) then
    raise ERangeError.Create(CozyText_Hashes_BLAKE3_input_length_overflow_76e85319);
  if ((not Assigned(Executor)) and (not Assigned(CancellableExecutor))) or
    (MaxWorkers = 1) or (Count < 256 * 1024) then
  begin UpdateCore(Buffer, Count, Cancellation); Exit; end;
  FillChar(Values, SizeOf(Values), 0); FillChar(Jobs, SizeOf(Jobs), 0);
  Input := @Buffer;
  try
    try
      { Complete an existing partial chunk without changing the streaming
        rule which reserves the final chunk for ROOT/XOF output. }
      Used := FBlocksCompressed * 64 + FBlockLength;
      if Used <> 0 then
      begin
        Take := 1024 - NativeUInt(Used);
        if Take > Count then Take := Count;
        if Take <> 0 then begin UpdateCore(Input^, Take, Cancellation); Inc(Input, Take); Dec(Count, Take); end;
        if Count = 0 then Exit;
        Output.InputCV := FChunkCV;
        BlakeWords(@FBlock[0], Output.BlockWords);
        Output.Counter := FChunkCounter; Output.BlockLength := 64;
        Output.Flags := FFlags or ChunkEnd;
        BlakeChainingValue(Output, CV);
        PushChunk(CV, FChunkCounter + 1); ResetChunk(FChunkCounter + 1);
      end;
      while Count > 1024 do
      begin
        CheckHashCancellation(Cancellation);
        Chunks := (Count - 1) div 1024;
        if Chunks > Length(Values) then Chunks := Length(Values);
        Workers := MaxWorkers;
        if NativeUInt(Workers) > Chunks then Workers := Integer(Chunks);
        FillChar(Jobs, SizeOf(Jobs), 0);
        First := 0;
        for I := 0 to Workers - 1 do
        begin
          N := (Integer(Chunks) - First) div (Workers - I);
          Jobs[I].Input := PByte(NativeUInt(Input) + NativeUInt(First) * 1024);
          Jobs[I].Counter := FChunkCounter + UInt64(First);
          Jobs[I].Key := FKeyCV; Jobs[I].Flags := FFlags;
          Jobs[I].Cancellation := Cancellation;
          Jobs[I].First := First; Jobs[I].Count := N; Jobs[I].Values := @Values;
          Contexts[I] := @Jobs[I]; Inc(First, N);
        end;
        if Assigned(CancellableExecutor) then
          CancellableExecutor(BlakeLeafWork, Slice(Contexts, Workers), Cancellation)
        else Executor(BlakeLeafWork, Slice(Contexts, Workers));
        CheckHashCancellation(Cancellation);
        for I := 0 to Workers - 1 do
          if not Jobs[I].Completed then raise EInvalidOp.Create(CozyText_Hashes_BLAKE3_worker_incomplete_179efd16);
        for I := 0 to Integer(Chunks) - 1 do
        begin
          PushChunk(Values[I], FChunkCounter + 1);
          Inc(FChunkCounter);
        end;
        Take := Chunks * 1024;
        Inc(FLength, UInt64(Take)); Inc(Result, Chunks);
        Inc(Input, Take); Dec(Count, Take);
        ResetChunk(FChunkCounter);
        FillChar(Values, SizeOf(Values), 0); FillChar(Jobs, SizeOf(Jobs), 0);
      end;
      if Count <> 0 then UpdateCore(Input^, Count, Cancellation);
      CheckHashCancellation(Cancellation);
    except
      FFailed := True;
      raise;
    end;
  finally
    FillChar(Values, SizeOf(Values), 0); FillChar(Jobs, SizeOf(Jobs), 0);
    FillChar(CV, SizeOf(CV), 0); FillChar(Output, SizeOf(Output), 0);
  end;
end;

function TBlake3Hasher.FinishBytes(OutputLength: Integer; Seek: UInt64): TBytes;
begin
  EnterCall;
  try Result := FinishBytesCore(OutputLength, Seek);
  finally LeaveCall; end;
end;

function TBlake3Hasher.FinishBytesCore(OutputLength: Integer; Seek: UInt64): TBytes;
var Output, NextOutput: TBlakeOutput; CV: THashCV; State: THashBlockWords;
  I, Offset, Take, Written, J: Integer; Counter: UInt64;
begin
  Result := nil;
  if FFailed then raise EInvalidOp.Create(CozyText_Hashes_BLAKE3_stream_failed_8b61c9d6);
  if OutputLength < 0 then raise EArgumentException.Create(CozyText_Hashes_Negative_BLAKE3_output_length_ec1c9635);
  if UInt64(OutputLength) > High(UInt64) - Seek then raise ERangeError.Create(CozyText_Hashes_BLAKE3_XOF_offset_overflow_d151735a);
  SetLength(Result, OutputLength);
  if OutputLength = 0 then Exit;
  try
    Output.InputCV := FChunkCV;
    BlakeWords(@FBlock[0], Output.BlockWords);
    Output.Counter := FChunkCounter;
    Output.BlockLength := UInt32(FBlockLength);
    Output.Flags := FFlags or ChunkEnd;
    if FBlocksCompressed = 0 then Output.Flags := Output.Flags or ChunkStart;
    for I := FStackLength - 1 downto 0 do
    begin
      BlakeChainingValue(Output, CV);
      BlakeParent(FStack[I], CV, FKeyCV, FFlags, NextOutput);
      Output := NextOutput;
    end;
    Counter := Seek div 64; Offset := Integer(Seek mod 64); Written := 0;
    while Written < OutputLength do
    begin
      BlakeCompress(Output.InputCV, Output.BlockWords, Counter,
        Output.BlockLength, Output.Flags or RootFlag, State);
      Take := 64 - Offset;
      if Take > OutputLength - Written then Take := OutputLength - Written;
      for J := 0 to Take - 1 do
        Result[Written + J] := Byte(State[(Offset + J) div 4] shr (((Offset + J) mod 4) * 8));
      Inc(Written, Take); Inc(Counter); Offset := 0;
    end;
  finally
    FillChar(Output, SizeOf(Output), 0); FillChar(NextOutput, SizeOf(NextOutput), 0);
    FillChar(CV, SizeOf(CV), 0); FillChar(State, SizeOf(State), 0);
  end;
end;

function TBlake3Hasher.FinishHex(OutputLength: Integer; Seek: UInt64): string;
var Bytes: TBytes; I: Integer;
begin
  EnterCall;
  try
  if OutputLength > High(Integer) div 2 then raise ERangeError.Create(CozyText_Hashes_BLAKE3_hex_output_too_large_7ad5cccc);
  Bytes := FinishBytesCore(OutputLength, Seek);
  try
    SetLength(Result, OutputLength * 2);
    for I := 0 to OutputLength - 1 do
    begin
      Result[I * 2 + 1] := HexDigits[(Bytes[I] shr 4) + 1];
      Result[I * 2 + 2] := HexDigits[(Bytes[I] and 15) + 1];
    end;
  finally if Length(Bytes) <> 0 then FillChar(Bytes[0], Length(Bytes), 0); Bytes := nil; end;
  finally LeaveCall; end;
end;

constructor TIntegrityHasher.Create;
begin
  inherited Create;
  FOwnerThread := @HashOwnerThreadMarker;
  Reset;
end;

destructor TIntegrityHasher.Destroy;
begin
  FReady := False;
  FBlake3.Free;
  FXXH3.Free;
  FSHA512.Free;
  FSize := 0;
  inherited;
end;

procedure TIntegrityHasher.EnterCall;
begin
  if FOwnerThread <> @HashOwnerThreadMarker then
    raise EInvalidOp.Create(CozyText_Hashes_Integrity_hash_owner_thread_required_3d5e626a);
  if FInCall then raise EInvalidOp.Create(CozyText_Hashes_Integrity_hash_operation_already_active_3a869710);
  FInCall := True;
end;

procedure TIntegrityHasher.LeaveCall;
begin FInCall := False; end;

procedure TIntegrityHasher.RequireReady;
begin
  if not FReady then
    raise EInvalidOp.Create(CozyText_Hashes_Integrity_hash_stream_requires_reset_0ca1f3cf);
end;

procedure TIntegrityHasher.Reset;
begin
  EnterCall;
  try ResetCore;
  finally LeaveCall; end;
end;

procedure TIntegrityHasher.ResetCore;
var
  NewSHA512: TSHA512Hasher;
  NewXXH3: TXXHash3_128;
  NewBlake3: TBlake3Hasher;
begin
  NewSHA512 := nil;
  NewXXH3 := nil;
  NewBlake3 := nil;
  try
    NewSHA512 := TSHA512Hasher.Create;
    NewXXH3 := TXXHash3_128.Create;
    NewBlake3 := TBlake3Hasher.Create;
  except
    NewBlake3.Free;
    NewXXH3.Free;
    NewSHA512.Free;
    raise;
  end;
  { Publish a completely initialized replacement; failed allocation leaves the
    previous state (including any invalid state) intact. }
  FReady := False;
  FBlake3.Free;
  FXXH3.Free;
  FSHA512.Free;
  FSHA512 := NewSHA512;
  FXXH3 := NewXXH3;
  FBlake3 := NewBlake3;
  FSize := 0;
  FReady := True;
end;

procedure TIntegrityHasher.Update(const Buffer; Count: NativeUInt);
var Cancellation: THashCancellation;
begin
  FillChar(Cancellation, SizeOf(Cancellation), 0);
  EnterCall;
  try UpdateCore(Buffer, Count, nil, nil, Cancellation, 1);
  finally LeaveCall; end;
end;

function TIntegrityHasher.UpdateParallel(const Buffer; Count: NativeUInt;
  Executor: TBlake3Executor; MaxWorkers: Integer): NativeUInt;
var Cancellation: THashCancellation;
begin
  FillChar(Cancellation, SizeOf(Cancellation), 0);
  EnterCall;
  try Result := UpdateCore(Buffer, Count, Executor, nil, Cancellation, MaxWorkers);
  finally LeaveCall; end;
end;

function TIntegrityHasher.UpdateParallelCancellable(const Buffer; Count: NativeUInt;
  Executor: TBlake3CancellableExecutor; const Cancellation: THashCancellation;
  MaxWorkers: Integer): NativeUInt;
begin
  EnterCall;
  try Result := UpdateCore(Buffer, Count, nil, Executor, Cancellation, MaxWorkers);
  finally LeaveCall; end;
end;

function TIntegrityHasher.UpdateCore(const Buffer; Count: NativeUInt;
  Executor: TBlake3Executor; CancellableExecutor: TBlake3CancellableExecutor;
  const Cancellation: THashCancellation; MaxWorkers: Integer): NativeUInt;
var Input: PByte; Remaining, Take: NativeUInt;
begin
  RequireReady;
  if (MaxWorkers < 1) or (MaxWorkers > 4) then
    raise EArgumentException.Create(CozyText_Hashes_BLAKE3_workers_must_be_1_4_05cbc465);
  if Count <> 0 then
  begin
    if @Buffer = nil then raise EArgumentException.Create(CozyText_Hashes_Integrity_hash_input_is_nil_b7f4a41f);
    if (UInt64(Count) > High(UInt64) - FSize) or
      (Count - 1 > High(NativeUInt) - NativeUInt(@Buffer)) then
      raise ERangeError.Create(CozyText_Hashes_Integrity_hash_input_length_overflow_c80d860e);
  end;
  { From the first cancellation checkpoint onward, failure requires Reset.
    SHA and XX updates are limited to 64 KiB before checking again. BLAKE3
    leaves check at each 1 KiB chunk; the bounded executor always joins. }
  FReady := False;
  CheckHashCancellation(Cancellation);
  Input := @Buffer;
  Remaining := Count;
  while Remaining <> 0 do
  begin
    CheckHashCancellation(Cancellation);
    Take := Remaining;
    if Take > 65536 then Take := 65536;
    FSHA512.Update(Input^, Take);
    CheckHashCancellation(Cancellation);
    FXXH3.Update(Input^, Take);
    Inc(Input, Take); Dec(Remaining, Take);
  end;
  if Assigned(CancellableExecutor) or Assigned(Cancellation.Check) then
    Result := FBlake3.UpdateParallelCancellable(Buffer, Count, CancellableExecutor,
      Cancellation, MaxWorkers)
  else Result := FBlake3.UpdateParallel(Buffer, Count, Executor, MaxWorkers);
  CheckHashCancellation(Cancellation);
  Inc(FSize, UInt64(Count));
  FReady := True;
end;

function TIntegrityHasher.Finish: TIntegrityHashResult;
begin
  EnterCall;
  try
    RequireReady;
    try
      Result.SHA512 := FSHA512.FinishHex;
      Result.XXH3_128 := FXXH3.FinishHex;
      Result.Blake3 := FBlake3.FinishHex;
      Result.Size := FSize;
    except FReady := False; raise; end;
  finally LeaveCall; end;
end;

function IntegrityHashesBytes(const Data: TBytes): TIntegrityHashResult;
var Hasher: TIntegrityHasher;
begin
  Hasher := TIntegrityHasher.Create;
  try
    if Length(Data) <> 0 then Hasher.Update(Data[0], NativeUInt(Length(Data)));
    Result := Hasher.Finish;
  finally
    Hasher.Free;
  end;
end;

function XXHash3_128Bytes(const Data: TBytes): string;
begin Result := Cozy.Hashes.XXH3.XXHash3_128Bytes(Data); end;

function SHA512Bytes(const Data: TBytes): string;
begin Result := Cozy.Hashes.SHA512.SHA512Bytes(Data); end;

function Blake3KeyedBytes(const Key, Data: TBytes; OutputLength: Integer): TBytes;
var H: TBlake3Hasher;
begin
  H := TBlake3Hasher.CreateKeyed(Key);
  try
    if Length(Data) <> 0 then H.Update(Data[0], Length(Data));
    Result := H.FinishBytes(OutputLength);
  finally H.Free; end;
end;

function Blake3DeriveKeyBytes(const ContextUTF8, KeyMaterial: TBytes; OutputLength: Integer): TBytes;
var H: TBlake3Hasher;
begin
  H := TBlake3Hasher.CreateDeriveKey(ContextUTF8);
  try
    if Length(KeyMaterial) <> 0 then H.Update(KeyMaterial[0], Length(KeyMaterial));
    Result := H.FinishBytes(OutputLength);
  finally H.Free; end;
end;

function Blake3Bytes(const Data: TBytes): string;
var Hasher: TBlake3Hasher;
begin
  Hasher := TBlake3Hasher.Create;
  try
    if Length(Data) <> 0 then Hasher.Update(Data[0], NativeUInt(Length(Data)));
    Result := Hasher.FinishHex;
  finally
    Hasher.Free;
  end;
end;

end.
