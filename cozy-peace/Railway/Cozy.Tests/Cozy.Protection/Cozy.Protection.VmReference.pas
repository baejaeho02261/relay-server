unit Cozy.Protection.VmReference;

{$I ..\..\Cozy.Source\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}{$Q-}{$R-}{$J-}

interface
uses
{ Cozy central text imports. }
  Cozy.Strings.TestsProtection,
 System.SysUtils;
{ Test-only independent reference for the bounded server integer policy IR.
  This unit is never included by production A/B/O projects. }
function CozyVmEvaluateBytecode(const ProgramBytes: TBytes; FunctionID: Word;
  const Arguments: array of LongInt; MaximumSteps: Cardinal): LongInt;
implementation
uses Cozy.Protection.Engine;
const
  MaximumProgramBytes = 3952;
  MaximumFunctions = 16;
  MaximumArguments = 8;
  MaximumStack = 32;
  StepLimit = 1024;
type
  TVmFunction = record
    ID: Word;
    ArgumentCount: Byte;
    Offset, Count: Integer;
  end;
  TVmFunctions = array of TVmFunction;

procedure Fail(const Code: string);
begin
  raise ECozyProtection.Create(Code);
end;

procedure Wipe(var Bytes: TBytes);
begin
  if Length(Bytes) <> 0 then FillChar(Bytes[0], Length(Bytes), 0);
  Bytes := nil;
end;

procedure Need(At, Count, Limit: Integer);
begin
  if (At < 0) or (Count < 0) or (At > Limit) or (Count > Limit - At) then
    Fail(CozyText_Protection_VmReference_COZY_VM_BOUNDS_INVALID_03787c29);
end;

function U16(const Bytes: TBytes; At: Integer): Word;
begin
  Need(At, 2, Length(Bytes));
  Result := Word(Bytes[At]) or (Word(Bytes[At + 1]) shl 8);
end;

function U32(const Bytes: TBytes; At: Integer): Cardinal;
begin
  Need(At, 4, Length(Bytes));
  Result := Cardinal(Bytes[At]) or (Cardinal(Bytes[At + 1]) shl 8) or
    (Cardinal(Bytes[At + 2]) shl 16) or (Cardinal(Bytes[At + 3]) shl 24);
end;

function I16(const Bytes: TBytes; At: Integer): Integer;
var Bits: Word; Signed: SmallInt;
begin
  Bits := U16(Bytes, At); Move(Bits, Signed, SizeOf(Signed)); Result := Signed;
end;

function I32(const Bytes: TBytes; At: Integer): LongInt;
var Bits: Cardinal;
begin
  Bits := U32(Bytes, At); Move(Bits, Result, SizeOf(Result));
end;

function InstructionBytes(Op: Byte): Integer;
begin
  case Op of
    1: Result := 2;             { ARG + u8 index }
    2: Result := 5;             { CONST + i32 little endian }
    3..8, 11: Result := 1;      { EQ/AND/OR/NOT/ADD/XOR/RETURN }
    9, 10: Result := 3;         { JZ/JMP + i16 relative to next instruction }
  else
    Fail(CozyText_Protection_VmReference_COZY_VM_OPCODE_INVALID_077acaf3); Result := 0;
  end;
end;

function ValidateCode(const Bytes: TBytes; const Func: TVmFunction): TBytes;
var PC, Finish, Size, Target, I, Head, Tail, Height, Pops, Pushes, After: Integer;
  Op: Byte; Heights, Queue: array of Integer;
  procedure Enqueue(Position, StackHeight: Integer);
  var Index: Integer;
  begin
    if (Position < Func.Offset) or (Position >= Finish) or
      (Result[Position - Func.Offset] <> 1) then Fail(CozyText_Protection_VmReference_COZY_VM_BRANCH_INVALID_af336079);
    Index := Position - Func.Offset;
    if Heights[Index] >= 0 then
    begin
      if Heights[Index] <> StackHeight then Fail(CozyText_Protection_VmReference_COZY_VM_STACK_INVALID_f34ea14b);
      Exit;
    end;
    if Tail >= Length(Queue) then Fail(CozyText_Protection_VmReference_COZY_VM_BOUNDS_INVALID_03787c29);
    Heights[Index] := StackHeight; Queue[Tail] := Position; Inc(Tail);
  end;
begin
  Result := nil; Heights := nil; Queue := nil; Finish := Func.Offset + Func.Count;
  SetLength(Result, Func.Count);
  try
    try
      PC := Func.Offset;
      while PC < Finish do
      begin
        Result[PC - Func.Offset] := 1;
        Op := Bytes[PC]; Size := InstructionBytes(Op); Need(PC, Size, Finish);
        if (Op = 1) and (Bytes[PC + 1] >= Func.ArgumentCount) then
          Fail(CozyText_Protection_VmReference_COZY_VM_ARGUMENT_INVALID_3dd4847d);
        Inc(PC, Size);
      end;
      if (PC <> Finish) or (Bytes[Finish - 1] <> 11) then
        Fail(CozyText_Protection_VmReference_COZY_VM_PROGRAM_INVALID_5076b14f);
      PC := Func.Offset;
      while PC < Finish do
      begin
        Op := Bytes[PC]; Size := InstructionBytes(Op);
        if (Op = 9) or (Op = 10) then
        begin
          Target := PC + Size + I16(Bytes, PC + 1);
          if (Target < Func.Offset) or (Target >= Finish) or
            (Result[Target - Func.Offset] <> 1) then
            Fail(CozyText_Protection_VmReference_COZY_VM_BRANCH_INVALID_af336079);
        end;
        Inc(PC, Size);
      end;
      SetLength(Heights, Func.Count); SetLength(Queue, Func.Count);
      for I := 0 to High(Heights) do Heights[I] := -1;
      Head := 0; Tail := 0; Enqueue(Func.Offset, 0);
      while Head < Tail do
      begin
        PC := Queue[Head]; Inc(Head); Height := Heights[PC - Func.Offset];
        Op := Bytes[PC]; Size := InstructionBytes(Op); Pops := 0; Pushes := 0;
        case Op of
          1, 2: Pushes := 1;
          3, 4, 5, 7, 8: begin Pops := 2; Pushes := 1; end;
          6: begin Pops := 1; Pushes := 1; end;
          9, 11: Pops := 1;
        end;
        After := Height - Pops + Pushes;
        if (Height < Pops) or (After > MaximumStack) then
          Fail(CozyText_Protection_VmReference_COZY_VM_STACK_INVALID_f34ea14b);
        if Op = 11 then
        begin
          if Height <> 1 then Fail(CozyText_Protection_VmReference_COZY_VM_STACK_INVALID_f34ea14b);
          Continue;
        end;
        if Op <> 10 then Enqueue(PC + Size, After);
        if (Op = 9) or (Op = 10) then
          Enqueue(PC + Size + I16(Bytes, PC + 1), After);
      end;
      for I := 0 to Func.Count - 1 do
        if (Result[I] = 1) and (Heights[I] < 0) then
          Fail(CozyText_Protection_VmReference_COZY_VM_PROGRAM_INVALID_5076b14f);
    except
      Wipe(Result); raise;
    end;
  finally
    if Length(Heights) <> 0 then FillChar(Heights[0], Length(Heights) * SizeOf(Integer), 0);
    if Length(Queue) <> 0 then FillChar(Queue[0], Length(Queue) * SizeOf(Integer), 0);
  end;
end;

function ParseProgram(const Bytes: TBytes): TVmFunctions;
var Count, I, At, Cursor: Integer; PreviousID: Word; Boundaries: TBytes;
begin
  Result := nil; Boundaries := nil;
  if (Length(Bytes) < 17) or (Length(Bytes) > MaximumProgramBytes) or
    (U32(Bytes, 0) <> $314D5643) or (U16(Bytes, 6) <> 0) then
    Fail(CozyText_Protection_VmReference_COZY_VM_PROGRAM_INVALID_5076b14f);
  Count := U16(Bytes, 4);
  if (Count < 1) or (Count > MaximumFunctions) then
    Fail(CozyText_Protection_VmReference_COZY_VM_PROGRAM_INVALID_5076b14f);
  Cursor := 8 + Count * 8; Need(0, Cursor, Length(Bytes)); PreviousID := 0;
  SetLength(Result, Count);
  for I := 0 to Count - 1 do
  begin
    At := 8 + I * 8;
    Result[I].ID := U16(Bytes, At);
    Result[I].ArgumentCount := Bytes[At + 2];
    Result[I].Offset := U16(Bytes, At + 4);
    Result[I].Count := U16(Bytes, At + 6);
    if (Result[I].ID <= PreviousID) or (Bytes[At + 3] <> 0) or
      (Result[I].ArgumentCount > MaximumArguments) or
      (Result[I].Offset <> Cursor) or (Result[I].Count < 1) then
      Fail(CozyText_Protection_VmReference_COZY_VM_FUNCTION_INVALID_8a1d53c9);
    Need(Cursor, Result[I].Count, Length(Bytes));
    Inc(Cursor, Result[I].Count); PreviousID := Result[I].ID;
    try Boundaries := ValidateCode(Bytes, Result[I]);
    finally Wipe(Boundaries); end;
  end;
  if Cursor <> Length(Bytes) then Fail(CozyText_Protection_VmReference_COZY_VM_PROGRAM_INVALID_5076b14f);
  if (Result[0].ID <> 1) or (Result[0].ArgumentCount <> 3) then
    Fail(CozyText_Protection_VmReference_COZY_VM_PROGRAM_INVALID_5076b14f);
end;

function ExecuteFunction(const Bytes: TBytes; const Func: TVmFunction;
  const Arguments: array of LongInt; MaximumSteps: Cardinal): LongInt;
var Stack: array[0..MaximumStack - 1] of LongInt;
  Top, PC, Finish, Target: Integer; Steps: Cardinal;
  Op: Byte; Left, Right: LongInt; Boundaries: TBytes;
  procedure Push(Value: LongInt);
  begin
    if Top >= MaximumStack then Fail(CozyText_Protection_VmReference_COZY_VM_STACK_INVALID_f34ea14b);
    Stack[Top] := Value; Inc(Top);
  end;
  function Pop: LongInt;
  begin
    if Top <= 0 then Fail(CozyText_Protection_VmReference_COZY_VM_STACK_INVALID_f34ea14b);
    Dec(Top); Result := Stack[Top]; Stack[Top] := 0;
  end;
  procedure Jump(Destination: Integer);
  begin
    if (Destination < Func.Offset) or (Destination >= Finish) or
      (Boundaries[Destination - Func.Offset] <> 1) then
      Fail(CozyText_Protection_VmReference_COZY_VM_BRANCH_INVALID_af336079);
    PC := Destination;
  end;
begin
  Result := 0; Boundaries := nil; Top := 0; Steps := 0;
  FillChar(Stack, SizeOf(Stack), 0);
  if (Length(Arguments) <> Func.ArgumentCount) or
    (MaximumSteps < 1) or (MaximumSteps > StepLimit) then
    Fail(CozyText_Protection_VmReference_COZY_VM_ARGUMENT_INVALID_3dd4847d);
  PC := Func.Offset; Finish := Func.Offset + Func.Count;
  try
    Boundaries := ValidateCode(Bytes, Func);
    while True do
    begin
      if Steps >= MaximumSteps then Fail(CozyText_Protection_VmReference_COZY_VM_STEP_LIMIT_96aee27a);
      Inc(Steps); Need(PC, 1, Finish); Op := Bytes[PC]; Inc(PC);
      case Op of
        1: begin Need(PC, 1, Finish); if Bytes[PC] >= Length(Arguments) then Fail(CozyText_Protection_VmReference_COZY_VM_ARGUMENT_INVALID_3dd4847d); Push(Arguments[Bytes[PC]]); Inc(PC); end;
        2: begin Need(PC, 4, Finish); Push(I32(Bytes, PC)); Inc(PC, 4); end;
        3: begin Right := Pop; Left := Pop; Push(Ord(Left = Right)); end;
        4: begin Right := Pop; Left := Pop; Push(Ord((Left <> 0) and (Right <> 0))); end;
        5: begin Right := Pop; Left := Pop; Push(Ord((Left <> 0) or (Right <> 0))); end;
        6: begin Left := Pop; Push(Ord(Left = 0)); end;
        7: begin Right := Pop; Left := Pop; Push(LongInt(Cardinal(Left) + Cardinal(Right))); end;
        8: begin Right := Pop; Left := Pop; Push(LongInt(Cardinal(Left) xor Cardinal(Right))); end;
        9: begin Need(PC, 2, Finish); Target := PC + 2 + I16(Bytes, PC); Inc(PC, 2); Left := Pop; if Left = 0 then Jump(Target); end;
        10: begin Need(PC, 2, Finish); Target := PC + 2 + I16(Bytes, PC); Inc(PC, 2); Jump(Target); end;
        11: begin Result := Pop; if Top <> 0 then Fail(CozyText_Protection_VmReference_COZY_VM_STACK_INVALID_f34ea14b); Exit; end;
      else Fail(CozyText_Protection_VmReference_COZY_VM_OPCODE_INVALID_077acaf3);
      end;
    end;
  finally
    FillChar(Stack, SizeOf(Stack), 0); Wipe(Boundaries);
  end;
end;

function CozyVmEvaluateBytecode(const ProgramBytes: TBytes; FunctionID: Word;
  const Arguments: array of LongInt; MaximumSteps: Cardinal): LongInt;
var Functions: TVmFunctions; I: Integer;
begin
  Functions := ParseProgram(ProgramBytes);
  for I := 0 to High(Functions) do
    if Functions[I].ID = FunctionID then
      Exit(ExecuteFunction(ProgramBytes, Functions[I], Arguments, MaximumSteps));
  Fail(CozyText_Protection_VmReference_COZY_VM_FUNCTION_MISSING_a1100d00); Result := 0;
end;

end.
