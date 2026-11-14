unit Cozy.Protection.Engine;

{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$ALIGN 8}
{$B-}{$Q-}{$R-}{$J-}

interface
uses
{ Cozy central text imports. }
  Cozy.Strings.Protection,
 System.SysUtils;
type
  ECozyProtection = class(Exception);
  TCozyPolicyBinding = record
    Role: AnsiChar;
    FunctionCount: Cardinal;
    PolicyID, PolicySHA512: string;
  end;

{ Public artifact-to-server-policy commitment only. No key, bytecode, decryption
  or local authorization decision exists here. A valid slot never grants access:
  authenticated server bootstrap, integrity and operation checks remain required. }
function CozyPolicyBindingFromBytes(const Slot: TBytes;
  Role: AnsiChar): TCozyPolicyBinding;
function ReadCozyPolicyBinding(Role: AnsiChar): TCozyPolicyBinding;
procedure RequireCozyProtection(Role: AnsiChar);

implementation
uses Cozy.Security;
const
  SlotBytes = 4096;
  SlotHeaderBytes = 160;
  SlotTrailerAt = 4080;
type
  TProtectionSlot = array[0..SlotBytes - 1] of Byte;
var
  { Initialized mapped data slot; the binder changes public commitments only. }
  CozyProtectionSlot: TProtectionSlot = (
{$I Cozy.Protection.Slot.inc}
  );

procedure Fail(const Code: string);
begin
  raise ECozyProtection.Create(Code);
end;

function U16(const Bytes: TBytes; At: Integer): Word;
begin
  if (At < 0) or (At > Length(Bytes) - 2) then Fail(CozyText_Protection_Engine_COZY_SERVER_POLICY_SLOT_INVALID_9b31dc24);
  Result := Word(Bytes[At]) or (Word(Bytes[At + 1]) shl 8);
end;

function U32(const Bytes: TBytes; At: Integer): Cardinal;
begin
  if (At < 0) or (At > Length(Bytes) - 4) then Fail(CozyText_Protection_Engine_COZY_SERVER_POLICY_SLOT_INVALID_9b31dc24);
  Result := Cardinal(Bytes[At]) or (Cardinal(Bytes[At + 1]) shl 8) or
    (Cardinal(Bytes[At + 2]) shl 16) or (Cardinal(Bytes[At + 3]) shl 24);
end;

function Hex(const Bytes: TBytes; At, Count: Integer): string;
const Digits: string = CozyText_Protection_Engine_0123456789abcdef_98a7f764;
var I: Integer;
begin
  if (At < 0) or (Count < 0) or (At > Length(Bytes) - Count) then
    Fail(CozyText_Protection_Engine_COZY_SERVER_POLICY_SLOT_INVALID_9b31dc24);
  SetLength(Result, Count * 2);
  for I := 0 to Count - 1 do
  begin
    Result[I * 2 + 1] := Digits[(Bytes[At + I] shr 4) + 1];
    Result[I * 2 + 2] := Digits[(Bytes[At + I] and 15) + 1];
  end;
end;

function RoleCode(Role: AnsiChar): Byte;
begin
  case Role of
    'A': Result := 1;
    'B': Result := 2;
    'O': Result := 3;
  else
    Fail(CozyText_Protection_Engine_COZY_SERVER_POLICY_ROLE_INVALID_f91fe53c); Result := 0;
  end;
end;

function CozyPolicyBindingFromBytes(const Slot: TBytes;
  Role: AnsiChar): TCozyPolicyBinding;
var I: Integer; Nonzero: Byte; Bytes, Digest: TBytes; ExpectedID: string;
begin
  Result := Default(TCozyPolicyBinding);
  if Length(Slot) <> SlotBytes then Fail(CozyText_Protection_Engine_COZY_SERVER_POLICY_SLOT_INVALID_9b31dc24);
  if (U32(Slot, 0) <> $595A4F43) or (U32(Slot, 4) <> $4C4F502D) or
    (U32(Slot, 8) <> $2D594349) or (U32(Slot, 12) <> $00003256) or
    (U16(Slot, 16) <> 2) or (U16(Slot, 18) <> SlotHeaderBytes) or
    (U32(Slot, 20) <> SlotBytes) or (U16(Slot, 26) <> 0) or
    (U32(Slot, 28) <> 1) or (U32(Slot, 36) <> 1024) or
    (U32(Slot, 4080) <> $595A4F43) or (U32(Slot, 4084) <> $4C4F502D) or
    (U32(Slot, 4088) <> $2D444E45) or (U32(Slot, 4092) <> $00003256) then
    Fail(CozyText_Protection_Engine_COZY_SERVER_POLICY_SLOT_INVALID_9b31dc24);
  for I := 136 to SlotTrailerAt - 1 do
    if Slot[I] <> 0 then Fail(CozyText_Protection_Engine_COZY_SERVER_POLICY_SLOT_INVALID_9b31dc24);
  if Slot[25] = 0 then Fail(CozyText_Protection_Engine_COZY_PROTECTION_UNSEALED_b92b40bb);
  if (Slot[25] <> 1) or (Slot[24] <> RoleCode(Role)) or
    (U32(Slot, 32) < 1) or (U32(Slot, 32) > 16) then
    Fail(CozyText_Protection_Engine_COZY_SERVER_POLICY_SLOT_INVALID_9b31dc24);
  Nonzero := 0;
  for I := 72 to 135 do Nonzero := Nonzero or Slot[I];
  if Nonzero = 0 then Fail(CozyText_Protection_Engine_COZY_SERVER_POLICY_COMMITMENT_INVALID_b6bb88f8);
  Result.Role := Role;
  Result.FunctionCount := U32(Slot, 32);
  Result.PolicyID := Hex(Slot, 40, 32);
  Result.PolicySHA512 := Hex(Slot, 72, 64);
  Bytes := nil; Digest := nil;
  try
    Bytes := TEncoding.UTF8.GetBytes(CozyText_Protection_Engine_COZY_SERVER_POLICY_ID_V2_883eb881 + #10 +
      string(Role) + #10 + Result.PolicySHA512);
    Digest := DeviceSHA256(Bytes);
    ExpectedID := Hex(Digest, 0, Length(Digest));
    if (Length(Digest) <> 32) or (ExpectedID <> Result.PolicyID) then
      Fail(CozyText_Protection_Engine_COZY_SERVER_POLICY_COMMITMENT_INVALID_b6bb88f8);
  finally
    WipeBytes(Bytes); WipeBytes(Digest); WipeText(ExpectedID);
  end;
end;

function ReadCozyPolicyBinding(Role: AnsiChar): TCozyPolicyBinding;
var Slot: TBytes;
begin
  SetLength(Slot, SlotBytes);
  try
    Move(CozyProtectionSlot[0], Slot[0], SlotBytes);
    Result := CozyPolicyBindingFromBytes(Slot, Role);
  finally WipeBytes(Slot); end;
end;

procedure RequireCozyProtection(Role: AnsiChar);
var Binding: TCozyPolicyBinding;
begin
  Binding := ReadCozyPolicyBinding(Role);
  { Parsing a public commitment does not authorize startup or any operation. }
  WipeText(Binding.PolicyID); WipeText(Binding.PolicySHA512);
end;

end.
