program Cozy_Protection_VmProbe;

{$APPTYPE CONSOLE}
{$R+}{$Q+}

uses
{ Cozy central text imports. }
  Cozy.Strings.Crypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Crypto.pas',
  Cozy.Strings.Handoff in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Handoff.pas',
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.Lifecycle in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Lifecycle.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.Protection in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Protection.pas',
  Cozy.Strings.Security in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Security.pas',
{$IF (Defined(GAME_NATIVE_ABI_TESTS))}
  Cozy.Strings.TestsPlatform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsPlatform.pas',
{$ENDIF}
  Cozy.Strings.TestsProtection in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsProtection.pas',
 System.SysUtils,
  Cozy.Protection.Engine in '..\..\Cozy.Source\Cozy.Protection\Cozy.Protection.Engine.pas',
  Cozy.Protection.VmReference in 'Cozy.Protection.VmReference.pas',
  Cozy.Handoff.Crypto;

{ Windows-only native interpreter/CNG probe. Golden AEAD bytes were checked
  independently with Node crypto and Python cryptography. This file has not
  been executed by the source-only build environment. }
const
  ProgramHex =
    CozyText_Protection_VmProbe_Digest_39845e50 +
    CozyText_Protection_VmProbe_Digest_7ff6aaa6 +
    CozyText_Protection_VmProbe_Digest_f8a6adcc;

procedure Check(Value: Boolean; const MessageText: string);
begin
  if not Value then raise EInvalidOpException.Create(MessageText);
end;

function Hex(const Text: string): TBytes;
var I, N: Integer;
begin
  Check((Length(Text) mod 2) = 0, CozyText_Protection_VmProbe_Invalid_probe_hex_1aaeee92);
  SetLength(Result, Length(Text) div 2);
  for I := 0 to High(Result) do
  begin
    N := StrToInt('$' + Copy(Text, I * 2 + 1, 2));
    Check((N >= 0) and (N <= 255), CozyText_Protection_VmProbe_Invalid_probe_byte_b272cacf);
    Result[I] := Byte(N);
  end;
end;

procedure Wipe(var Bytes: TBytes);
begin
  if Length(Bytes) <> 0 then FillChar(Bytes[0], Length(Bytes), 0);
  Bytes := nil;
end;

procedure Reject(const Bytes: TBytes; FunctionID: Word;
  const Arguments: array of LongInt; Steps: Cardinal = 1024);
var Rejected: Boolean;
begin
  Rejected := False;
  try CozyVmEvaluateBytecode(Bytes, FunctionID, Arguments, Steps);
  except on E: ECozyProtection do Rejected := True; end;
  Check(Rejected, CozyText_Protection_VmProbe_Malformed_or_unbounded_VM_input_was_accepted_950ffa81);
end;

procedure VmVectors;
var Bytes, Bad: TBytes; FunctionAt: Integer; Rejected: Boolean;
begin
  Bytes := Hex(ProgramHex); Bad := nil;
  try
    Check(CozyVmEvaluateBytecode(Bytes, 1, [1, 1, 1], 1024) = 1, CozyText_Protection_VmProbe_A_gate_failed_9db26f35);
    Check(CozyVmEvaluateBytecode(Bytes, 1, [1, 1, 0], 1024) = 0, CozyText_Protection_VmProbe_Authorization_flag_ignored_27ebfd99);
    Check(CozyVmEvaluateBytecode(Bytes, 1, [2, 1, 1], 1024) = 0, CozyText_Protection_VmProbe_Role_flag_ignored_3452c9e6);
    Check(CozyVmEvaluateBytecode(Bytes, 1, [1, 2, 1], 1024) = 0, CozyText_Protection_VmProbe_Version_flag_ignored_fbd512c1);
    Check(CozyVmEvaluateBytecode(Bytes, 2, [2147483647, 1], 1024) = -1822975009, CozyText_Protection_VmProbe_32_bit_add_wrap_differs_690b3e92);
    Check(CozyVmEvaluateBytecode(Bytes, 2, [-1, 1], 1024) = 324508639, CozyText_Protection_VmProbe_XOR_vector_differs_c7ae5f29);
    Check(CozyVmEvaluateBytecode(Bytes, 2, [Low(LongInt), -1], 1024) = 1822975008, CozyText_Protection_VmProbe_Negative_wrap_differs_293d09c5);
    Check(CozyVmEvaluateBytecode(Bytes, 3, [0], 1024) = -1, CozyText_Protection_VmProbe_True_branch_differs_2a1b13fa);
    Check(CozyVmEvaluateBytecode(Bytes, 3, [1], 1024) = 7, CozyText_Protection_VmProbe_False_branch_differs_86c44de0);
    Check(CozyVmEvaluateBytecode(Bytes, 3, [-7], 1024) = 7, CozyText_Protection_VmProbe_Negative_condition_differs_d0540f6e);
    Check(CozyVmEvaluateBytecode(Bytes, 4, [0, 0], 1024) = 1, CozyText_Protection_VmProbe_NOT_OR_false_vector_differs_c2fe0c3a);
    Check(CozyVmEvaluateBytecode(Bytes, 4, [5, 7], 1024) = 1, CozyText_Protection_VmProbe_AND_OR_true_vector_differs_1e703cae);
    Check(CozyVmEvaluateBytecode(Bytes, 4, [0, 7], 1024) = 0, CozyText_Protection_VmProbe_Boolean_normalization_differs_efcceb03);
    Reject(Bytes, 1, [1, 1], 1024); Reject(Bytes, 99, [], 1024);
    Reject(Bytes, 1, [1, 1, 1], 1); Reject(Bytes, 1, [1, 1, 1], 0);
    Reject(Bytes, 1, [1, 1, 1], 1025);
    Bad := Copy(Bytes, 0, Length(Bytes)); Bad[40] := $FF;
    Reject(Bad, 1, [1, 1, 1]); Wipe(Bad);
    Bad := Copy(Bytes, 0, Length(Bytes));
    FunctionAt := Integer(Bad[28]) or (Integer(Bad[29]) shl 8);
    Bad[FunctionAt + 9] := 1; Bad[FunctionAt + 10] := 0;
    Reject(Bad, 3, [0]); Wipe(Bad);
    Bad := Copy(Bytes, 0, Length(Bytes)); SetLength(Bad, Length(Bad) + 1);
    Reject(Bad, 1, [1, 1, 1]);
    Rejected := False;
    try RequireCozyProtection('A');
    except on E: ECozyProtection do Rejected := E.Message = CozyText_Protection_VmProbe_COZY_PROTECTION_UNSEALED_c8a9fa8a; end;
    Check(Rejected, CozyText_Protection_VmProbe_An_unsealed_probe_was_allowed_to_pass_protected__e1706eea);
  finally Wipe(Bytes); Wipe(Bad); end;
end;

procedure PolicyVectors;
const
  Unsealed: array[0..4095] of Byte = (
{$I ..\..\Cozy.Source\Cozy.Protection\Cozy.Protection.Slot.inc}
  );
  PolicyDigest = CozyText_Protection_VmProbe_Digest_bb1c396f +
    CozyText_Protection_VmProbe_Digest_f958c14c;
  PolicyID = CozyText_Protection_VmProbe_Digest_8ac66bd5;
var Slot, IDBytes, DigestBytes: TBytes; Binding: TCozyPolicyBinding;
  Rejected: Boolean;
  procedure RejectSlot(Role: AnsiChar);
  begin
    Rejected := False;
    try Binding := CozyPolicyBindingFromBytes(Slot, Role);
    except on E: ECozyProtection do Rejected := True; end;
    Check(Rejected, CozyText_Protection_VmProbe_Invalid_public_policy_binding_was_accepted_3569c8da);
  end;
begin
  SetLength(Slot, SizeOf(Unsealed)); IDBytes := nil; DigestBytes := nil;
  try
    Move(Unsealed[0], Slot[0], Length(Slot));
    RejectSlot('A');
    Slot[24] := 1; Slot[25] := 1; Slot[32] := 1;
    IDBytes := Hex(PolicyID); DigestBytes := Hex(PolicyDigest);
    Move(IDBytes[0], Slot[40], Length(IDBytes));
    Move(DigestBytes[0], Slot[72], Length(DigestBytes));
    Binding := CozyPolicyBindingFromBytes(Slot, 'A');
    Check((Binding.PolicyID = PolicyID) and (Binding.PolicySHA512 = PolicyDigest) and
      (Binding.FunctionCount = 1) and (Binding.Role = 'A'), CozyText_Protection_VmProbe_Public_policy_golden_vector_differs_f2cf44d7);
    RejectSlot('B');
    Slot[40] := Slot[40] xor 1; RejectSlot('A'); Slot[40] := Slot[40] xor 1;
    Slot[136] := 1; RejectSlot('A'); Slot[136] := 0;
    Slot[16] := 1; RejectSlot('A'); Slot[16] := 2;
    Slot[25] := 2; RejectSlot('A');
  finally Wipe(Slot); Wipe(IDBytes); Wipe(DigestBytes); end;
end;

procedure AeadVectors;
var Key, Nonce, AAD, Plain, Cipher, Tag, Output: TBytes; Rejected: Boolean;
begin
  Key := nil; Nonce := nil; AAD := nil; Plain := nil;
  Cipher := nil; Tag := nil; Output := nil;
  try
    Key := Hex(CozyText_Protection_VmProbe_Digest_c860748e);
    Nonce := Hex(CozyText_Protection_VmProbe_000102030405060708090a0b_310ef8fb);
    AAD := Hex(CozyText_Protection_VmProbe_Digest_eb22bd5d);
    Plain := Hex(CozyText_Protection_VmProbe_Digest_c0ca4812);
    Cipher := Hex(CozyText_Protection_VmProbe_Digest_8150340c);
    Tag := Hex(CozyText_Protection_VmProbe_Digest_888894de);
    Output := HandoffDecryptAes256Gcm(Key, Nonce, Tag, AAD, Cipher, 8192);
    Check((Length(Output) = Length(Plain)) and
      CompareMem(@Output[0], @Plain[0], Length(Plain)), CozyText_Protection_VmProbe_CNG_golden_plaintext_differs_8e94084a);
    Wipe(Output); Tag[0] := Tag[0] xor 1; Rejected := False;
    try Output := HandoffDecryptAes256Gcm(Key, Nonce, Tag, AAD, Cipher, 8192);
    except on E: Exception do Rejected := True; end;
    Check(Rejected and (Length(Output) = 0), CozyText_Protection_VmProbe_Unauthenticated_CNG_bytes_escaped_88615f03);
    Tag[0] := Tag[0] xor 1; AAD[0] := AAD[0] xor 1; Rejected := False;
    try Output := HandoffDecryptAes256Gcm(Key, Nonce, Tag, AAD, Cipher, 8192);
    except on E: Exception do Rejected := True; end;
    Check(Rejected and (Length(Output) = 0), CozyText_Protection_VmProbe_Changed_AAD_was_accepted_134e284b);
    Rejected := False;
    try Output := HandoffDecryptAes256Gcm(Key, Nonce, Tag, AAD, Cipher, 1);
    except on E: Exception do Rejected := True; end;
    Check(Rejected and (Length(Output) = 0), CozyText_Protection_VmProbe_Ciphertext_bound_was_ignored_65f616af);
  finally
    Wipe(Key); Wipe(Nonce); Wipe(AAD); Wipe(Plain);
    Wipe(Cipher); Wipe(Tag); Wipe(Output);
  end;
end;

begin
  try
    VmVectors; PolicyVectors; AeadVectors;
    WriteLn(CozyText_Protection_VmProbe_PASS_test_only_policy_IR_public_V2_binding_and_C_f0eca04e);
  except
    on E: Exception do
    begin WriteLn(E.ClassName + CozyText_Protection_VmProbe_Text_172ee021 + E.Message); ExitCode := 1; end;
  end;
end.
