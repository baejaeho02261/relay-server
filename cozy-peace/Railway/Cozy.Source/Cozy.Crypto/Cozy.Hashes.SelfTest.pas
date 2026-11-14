unit Cozy.Hashes.SelfTest;

{$IFDEF FPC}{$MODE DELPHI}{$ENDIF}
{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$J-}
{$B-}

interface
{ Cozy central text imports. }
uses
  Cozy.Strings.Crypto;


{ Public known-answer diagnostics. These vectors are neither secrets nor
  server integrity baselines, licenses, keys or authorization decisions. }
function IntegrityAlgorithmsSelfTest: Boolean;

implementation

uses
  {$IFDEF FPC}SysUtils,{$ELSE}System.SysUtils,{$ENDIF}
  Cozy.Hashes, Cozy.CrcLayers;

const
  KnownInput: array[0..2] of Byte = (97, 98, 99);
  SHA512Answer: array[0..63] of Byte = (
    $DD, $AF, $35, $A1, $93, $61, $7A, $BA,
    $CC, $41, $73, $49, $AE, $20, $41, $31,
    $12, $E6, $FA, $4E, $89, $A9, $7E, $A2,
    $0A, $9E, $EE, $E6, $4B, $55, $D3, $9A,
    $21, $92, $99, $2A, $27, $4F, $C1, $A8,
    $36, $BA, $3C, $23, $A3, $FE, $EB, $BD,
    $45, $4D, $44, $23, $64, $3C, $E8, $0E,
    $2A, $9A, $C9, $4F, $A5, $4C, $A4, $9F);
  XXH3Answer: array[0..15] of Byte = (
    $06, $B0, $5A, $B6, $73, $3A, $61, $85,
    $78, $AF, $5F, $94, $89, $2F, $39, $50);
  Blake3Answer: array[0..31] of Byte = (
    $64, $37, $B3, $AC, $38, $46, $51, $33,
    $FF, $B6, $3B, $75, $27, $3A, $8D, $B5,
    $48, $C5, $58, $46, $5D, $79, $DB, $03,
    $FD, $35, $9C, $6C, $D5, $BD, $9D, $85);

const
  Blake3KeyedAnswer: array[0..31] of Byte = (
    $92, $B2, $B7, $56, $04, $ED, $3C, $76,
    $1F, $9D, $6F, $62, $39, $2C, $8A, $92,
    $27, $AD, $0E, $A3, $F0, $95, $73, $E7,
    $83, $F1, $49, $8A, $4E, $D6, $0D, $26);
  Blake3DeriveAnswer: array[0..31] of Byte = (
    $2C, $C3, $97, $83, $C2, $23, $15, $4F,
    $EA, $8D, $FB, $7C, $1B, $16, $60, $F2,
    $AC, $2D, $CB, $D1, $C1, $DE, $82, $77,
    $B0, $B0, $DD, $39, $B7, $E5, $0D, $7D);

function HexNibble(Value: Char): Integer;
begin
  if (Value >= '0') and (Value <= '9') then
    Result := Ord(Value) - Ord('0')
  else if (Value >= 'a') and (Value <= 'f') then
    Result := Ord(Value) - Ord('a') + 10
  else
    Result := -1;
end;

function MatchesKnownAnswer(const Value: string; const Expected: array of Byte): Boolean;
var I, Upper, Lower: Integer;
begin
  if Length(Value) <> Length(Expected) * 2 then Exit(False);
  for I := 0 to High(Expected) do
  begin
    Upper := HexNibble(Value[I * 2 + 1]);
    Lower := HexNibble(Value[I * 2 + 2]);
    if (Upper < 0) or (Lower < 0) then Exit(False);
    if Byte(Upper * 16 + Lower) <> Expected[I] then Exit(False);
  end;
  Result := True;
end;

function Blake3ModesSelfTest: Boolean;
const
  PublicKey: AnsiString = CozyText_Hashes_SelfTest_whats_the_Elvish_word_for_friend_eb04f1bf;
  PublicContext: AnsiString = CozyText_Hashes_SelfTest_BLAKE3_2019_12_27_16_29_52_test_vectors_context_c78916f2;
var Key, Context: TBytes; Keyed, Derived: TBlake3Hasher; I: Integer;
begin
  Keyed := nil; Derived := nil;
  SetLength(Key, Length(PublicKey)); SetLength(Context, Length(PublicContext));
  try
    for I := 1 to Length(PublicKey) do Key[I - 1] := Byte(PublicKey[I]);
    for I := 1 to Length(PublicContext) do Context[I - 1] := Byte(PublicContext[I]);
    Keyed := TBlake3Hasher.CreateKeyed(Key);
    Derived := TBlake3Hasher.CreateDeriveKey(Context);
    Result := MatchesKnownAnswer(Keyed.FinishHex, Blake3KeyedAnswer) and
      MatchesKnownAnswer(Derived.FinishHex, Blake3DeriveAnswer);
  finally
    Derived.Free; Keyed.Free;
    if Length(Key) <> 0 then FillChar(Key[0], Length(Key), 0);
    if Length(Context) <> 0 then FillChar(Context[0], Length(Context), 0);
  end;
end;

function IntegrityAlgorithmsSelfTest: Boolean;
var Input: TBytes; Digest: TIntegrityHashResult;
begin
  SetLength(Input, Length(KnownInput));
  try
    Move(KnownInput[0], Input[0], Length(KnownInput));
    Digest := IntegrityHashesBytes(Input);
    Result := (Digest.Size = Length(KnownInput)) and
      MatchesKnownAnswer(Digest.SHA512, SHA512Answer) and
      MatchesKnownAnswer(Digest.XXH3_128, XXH3Answer) and
      MatchesKnownAnswer(Digest.Blake3, Blake3Answer) and Blake3ModesSelfTest and CrcSelfTest;
  finally
    FillChar(Input[0], Length(Input), 0);
    Input := nil;
  end;
end;

end.
