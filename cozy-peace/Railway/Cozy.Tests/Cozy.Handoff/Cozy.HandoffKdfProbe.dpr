program Cozy_HandoffKdfProbe;
{$IFDEF FPC}{$MODE DELPHI}{$ELSE}{$APPTYPE CONSOLE}{$ENDIF}
uses
{ Cozy central text imports. }
  Cozy.Strings.Crypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Crypto.pas',
  Cozy.Strings.Handoff in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Handoff.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.TestsHandoff in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsHandoff.pas',
 {$IFDEF FPC}SysUtils,{$ELSE}System.SysUtils,{$ENDIF}Cozy.Handoff.Kdf, Cozy.Api.Contracts;
function Bytes(const S: AnsiString): TBytes;
var I: Integer;
begin SetLength(Result, Length(S)); for I := 1 to Length(S) do Result[I-1] := Byte(S[I]); end;
function Hex(const Value: TBytes): string;
var I: Integer;
begin Result := ''; for I := 0 to High(Value) do Result := Result + LowerCase(IntToHex(Value[I], 2)); end;
var Seed, Original, Transcript, Key, Changed: TBytes; I, N: Integer; Rejected: Boolean;
  Owned: TApiSensitiveBuffer; Scope: TApiSensitiveScope;
begin
  try
    SetLength(Seed, 32); for I := 0 to 31 do Seed[I] := I;
    Original := Copy(Seed); Transcript := Bytes(CozyText_HandoffKdfProbe_GAME_HANDOFF_V3_A_B_PUBLIC_TEST_b2414602);
    Key := DeriveHandoffContentKey(Seed, Transcript);
    if Hex(Key) <> CozyText_HandoffKdfProbe_Digest_40c22b53 then
      raise Exception.Create(CozyText_HandoffKdfProbe_Independent_upstream_KDF_vector_mismatch_b13609e5);
    if Hex(Seed) <> Hex(Original) then raise Exception.Create(CozyText_HandoffKdfProbe_Borrowed_seed_changed_345b11e4);
    Owned := DeriveHandoffContentKeyOwned(TApiBuffer.ReadBytes(Seed), Transcript);
    try
      Scope := Owned.OpenRead;
      try
        if (Owned.Capacity <> 32) or not CompareMem(Scope.Buffer.Read(0, 32), @Key[0], 32) then
          raise Exception.Create(CozyText_HandoffKdfProbe_Owned_KDF_differs_from_independent_vector_19a60728);
      finally Scope.Free; end;
    finally Owned.Free; end;
    Transcript[0] := Transcript[0] xor 1;
    Changed := DeriveHandoffContentKey(Seed, Transcript);
    if Hex(Changed) = Hex(Key) then raise Exception.Create(CozyText_HandoffKdfProbe_Transcript_separation_failed_69edce4d);
    Transcript[0] := Transcript[0] xor 1; Seed[0] := Seed[0] xor 1;
    Changed := DeriveHandoffContentKey(Seed, Transcript);
    if Hex(Changed) = Hex(Key) then raise Exception.Create(CozyText_HandoffKdfProbe_Fresh_seed_separation_failed_c2ef4cb2);
    for N := 0 to 2 do begin
      Seed := Copy(Original); Transcript := Bytes(CozyText_HandoffKdfProbe_test_f5be38f8);
      if N = 0 then SetLength(Seed, 31);
      if N = 1 then SetLength(Transcript, 0);
      if N = 2 then SetLength(Transcript, 8193);
      Rejected := False;
      try Changed := DeriveHandoffContentKey(Seed, Transcript); except Rejected := True; end;
      if not Rejected then raise Exception.Create(CozyText_HandoffKdfProbe_Invalid_key_derivation_input_accepted_0da676c8);
    end;
    WriteLn(CozyText_HandoffKdfProbe_PASS_HANDOFF_KDF_independent_vector_seed_transcr_7e7d0457);
  except on E: Exception do begin WriteLn(E.Message); Halt(1); end; end;
end.
