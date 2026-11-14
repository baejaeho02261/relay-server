program Cozy_HashContracts;
{ Invalid-argument and XOF lifecycle tests for the portable native implementation. }
{$IFDEF FPC}{$MODE DELPHI}{$ELSE}{$APPTYPE CONSOLE}{$ENDIF}
uses
{ Cozy central text imports. }
  Cozy.Strings.Crypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Crypto.pas',
  Cozy.Strings.TestsCrypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsCrypto.pas',

{$IFDEF FPC} SysUtils, {$ELSE} System.SysUtils, {$ENDIF}
  Cozy.Hashes;
var
  H: TBlake3Hasher;
  Key, Material, Empty: TBytes;
  Text, Tail: string;
  Failed: Boolean;
  I: Integer;
procedure Require(Value: Boolean; const MessageText: string);
begin if not Value then raise Exception.Create(MessageText); end;
begin
  try
    Empty := nil; Material := nil; Key := nil;
    for I := 0 to 33 do
      if I <> 32 then begin
        SetLength(Key, I); H := nil; Failed := False;
        try
          try H := TBlake3Hasher.CreateKeyed(Key);
          except on E: EArgumentException do Failed := True; end;
        finally H.Free; end;
        Require(Failed, CozyText_HashContracts_Non_32_byte_key_accepted_6878c049);
      end;
    SetLength(Key, 32); for I := 0 to 31 do Key[I] := I;
    H := TBlake3Hasher.CreateKeyed(Key);
    try
      Require(Length(H.FinishBytes(0)) = 0, CozyText_HashContracts_Zero_length_XOF_failed_2b32dae6);
      Failed := False;
      try Material := H.FinishBytes(-1); except on E: EArgumentException do Failed := True; end;
      Require(Failed, CozyText_HashContracts_Negative_XOF_length_accepted_caa66429);
      Failed := False;
      try Material := H.FinishBytes(2, High(UInt64)); except on E: ERangeError do Failed := True; end;
      Require(Failed, CozyText_HashContracts_XOF_position_overflow_accepted_ad7fe84f);
      Failed := False;
      try Text := H.FinishHex(High(Integer)); except on E: ERangeError do Failed := True; end;
      Require(Failed, CozyText_HashContracts_Hex_allocation_integer_overflow_accepted_1b50b6cf);
      Text := H.FinishHex(131); Tail := H.FinishHex(68, 63);
      Require(Copy(Text, 127, 136) = Tail, CozyText_HashContracts_XOF_seek_mismatch_54718f14);
      H.Update(Key[0], Length(Key)); Text := H.FinishHex;
      Material := Blake3KeyedBytes(Key, Key);
      Require(Length(Material) = 32, CozyText_HashContracts_Keyed_convenience_output_length_07c951ec);
      Tail := ''; for I := 0 to High(Material) do Tail := Tail + LowerCase(IntToHex(Material[I], 2));
      Require(Text = Tail, CozyText_HashContracts_Keyed_helper_mismatch_9290411b);
    finally H.Free; end;
    H := TBlake3Hasher.CreateDeriveKey(Empty);
    try
      H.Update(Key[0], Length(Key)); Text := H.FinishHex;
      Material := Blake3DeriveKeyBytes(Empty, Key);
      Tail := ''; for I := 0 to High(Material) do Tail := Tail + LowerCase(IntToHex(Material[I], 2));
      Require(Text = Tail, CozyText_HashContracts_Derive_helper_mismatch_d4989547);
    finally H.Free; end;
    FillChar(Key[0], Length(Key), 0); FillChar(Material[0], Length(Material), 0);
    WriteLn(CozyText_HashContracts_PASS_invalid_key_sizes_XOF_lengths_overflow_seek_af66901e);
  except on E: Exception do begin WriteLn(E.ClassName, CozyText_HashContracts_Text_7069facb, E.Message); Halt(1); end; end;
end.
