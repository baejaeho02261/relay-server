program Cozy_HashProbe;
{ Validation CLI only, not linked into the product.
  Usage: Cozy.HashProbe <file> <positive-update-size> [hash|keyed|derive] [xof-bytes] [seek]
  Output: byte count, XXH3-128, BLAKE3 mode/XOF output, SHA-512 (tab-separated).
  Key/context below are public official test-vector constants, never production keys. }
{$IFDEF FPC}{$MODE DELPHI}{$ELSE}{$APPTYPE CONSOLE}{$ENDIF}
uses
{ Cozy central text imports. }
  Cozy.Strings.Crypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Crypto.pas',
  Cozy.Strings.TestsCrypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsCrypto.pas',

{$IFDEF FPC} SysUtils, Classes, {$ELSE} System.SysUtils, System.Classes, {$ENDIF}
  Cozy.Hashes;
var
  Stream: TFileStream;
  XX: TXXHash3_128;
  SHA: TSHA512Hasher;
  Blake: TBlake3Hasher;
  Buffer, Whole, Key, Context: TBytes;
  Count, UpdateSize, OutputLength: Integer;
  Total, Seek: UInt64;
  XXText, BlakeText, SHAText, Mode, SnapshotXX, SnapshotBlake, SnapshotSHA: string;
function ASCIIBytes(const S: AnsiString): TBytes;
var I: Integer;
begin
  SetLength(Result, Length(S));
  for I := 1 to Length(S) do Result[I - 1] := Byte(S[I]);
end;
begin
  XX := nil; SHA := nil; Blake := nil; Stream := nil;
  try
    try
      if (ParamCount < 2) or (ParamCount > 5) then
        raise Exception.Create(CozyText_HashProbe_Usage_Cozy_HashProbe_file_update_size_hash_keyed_7030f71c);
      UpdateSize := StrToInt(ParamStr(2));
      if (UpdateSize < 1) or (UpdateSize > 1048576) then raise Exception.Create(CozyText_HashProbe_Invalid_update_size_9e4419d4);
      Mode := CozyText_HashProbe_hash_dd1ef3c4; if ParamCount >= 3 then Mode := ParamStr(3);
      OutputLength := 32; if ParamCount >= 4 then OutputLength := StrToInt(ParamStr(4));
      Seek := 0; if ParamCount >= 5 then Seek := StrToUInt64(ParamStr(5));
      if (OutputLength < 0) or (OutputLength > 65536) then raise Exception.Create(CozyText_HashProbe_Invalid_XOF_size_9eb99360);
      Key := ASCIIBytes(CozyText_HashProbe_whats_the_Elvish_word_for_friend_5905c7e3);
      Context := ASCIIBytes(CozyText_HashProbe_BLAKE3_2019_12_27_16_29_52_test_vectors_context_1bea33fc);
      if Mode = CozyText_HashProbe_hash_dd1ef3c4 then Blake := TBlake3Hasher.Create
      else if Mode = CozyText_HashProbe_keyed_741b0ec6 then Blake := TBlake3Hasher.CreateKeyed(Key)
      else if Mode = CozyText_HashProbe_derive_afff3795 then Blake := TBlake3Hasher.CreateDeriveKey(Context)
      else raise Exception.Create(CozyText_HashProbe_Invalid_mode_d3e23cc9);
      XX := TXXHash3_128.Create; SHA := TSHA512Hasher.Create;
      Stream := TFileStream.Create(ParamStr(1), fmOpenRead or fmShareDenyWrite);
      SetLength(Buffer, UpdateSize); Total := 0;
      XX.Update(Buffer[0], 0); SHA.Update(Buffer[0], 0); Blake.Update(Buffer[0], 0);
      repeat
        Count := Stream.Read(Buffer[0], Length(Buffer)); if Count = 0 then Break;
        XX.Update(Buffer[0], NativeUInt(Count)); SHA.Update(Buffer[0], NativeUInt(Count)); Blake.Update(Buffer[0], NativeUInt(Count));
        Inc(Total, UInt64(Count));
        if Total <= 4096 then begin
          SnapshotXX := XX.FinishHex; SnapshotBlake := Blake.FinishHex(OutputLength, Seek); SnapshotSHA := SHA.FinishHex;
          if (SnapshotXX <> XX.FinishHex) or (SnapshotBlake <> Blake.FinishHex(OutputLength, Seek)) or (SnapshotSHA <> SHA.FinishHex) then
            raise Exception.Create(CozyText_HashProbe_Finalization_changed_the_streaming_state_bb006373);
        end;
      until False;
      XXText := XX.FinishHex; BlakeText := Blake.FinishHex(OutputLength, Seek); SHAText := SHA.FinishHex;
      if (XXText <> XX.FinishHex) or (BlakeText <> Blake.FinishHex(OutputLength, Seek)) or (SHAText <> SHA.FinishHex) then
        raise Exception.Create(CozyText_HashProbe_Finalization_changed_final_state_de603090);
      if Total <= 1048576 then begin
        SetLength(Whole, Integer(Total)); Stream.Position := 0;
        if Total <> 0 then Stream.ReadBuffer(Whole[0], Integer(Total));
        if (XXHash3_128Bytes(Whole) <> XXText) or (SHA512Bytes(Whole) <> SHAText) then
          raise Exception.Create(CozyText_HashProbe_Streaming_differs_from_byte_array_API_0dc6bdaf);
        if (Mode = CozyText_HashProbe_hash_dd1ef3c4) and (OutputLength = 32) and (Seek = 0) and (Blake3Bytes(Whole) <> BlakeText) then
          raise Exception.Create(CozyText_HashProbe_BLAKE3_byte_array_API_mismatch_bbab11a7);
      end;
      WriteLn(UIntToStr(Total), #9, XXText, #9, BlakeText, #9, SHAText);
    finally
      Stream.Free; XX.Free; SHA.Free; Blake.Free;
      if Length(Key) <> 0 then FillChar(Key[0], Length(Key), 0);
      if Length(Buffer) <> 0 then FillChar(Buffer[0], Length(Buffer), 0);
      if Length(Whole) <> 0 then FillChar(Whole[0], Length(Whole), 0);
    end;
  except on E: Exception do begin WriteLn(E.ClassName, CozyText_HashProbe_Text_4d0878e4, E.Message); Halt(1); end; end;
end.
