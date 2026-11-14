program Cozy_IntegrityHashProbe;
{ Portable common-stream contract probe. No network, Windows API or secret keys.
  fpc -Mdelphi -O2 -Fu.. -FE<temp-dir> -FU<temp-dir> cozy.IntegrityHashProbe.dpr
  dcc64 -U.. -E<temp-dir> -N0<temp-dir> cozy.IntegrityHashProbe.dpr
  No arguments: known-answer, chunking, reset and argument-boundary contracts.
  <file> <chunk-size>: count, XXH3-128, BLAKE3, SHA-512 (tab-separated). }
{$IFDEF FPC}{$MODE DELPHI}{$ELSE}{$APPTYPE CONSOLE}{$ENDIF}
uses
{ Cozy central text imports. }
  Cozy.Strings.Crypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Crypto.pas',
  Cozy.Strings.TestsCrypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsCrypto.pas',

{$IFDEF FPC} SysUtils, Classes, {$ELSE} System.SysUtils, System.Classes, {$ENDIF}
  Cozy.Hashes;

procedure Require(Value: Boolean; const MessageText: string);
begin
  if not Value then raise Exception.Create(MessageText);
end;

procedure Same(const Actual, Expected: TIntegrityHashResult; const LabelText: string);
begin
  Require(Actual.SHA512 = Expected.SHA512, LabelText + CozyText_IntegrityHashProbe_SHA_512_f60c756c);
  Require(Actual.XXH3_128 = Expected.XXH3_128, LabelText + CozyText_IntegrityHashProbe_XXH3_128_62f672f7);
  Require(Actual.Blake3 = Expected.Blake3, LabelText + CozyText_IntegrityHashProbe_BLAKE3_e9d7fc94);
  Require(Actual.Size = Expected.Size, LabelText + CozyText_IntegrityHashProbe_byte_count_524ed3a3);
end;

procedure CheckKnown(const Data: TBytes; const SHA512, XXH3, Blake3: string);
var Actual: TIntegrityHashResult;
begin
  Actual := IntegrityHashesBytes(Data);
  Require(Actual.SHA512 = SHA512, CozyText_IntegrityHashProbe_Known_answer_SHA_512_314975eb);
  Require(Actual.XXH3_128 = XXH3, CozyText_IntegrityHashProbe_Known_answer_XXH3_128_cc7ce9e4);
  Require(Actual.Blake3 = Blake3, CozyText_IntegrityHashProbe_Known_answer_BLAKE3_81721ad9);
  Require(Actual.Size = UInt64(Length(Data)), CozyText_IntegrityHashProbe_Known_answer_size_a28c60ea);
end;

procedure Contracts;
const
  Steps: array[0..19] of Integer = (1, 7, 31, 63, 64, 65, 127, 128, 129,
    239, 240, 241, 255, 256, 257, 1023, 1024, 1025, 4093, 65536);
  Sizes: array[0..18] of Integer = (0, 1, 3, 63, 64, 65, 127, 128, 129,
    239, 240, 241, 255, 256, 257, 1023, 1024, 1025, 65536);
var
  Hasher: TIntegrityHasher;
  Data, Empty, Prefix: TBytes;
  Expected, Snapshot: TIntegrityHashResult;
  NilBuffer: PByte;
  I, J, K, At, Take: Integer;
  Rejected: Boolean;
begin
  Empty := nil;
  Data := nil;
  CheckKnown(Empty,
    CozyText_IntegrityHashProbe_Digest_951b1188,
    CozyText_IntegrityHashProbe_Digest_8074d43c,
    CozyText_IntegrityHashProbe_Digest_546b7f99);
  SetLength(Data, 3); Data[0] := 97; Data[1] := 98; Data[2] := 99;
  CheckKnown(Data,
    CozyText_IntegrityHashProbe_Digest_787909f9,
    CozyText_IntegrityHashProbe_Digest_57a54ee6,
    CozyText_IntegrityHashProbe_Digest_6333269d);
  SetLength(Data, 1025); for I := 0 to High(Data) do Data[I] := Byte(I mod 251);
  CheckKnown(Data,
    CozyText_IntegrityHashProbe_Digest_6b6ac4a2,
    CozyText_IntegrityHashProbe_Digest_5446e383,
    CozyText_IntegrityHashProbe_Digest_e0f5bad5);
  Hasher := TIntegrityHasher.Create;
  try
    for I := Low(Sizes) to High(Sizes) do
    begin
      SetLength(Data, Sizes[I]);
      for J := 0 to High(Data) do Data[J] := Byte(J mod 251);
      Expected.SHA512 := SHA512Bytes(Data);
      Expected.XXH3_128 := XXHash3_128Bytes(Data);
      Expected.Blake3 := Blake3Bytes(Data);
      Expected.Size := Length(Data);
      for J := Low(Steps) to High(Steps) do
      begin
        Hasher.Reset;
        NilBuffer := nil;
        Hasher.Update(NilBuffer^, 0);
        At := 0;
        while At < Length(Data) do
        begin
          Take := Steps[J];
          if Take > Length(Data) - At then Take := Length(Data) - At;
          Hasher.Update(Data[At], Take);
          Inc(At, Take);
          { Repeated snapshots must not finalize or consume the stream. }
          if At = Take then
          begin
            Snapshot := Hasher.Finish;
            Prefix := Copy(Data, 0, At);
            Same(Snapshot, IntegrityHashesBytes(Prefix), CozyText_IntegrityHashProbe_Prefix_snapshot_7ef21ed9);
            Same(Hasher.Finish, Snapshot, CozyText_IntegrityHashProbe_Repeated_prefix_9056ac4e);
          end;
        end;
        Same(Hasher.Finish, Expected, CozyText_IntegrityHashProbe_Partition_result_23a66450);
        Same(Hasher.Finish, Expected, CozyText_IntegrityHashProbe_Repeated_final_snapshot_27168962);
        Hasher.Update(NilBuffer^, 0);
        Same(Hasher.Finish, Expected, CozyText_IntegrityHashProbe_Empty_update_after_finish_4afa90e8);
        { Rejected ranges must not advance any component. }
        Rejected := False;
        try Hasher.Update(NilBuffer^, 1);
        except on E: EArgumentException do Rejected := True; end;
        Require(Rejected, CozyText_IntegrityHashProbe_Nonempty_nil_input_accepted_8c415523);
        Same(Hasher.Finish, Expected, CozyText_IntegrityHashProbe_Rejected_nil_preserves_stream_9d58cfb1);
        K := 0;
        Rejected := False;
        try Hasher.Update(K, High(NativeUInt));
        except on E: ERangeError do Rejected := True; end;
        Require(Rejected, CozyText_IntegrityHashProbe_Wrapping_address_range_accepted_e226d121);
        Same(Hasher.Finish, Expected, CozyText_IntegrityHashProbe_Rejected_overflow_preserves_stream_67f2dd5b);
      end;
    end;
    Hasher.Reset;
    Same(Hasher.Finish, IntegrityHashesBytes(Empty), CozyText_IntegrityHashProbe_Reset_returns_empty_digest_54de1931);
    SetLength(Data, 3); Data[0] := 97; Data[1] := 98; Data[2] := 99;
    Hasher.Update(Data[0], 1);
    Snapshot := Hasher.Finish;
    Require(Snapshot.Size = 1, CozyText_IntegrityHashProbe_Partial_count_ca1781d6);
    Hasher.Update(Data[1], 2);
    Same(Hasher.Finish, IntegrityHashesBytes(Data), CozyText_IntegrityHashProbe_Continue_after_finish_f00c9891);
    Hasher.Reset;
    Hasher.Update(Data[0], Length(Data));
    Same(Hasher.Finish, IntegrityHashesBytes(Data), CozyText_IntegrityHashProbe_Reuse_after_reset_48cda711);
  finally
    Hasher.Free;
  end;
  WriteLn(CozyText_IntegrityHashProbe_PASS_common_hash_known_answers_380_chunk_partiti_639a7e34);
end;

procedure HashFile;
var
  Hasher: TIntegrityHasher;
  Stream: TFileStream;
  Buffer: TBytes;
  Count, Step: Integer;
  Actual: TIntegrityHashResult;
begin
  Require(ParamCount = 2, CozyText_IntegrityHashProbe_Usage_Cozy_IntegrityHashProbe_file_chunk_size_52210b73);
  Step := StrToInt(ParamStr(2));
  Require((Step > 0) and (Step <= 1048576), CozyText_IntegrityHashProbe_Invalid_chunk_size_559e3dc2);
  Hasher := TIntegrityHasher.Create;
  Stream := nil;
  Buffer := nil;
  try
    Stream := TFileStream.Create(ParamStr(1), fmOpenRead or fmShareDenyWrite);
    SetLength(Buffer, Step);
    repeat
      Count := Stream.Read(Buffer[0], Length(Buffer));
      if Count = 0 then Break;
      Hasher.Update(Buffer[0], Count);
    until False;
    Actual := Hasher.Finish;
    WriteLn(UIntToStr(Actual.Size), #9, Actual.XXH3_128, #9,
      Actual.Blake3, #9, Actual.SHA512);
  finally
    if Length(Buffer) <> 0 then FillChar(Buffer[0], Length(Buffer), 0);
    Stream.Free;
    Hasher.Free;
  end;
end;

begin
  try
    if ParamCount = 0 then Contracts else HashFile;
  except
    on E: Exception do
    begin
      WriteLn(E.ClassName, CozyText_IntegrityHashProbe_Text_b70d3142, E.Message);
      Halt(1);
    end;
  end;
end.
