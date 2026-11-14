program Cozy_CrcProbe;
{$IFDEF FPC}{$MODE DELPHI}{$ENDIF}
{$APPTYPE CONSOLE}
{$B-}
uses
{ Cozy central text imports. }
  Cozy.Strings.Crypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Crypto.pas',
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.TestsIntegrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsIntegrity.pas',

{$IFDEF FPC}
  SysUtils, Classes,
{$ELSE}
  Winapi.Windows, Winapi.PsAPI, System.SysUtils, System.Classes,
{$ENDIF}
  Cozy.CrcLayers in '..\..\Cozy.Source\Cozy.Integrity\Cozy.CrcLayers.pas',
  Cozy.Hashes.SHA512 in '..\..\Cozy.Source\Cozy.Crypto\Cozy.Hashes.SHA512.pas';
{$I Cozy.CrcCollisionVectors.inc}
procedure Require(Condition: Boolean; const Name: string);
begin if not Condition then raise Exception.Create(Name); end;

function CodeFrame(const Payload: TBytes; RVA: Cardinal = $1000): TBytes;
const Prefix: AnsiString = CozyText_CrcProbe_GAME_CODE_V1_35e1ff0f;
var At: Integer; Value: Cardinal;
begin
  At := Length(Prefix); SetLength(Result, At + 12 + Length(Payload));
  Move(Prefix[1], Result[0], At); Value := 1; Move(Value, Result[At], 4); Inc(At, 4);
  Move(RVA, Result[At], 4); Inc(At, 4); Value := Length(Payload);
  Move(Value, Result[At], 4); Inc(At, 4);
  if Length(Payload) <> 0 then Move(Payload[0], Result[At], Length(Payload));
end;

procedure CheckAcceleration;
const Lengths: array[0..18] of Integer = (0, 1, 2, 7, 8, 9, 15, 16, 17,
  31, 32, 33, 63, 64, 255, 256, 257, 4096, 65539);
var Data: TBytes; Reference, Fast, Streaming: TCrcState;
  Offset, N, I, At, Take: Integer;
begin
{$IFDEF COZY_CRC32C_REFERENCE_ONLY}
  Require(not Crc32CSlicingAvailable, CozyText_CrcProbe_REFERENCE_ONLY_BACKEND_8b225ab2);
{$ELSE}
  Require(Crc32CSlicingAvailable, CozyText_CrcProbe_SLICING_TABLE_DERIVATION_acd3d961);
{$ENDIF}
  SetLength(Data, 65539 + 16);
  for I := 0 to High(Data) do Data[I] := Byte((UInt64(I) * 131 + 17) and 255);
  for Offset := 0 to 15 do
    for N in Lengths do
    begin
      CrcInit(Reference, ckCrc32C, cmReference);
      CrcInit(Fast, ckCrc32C, cmSlicingBy8);
      CrcInit(Streaming, ckCrc32C, cmSlicingBy8);
      CrcUpdate(Reference, @Data[Offset], N); CrcUpdate(Fast, @Data[Offset], N);
      At := 0;
      while At < N do
      begin
        Take := (At mod 23) + 1; if Take > N - At then Take := N - At;
        CrcUpdate(Streaming, @Data[Offset + At], Take); Inc(At, Take);
        CrcFinal(Streaming);
      end;
      CrcUpdate(Streaming, nil, 0);
      Require(CrcFinal(Reference) = CrcFinal(Fast), CozyText_CrcProbe_CRC32C_ALIGNMENT_PARITY_382df856);
      Require(CrcFinal(Reference) = CrcFinal(Streaming), CozyText_CrcProbe_CRC32C_SPLIT_PARITY_aa257c97);
      Require((Fast.Bytes = UInt64(N)) and (Streaming.Bytes = UInt64(N)), CozyText_CrcProbe_CRC32C_BYTE_COUNT_a3e21ae3);
    end;
end;

procedure CheckCollisionBoundary(PublishVectors: Boolean);
var A, B, CodeA, CodeB, CrcA, CrcB, HashA, HashB, Moved: TBytes;
  I: Integer; AHash, BHash, ACodeHash, BCodeHash: string;
begin
  if PublishVectors then
    Writeln(CozyText_CrcProbe_JsonFixture_2a1d2d6e, CrcCollisionVectorName,
      CozyText_CrcProbe_scope_PORTABLE_CRC_AND_SHA512_PROBE_signatureVer_c9380c49);
  for I := Low(CrcCollisionSizes) to High(CrcCollisionSizes) do
  begin
    SetLength(A, CrcCollisionSizes[I]); SetLength(B, CrcCollisionSizes[I]);
    FillChar(A[0], Length(A), 0); FillChar(B[0], Length(B), 0);
    Move(CrcCollisionLeft[0], A[0], SizeOf(CrcCollisionLeft));
    Move(CrcCollisionRight[0], B[0], SizeOf(CrcCollisionRight));
    Require(not CompareMem(@A[0], @B[0], Length(A)), CozyText_CrcProbe_CRC_COLLISION_CONTENT_DIFFERS_7dc17a89);
    { Equality alone is insufficient: a broken implementation returning a
      constant would also pass it. Pin both public inputs to known answers. }
    Require(CrcBytes(ckCrc32C, A) = CrcCollisionCrc32c[I], CozyText_CrcProbe_CRC_COLLISION_LEFT_KNOWN_ANSWER_fa395873);
    Require(CrcBytes(ckCrc32C, B) = CrcCollisionCrc32c[I], CozyText_CrcProbe_CRC_COLLISION_RIGHT_KNOWN_ANSWER_cf7321a1);
    Require(CrcBytes(ckCrc32C, A) = CrcBytes(ckCrc32C, B), CozyText_CrcProbe_CRC_COLLISION_FIXTURE_95b2cd52);
    AHash := SHA512Bytes(A); BHash := SHA512Bytes(B);
    Require(AHash = CrcCollisionLeftSha512[I], CozyText_CrcProbe_CRC_COLLISION_LEFT_SHA512_KNOWN_ANSWER_1d31f26d);
    Require(BHash = CrcCollisionRightSha512[I], CozyText_CrcProbe_CRC_COLLISION_RIGHT_SHA512_KNOWN_ANSWER_a2c43564);
    Require(AHash <> BHash, CozyText_CrcProbe_FULL_SHA512_REJECTS_CRC_COLLISION_fea61601);
    CodeA := CodeFrame(A); CodeB := CodeFrame(B);
    CrcA := CrcCodePageManifest(CodeA); CrcB := CrcCodePageManifest(CodeB);
    Require((Length(CrcA) > 0) and (Length(CrcA) = Length(CrcB)), CozyText_CrcProbe_CRC_PAGE_MANIFEST_BOUND_79b73c64);
    Require(CompareMem(@CrcA[0], @CrcB[0], Length(CrcA)), CozyText_CrcProbe_CRC_PAGE_COLLISION_FIXTURE_357de8c3);
    HashA := CodePageSHA512Manifest(CodeA); HashB := CodePageSHA512Manifest(CodeB);
    Require((Length(HashA) > 0) and (Length(HashA) = Length(HashB)), CozyText_CrcProbe_SHA512_PAGE_MANIFEST_BOUND_40233d84);
    Require(SHA512Bytes(HashA) = CrcCollisionLeftPageManifestSha512[I], CozyText_CrcProbe_LEFT_PAGE_SHA512_KNOWN_ANSWER_066a1d86);
    Require(SHA512Bytes(HashB) = CrcCollisionRightPageManifestSha512[I], CozyText_CrcProbe_RIGHT_PAGE_SHA512_KNOWN_ANSWER_f17e9c35);
    Require(not CompareMem(@HashA[0], @HashB[0], Length(HashA)), CozyText_CrcProbe_PAGE_SHA512_REJECTS_CRC_COLLISION_77591279);
    ACodeHash := SHA512Bytes(CodeA); BCodeHash := SHA512Bytes(CodeB);
    Require(ACodeHash = CrcCollisionLeftCodeSha512[I], CozyText_CrcProbe_LEFT_CODE_SHA512_KNOWN_ANSWER_2f1058a5);
    Require(BCodeHash = CrcCollisionRightCodeSha512[I], CozyText_CrcProbe_RIGHT_CODE_SHA512_KNOWN_ANSWER_fad0aa69);
    Require(ACodeHash <> BCodeHash, CozyText_CrcProbe_FULL_CODE_SHA512_RETAINS_AUTHORITY_4ab70abc);
    Moved := CodePageSHA512Manifest(CodeFrame(A, $2000));
    Require((Length(Moved) = Length(HashA)) and
      not CompareMem(@HashA[0], @Moved[0], Length(HashA)), CozyText_CrcProbe_PAGE_SHA512_BINDS_RVA_78e62d4f);
    if PublishVectors then
    begin
      if I <> Low(CrcCollisionSizes) then Writeln(',');
      Write(CozyText_CrcProbe_JsonFixture_e1bc85d5, Length(A), CozyText_CrcProbe_crc32c_a41b806d, CrcCollisionCrc32c[I],
        CozyText_CrcProbe_leftSha512_3dc7eb88, AHash, CozyText_CrcProbe_rightSha512_d15c627d, BHash,
        CozyText_CrcProbe_leftCodeSha512_75beadf7, ACodeHash, CozyText_CrcProbe_rightCodeSha512_4452fb25, BCodeHash,
        CozyText_CrcProbe_contentDifferent_true_crcEqual_true_pageSha512Di_12168384);
    end;
  end;
  if PublishVectors then Writeln(CozyText_CrcProbe_outcome_PASS_abdae930);
end;

procedure MaximumPageMemory;
var Data, Code, Pages: TBytes;
{$IFNDEF FPC}
  Counters: PROCESS_MEMORY_COUNTERS;
{$ENDIF}
begin
  SetLength(Data, 64 * 1024 * 1024);
  Code := CodeFrame(Data); Data := nil;
  Pages := CodePageSHA512Manifest(Code);
  Require(Length(Pages) = Length(CozyText_CrcProbe_COZY_CODE_PAGES_SHA512_V1_93211faa) + 8 + 16384 * 72,
    CozyText_CrcProbe_MAXIMUM_PAGE_COUNT_AND_BOUND_b8d8eac2);
  Writeln(CozyText_CrcProbe_maximumCodeBytes_eb6831dc, Length(Code));
  Writeln(CozyText_CrcProbe_maximumPageManifestBytes_207bc573, Length(Pages));
  Writeln(CozyText_CrcProbe_maximumPagePayloadBytes_aec4fecf, UInt64(Length(Code)) + UInt64(Length(Pages)));
{$IFNDEF FPC}
  FillChar(Counters, SizeOf(Counters), 0); Counters.cb := SizeOf(Counters);
  Require(GetProcessMemoryInfo(GetCurrentProcess, @Counters, SizeOf(Counters)), CozyText_CrcProbe_PROCESS_MEMORY_QUERY_6a311646);
  Writeln(CozyText_CrcProbe_observedProcessPeakWorkingSetBytes_f8a7f026, UInt64(Counters.PeakWorkingSetSize));
  Writeln(CozyText_CrcProbe_observedProcessPeakPagefileBytes_c138d1e4, UInt64(Counters.PeakPagefileUsage));
  Writeln(CozyText_CrcProbe_measurementScope_ACTUAL_WINDOWS_PORTABLE_PAGE_HA_5ea4697b);
{$ELSE}
  Writeln(CozyText_CrcProbe_windowsProcessPeakMetrics_NOT_RUN_46e019ee);
{$ENDIF}
end;

var
  Kind: TCrcKind;
  Data: TBytes;
  Stream: TFileStream;
  State: TCrcState;
  I, At, Count: Integer;
  Expected, FileName: string;
begin
  try
    if not CrcSelfTest then raise Exception.Create(CozyText_CrcProbe_CRC_known_answer_failure_47fbb496);
    CheckAcceleration;
    CheckCollisionBoundary((ParamCount = 1) and (ParamStr(1) = CozyText_CrcProbe_collision_vectors_3f68e2ee));
    if (ParamCount = 1) and (ParamStr(1) = CozyText_CrcProbe_collision_vectors_3f68e2ee) then Halt(0);
    if (ParamCount = 1) and (ParamStr(1) = CozyText_CrcProbe_maximum_pages_c59398e7) then
    begin MaximumPageMemory; Halt(0); end;
    if (ParamCount = 1) or ((ParamCount = 2) and ((ParamStr(1) = CozyText_CrcProbe_pages_6dd964e5) or (ParamStr(1) = CozyText_CrcProbe_pages_sha512_f3895e8d))) then
    begin
      FileName := ParamStr(1);
      if ParamCount = 2 then FileName := ParamStr(2);
      Stream := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
      try
        if Stream.Size > 64 * 1024 * 1024 then raise Exception.Create(CozyText_CrcProbe_Probe_input_too_large_a72c5b50);
        SetLength(Data, Integer(Stream.Size));
        if Length(Data) > 0 then Stream.ReadBuffer(Data[0], Length(Data));
      finally
        Stream.Free;
      end;
    end
    else
    begin
      SetLength(Data, 65539);
      for I := 0 to High(Data) do Data[I] := Byte((UInt64(I) * 131 + 17) and 255);
    end;
    if ParamCount = 2 then
    begin
      if ParamStr(1) = CozyText_CrcProbe_pages_sha512_f3895e8d then Data := CodePageSHA512Manifest(Data)
      else Data := CrcCodePageManifest(Data);
      Write(CozyText_CrcProbe_pages_b9e812b5);
      for I := 0 to High(Data) do Write(IntToHex(Data[I], 2));
      Writeln;
      Halt(0);
    end;
    for Kind := Low(TCrcKind) to High(TCrcKind) do
    begin
      Expected := CrcBytes(Kind, Data);
      CrcInit(State, Kind);
      CrcUpdate(State, nil, 0);
      At := 0;
      while At < Length(Data) do
      begin
        Count := (At mod 521) + 1;
        if Count > Length(Data) - At then Count := Length(Data) - At;
        CrcUpdate(State, @Data[At], Count);
        { Final is a snapshot, not destructive to incremental operation. }
        CrcFinalHex(State);
        Inc(At, Count);
      end;
      if CrcFinalHex(State) <> Expected then raise Exception.Create(CozyText_CrcProbe_CRC_streaming_mismatch_a4d5f695);
      Writeln(CrcKindName(Kind), '=', Expected);
    end;
    Data := CrcParameterBytes;
    Writeln(CozyText_CrcProbe_parameters_2989cc4c, CrcBytes(ckWe, Data));
    Data := CrcAllTableBytes;
    Writeln(CozyText_CrcProbe_tables_2d5cf30c, CrcBytes(ckWe, Data));
  except
    on E: Exception do
    begin
      Writeln(E.ClassName, CozyText_CrcProbe_Text_14627ee0, E.Message);
      Halt(1);
    end;
  end;
end.
