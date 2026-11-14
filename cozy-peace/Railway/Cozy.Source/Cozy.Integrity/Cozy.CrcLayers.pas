unit Cozy.CrcLayers;

{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$IFDEF FPC}{$MODE DELPHI}{$ENDIF}
{$B-}{$Q-}{$R-}
{$IFNDEF FPC}{$STACKFRAMES ON}{$ENDIF}

{ Supplemental corruption measurements, not authentication or attestation.
  Every variant is explicit. JONES uses init=all-ones, xorout=0; it is not
  REDIS. ISO means GO-ISO. CRC16 means ARC. CRC8 means SMBUS.
  Parameters: https://reveng.sourceforge.io/crc-catalogue/
  Validation: Cozy.tests/Cozy.CrcProbe.dpr and Relay Server/scripts/test-crc-layers.js. }
interface

uses
{ Cozy central text imports. }
  Cozy.Strings.Integrity,

{$IFDEF FPC}
  SysUtils;
{$ELSE}
  System.SysUtils;
{$ENDIF}

type
  TCrcCheckpoint = procedure(Context: Pointer);
  TCrcKind = (ckEcma182, ckNvme, ckJones, ckXz, ckWe, ckIso,
    ckCrc32C, ckCrc16Arc, ckCrc8Smbus);
  { Portable software acceleration; no CPU instruction or alignment dependency. }
  TCrc32CMode = (cmAuto, cmReference, cmSlicingBy8);
  TCrcState = record
    Kind: TCrcKind;
    Value, Bytes: UInt64;
    Ready: Boolean;
    Mode: TCrc32CMode;
  end;

procedure CrcInit(out State: TCrcState; Kind: TCrcKind;
  Mode: TCrc32CMode = cmAuto);
procedure CrcUpdate(var State: TCrcState; Buffer: Pointer; Count: NativeUInt);
function Crc32CSlicingAvailable: Boolean;
function CrcFinal(const State: TCrcState): UInt64;
function CrcFinalHex(const State: TCrcState): string;
function CrcBufferHex(Kind: TCrcKind; Buffer: Pointer; Count: NativeUInt): string;
function CrcBytes(Kind: TCrcKind; const Bytes: TBytes): string;
function CrcKindName(Kind: TCrcKind): string;
function CrcTableBytes(Kind: TCrcKind): TBytes;
function CrcAllTableBytes: TBytes;
function CrcParameterBytes: TBytes;
{ One independently measured CRC32C for each RVA-aligned 4096-byte code page.
  Input is the already relocation-normalized GAME-CODE-V1 stream. Output is
  bounded, canonical little-endian framing, suitable for an authenticated
  SHA-512 digest. No function extent is guessed from a function pointer. }
function CrcCodePageManifest(const CodeStream: TBytes;
  Checkpoint: TCrcCheckpoint = nil; Context: Pointer = nil): TBytes;
{ Independent cryptographic page manifest. Each digest covers a domain tag,
  LE32 RVA, LE32 length and actual normalized bytes, not the page CRC. }
function CodePageSHA512Manifest(const CodeStream: TBytes;
  Checkpoint: TCrcCheckpoint = nil; Context: Pointer = nil): TBytes;
function CrcLayoutState(CodeBytes, HeaderBytes, ExportBytes: UInt64): TBytes;
function CrcSelfTest: Boolean;

implementation

uses Cozy.Hashes.SHA512;

type
  TCrcSpec = packed record
    Width: Byte;
    Reflected: Boolean;
    Poly, Initial, XorOut, Check: UInt64;
  end;
  TCrcTable = array[0..255] of UInt64;

const
  Specs: array[TCrcKind] of TCrcSpec = (
    (Width:64; Reflected:False; Poly:$42F0E1EBA9EA3693; Initial:0; XorOut:0; Check:$6C40DF5F0B497347),
    (Width:64; Reflected:True; Poly:$AD93D23594C93659; Initial:$FFFFFFFFFFFFFFFF; XorOut:$FFFFFFFFFFFFFFFF; Check:$AE8B14860A799888),
    (Width:64; Reflected:True; Poly:$AD93D23594C935A9; Initial:$FFFFFFFFFFFFFFFF; XorOut:0; Check:$CAA717168609F281),
    (Width:64; Reflected:True; Poly:$42F0E1EBA9EA3693; Initial:$FFFFFFFFFFFFFFFF; XorOut:$FFFFFFFFFFFFFFFF; Check:$995DC9BBDF1939FA),
    (Width:64; Reflected:False; Poly:$42F0E1EBA9EA3693; Initial:$FFFFFFFFFFFFFFFF; XorOut:$FFFFFFFFFFFFFFFF; Check:$62EC59E3F1A4F00A),
    (Width:64; Reflected:True; Poly:$000000000000001B; Initial:$FFFFFFFFFFFFFFFF; XorOut:$FFFFFFFFFFFFFFFF; Check:$B90956C775A41001),
    (Width:32; Reflected:True; Poly:$1EDC6F41; Initial:$FFFFFFFF; XorOut:$FFFFFFFF; Check:$E3069283),
    (Width:16; Reflected:True; Poly:$8005; Initial:0; XorOut:0; Check:$BB3D),
    (Width:8; Reflected:False; Poly:$07; Initial:0; XorOut:0; Check:$F4));
  HexDigits = CozyText_CrcLayers_0123456789ABCDEF_97caa0fe;
  CodePrefix: AnsiString = CozyText_CrcLayers_GAME_CODE_V1_4d69055a;
  PagePrefix: AnsiString = CozyText_CrcLayers_CRC_PAGES_V1_219bc09d;
  PageSHA512Prefix: AnsiString = CozyText_CrcLayers_COZY_CODE_PAGES_SHA512_V1_cb1f7ae4;
  PageSHA512Domain: AnsiString = CozyText_CrcLayers_COZY_CODE_PAGE_SHA512_V1_15a16187;

var
  Tables: array[TCrcKind] of TCrcTable;
  Crc32CSlices: array[0..7, 0..255] of Cardinal;
  SlicingReady: Boolean;

function Mask(Width: Integer): UInt64;
begin
  if Width = 64 then Result := High(UInt64)
  else Result := (UInt64(1) shl Width) - 1;
end;

function Reflect(Value: UInt64; Width: Integer): UInt64;
var I: Integer;
begin
  Result := 0;
  for I := 1 to Width do
  begin
    Result := (Result shl 1) or (Value and 1);
    Value := Value shr 1;
  end;
end;

procedure InitializeTables;
var Kind: TCrcKind; I, Bit, Slice: Integer; V, P, Top, Limit: UInt64;
begin
  for Kind := Low(TCrcKind) to High(TCrcKind) do
  begin
    P := Specs[Kind].Poly;
    Limit := Mask(Specs[Kind].Width);
    Top := UInt64(1) shl (Specs[Kind].Width - 1);
    if Specs[Kind].Reflected then P := Reflect(P, Specs[Kind].Width);
    for I := 0 to 255 do
    begin
      V := UInt64(I);
      if not Specs[Kind].Reflected then V := V shl (Specs[Kind].Width - 8);
      for Bit := 1 to 8 do
        if Specs[Kind].Reflected then
        begin
          if (V and 1) <> 0 then V := (V shr 1) xor P else V := V shr 1;
        end
        else
        begin
          if (V and Top) <> 0 then V := (V shl 1) xor P else V := V shl 1;
        end;
      Tables[Kind][I] := V and Limit;
    end;
  end;
  for I := 0 to 255 do
  begin
    V := Tables[ckCrc32C][I]; Crc32CSlices[0, I] := Cardinal(V);
    for Slice := 1 to 7 do
    begin
      V := (V shr 8) xor Tables[ckCrc32C][Byte(V)];
      Crc32CSlices[Slice, I] := Cardinal(V);
    end;
  end;
{$IFDEF COZY_CRC32C_REFERENCE_ONLY}
  SlicingReady := False;
{$ELSE}
  SlicingReady := True;
{$ENDIF}
end;

function Crc32CSlicingAvailable: Boolean;
var I, Slice: Integer; Expected: Cardinal;
begin
  Result := False;
  if not SlicingReady then Exit;
  { Derived acceleration state must match the measured canonical base table.
    A damaged optional table selects the reference backend; it cannot change
    the protocol result or turn a CRC into cryptographic authentication. }
  for I := 0 to 255 do
  begin
    Expected := Cardinal(Tables[ckCrc32C][I]);
    if Crc32CSlices[0, I] <> Expected then Exit;
    for Slice := 1 to 7 do
    begin
      Expected := (Expected shr 8) xor Cardinal(Tables[ckCrc32C][Byte(Expected)]);
      if Crc32CSlices[Slice, I] <> Expected then Exit;
    end;
  end;
  Result := True;
end;

procedure CrcInit(out State: TCrcState; Kind: TCrcKind; Mode: TCrc32CMode);
begin
  if (Ord(Kind) < Ord(Low(TCrcKind))) or (Ord(Kind) > Ord(High(TCrcKind))) then
    raise EArgumentException.Create(CozyText_CrcLayers_CRC_variant_is_invalid_5c131aed);
  if (Ord(Mode) < Ord(Low(TCrc32CMode))) or
    (Ord(Mode) > Ord(High(TCrc32CMode))) then
    raise EArgumentException.Create(CozyText_CrcLayers_CRC_backend_is_invalid_fc5a7256);
  State.Kind := Kind; State.Mode := Mode;
  if (Kind = ckCrc32C) and (Mode <> cmReference) and
    not Crc32CSlicingAvailable then State.Mode := cmReference;
  State.Value := Specs[Kind].Initial;
  State.Bytes := 0;
  State.Ready := True;
end;

procedure CrcUpdate(var State: TCrcState; Buffer: Pointer; Count: NativeUInt);
var P: PByte; Remaining: NativeUInt; Shift: Integer; Limit: UInt64;
  V: Cardinal; Chunk: array[0..7] of Byte;
begin
  if not State.Ready or (Ord(State.Kind) > Ord(High(TCrcKind))) then
    raise EArgumentException.Create(CozyText_CrcLayers_CRC_state_is_not_initialized_09b3173d);
  if ((Count <> 0) and (Buffer = nil)) or (UInt64(Count) > High(UInt64) - State.Bytes) then
    raise EArgumentException.Create(CozyText_CrcLayers_CRC_buffer_is_invalid_cb39b136);
  if Count = 0 then Exit;
  P := PByte(Buffer);
  Remaining := Count;
  Limit := Mask(Specs[State.Kind].Width);
  if (State.Kind = ckCrc32C) and (State.Mode <> cmReference) and SlicingReady then
    while Remaining >= 8 do
    begin
      { Move is safe for arbitrary byte alignment. Assemble explicitly so the
        result does not depend on the host byte order. Remaining guards every
        read; no padding or bytes beyond the input are accessed. }
      Move(P^, Chunk[0], 8);
      V := Cardinal(State.Value) xor Cardinal(Chunk[0]) xor
        (Cardinal(Chunk[1]) shl 8) xor (Cardinal(Chunk[2]) shl 16) xor
        (Cardinal(Chunk[3]) shl 24);
      State.Value := Crc32CSlices[7, Byte(V)] xor
        Crc32CSlices[6, Byte(V shr 8)] xor Crc32CSlices[5, Byte(V shr 16)] xor
        Crc32CSlices[4, Byte(V shr 24)] xor Crc32CSlices[3, Chunk[4]] xor
        Crc32CSlices[2, Chunk[5]] xor Crc32CSlices[1, Chunk[6]] xor
        Crc32CSlices[0, Chunk[7]];
      Inc(P, 8); Dec(Remaining, 8);
    end;
  if Specs[State.Kind].Reflected then
    while Remaining <> 0 do
    begin
      State.Value := (State.Value shr 8) xor Tables[State.Kind][Byte(State.Value xor P^)];
      Inc(P); Dec(Remaining);
    end
  else
  begin
    Shift := Specs[State.Kind].Width - 8;
    while Remaining <> 0 do
    begin
      State.Value := ((State.Value shl 8) xor Tables[State.Kind][Byte((State.Value shr Shift) xor P^)]) and Limit;
      Inc(P); Dec(Remaining);
    end;
  end;
  Inc(State.Bytes, UInt64(Count));
end;

function CrcFinal(const State: TCrcState): UInt64;
begin
  if not State.Ready or (Ord(State.Kind) > Ord(High(TCrcKind))) then
    raise EArgumentException.Create(CozyText_CrcLayers_CRC_state_is_not_initialized_09b3173d);
  Result := (State.Value xor Specs[State.Kind].XorOut) and Mask(Specs[State.Kind].Width);
end;

function CrcFinalHex(const State: TCrcState): string;
var V: UInt64; I: Integer;
begin
  V := CrcFinal(State);
  SetLength(Result, Specs[State.Kind].Width div 4);
  for I := Length(Result) downto 1 do
  begin
    Result[I] := HexDigits[Integer(V and 15) + 1];
    V := V shr 4;
  end;
end;

function CrcBufferHex(Kind: TCrcKind; Buffer: Pointer; Count: NativeUInt): string;
var State: TCrcState;
begin
  CrcInit(State, Kind);
  CrcUpdate(State, Buffer, Count);
  Result := CrcFinalHex(State);
end;

function CrcBytes(Kind: TCrcKind; const Bytes: TBytes): string;
begin
  if Length(Bytes) = 0 then Result := CrcBufferHex(Kind, nil, 0)
  else Result := CrcBufferHex(Kind, @Bytes[0], NativeUInt(Length(Bytes)));
end;

function CrcKindName(Kind: TCrcKind): string;
begin
  case Kind of
    ckEcma182: Result := CozyText_CrcLayers_CRC_64_ECMA_182_3044e94a;
    ckNvme: Result := CozyText_CrcLayers_CRC_64_NVME_810ca747;
    ckJones: Result := CozyText_CrcLayers_CRC_64_JONES_16f80275;
    ckXz: Result := CozyText_CrcLayers_CRC_64_XZ_c4d309d4;
    ckWe: Result := CozyText_CrcLayers_CRC_64_WE_981f99f5;
    ckIso: Result := CozyText_CrcLayers_CRC_64_GO_ISO_ffbf0f6e;
    ckCrc32C: Result := CozyText_CrcLayers_CRC_32_ISCSI_f7b0ee14;
    ckCrc16Arc: Result := CozyText_CrcLayers_CRC_16_ARC_aee265be;
    ckCrc8Smbus: Result := CozyText_CrcLayers_CRC_8_SMBUS_1372db88;
  else
    raise EArgumentException.Create(CozyText_CrcLayers_CRC_variant_is_invalid_5c131aed);
  end;
end;

procedure PutLE(var Bytes: TBytes; var At: Integer; Value: UInt64; Count: Integer);
var I: Integer;
begin
  for I := 1 to Count do
  begin
    Bytes[At] := Byte(Value and $FF);
    Inc(At); Value := Value shr 8;
  end;
end;

function CrcTableBytes(Kind: TCrcKind): TBytes;
var I, At: Integer;
begin
  if Ord(Kind) > Ord(High(TCrcKind)) then
    raise EArgumentException.Create(CozyText_CrcLayers_CRC_variant_is_invalid_5c131aed);
  SetLength(Result, 256 * 8);
  At := 0;
  for I := 0 to 255 do PutLE(Result, At, Tables[Kind][I], 8);
end;

function CrcAllTableBytes: TBytes;
var Kind: TCrcKind; I, At: Integer;
begin
  SetLength(Result, (Ord(High(TCrcKind)) + 1) * 256 * 8);
  At := 0;
  for Kind := Low(TCrcKind) to High(TCrcKind) do
    for I := 0 to 255 do PutLE(Result, At, Tables[Kind][I], 8);
end;

function CrcParameterBytes: TBytes;
var Kind: TCrcKind; At: Integer;
begin
  { No compiler record padding or process pointers enter a canonical digest. }
  SetLength(Result, (Ord(High(TCrcKind)) + 1) * 34);
  At := 0;
  for Kind := Low(TCrcKind) to High(TCrcKind) do
  begin
    PutLE(Result, At, Specs[Kind].Width, 1);
    PutLE(Result, At, Ord(Specs[Kind].Reflected), 1);
    PutLE(Result, At, Specs[Kind].Poly, 8);
    PutLE(Result, At, Specs[Kind].Initial, 8);
    PutLE(Result, At, Specs[Kind].XorOut, 8);
    PutLE(Result, At, Specs[Kind].Check, 8);
  end;
end;

function BuildCodePageManifest(const CodeStream: TBytes; Cryptographic: Boolean;
  Checkpoint: TCrcCheckpoint; Context: Pointer): TBytes;
var At, Section, Count, PageCount, PageSize, OutAt, PageRva: Cardinal;
    RVA, Span, Remaining, DataAt, EndAt: Cardinal;
    State: TCrcState; Prefix: AnsiString; EntrySize: Integer;
    Hasher: TSHA512Hasher; Hash: TBytes; Frame: array[0..7] of Byte;
  function Read32: Cardinal;
  begin
    if UInt64(At) + 4 > UInt64(Length(CodeStream)) then
      raise EArgumentException.Create(CozyText_CrcLayers_CRC_code_framing_is_invalid_67ad2a4a);
    Result := Cardinal(CodeStream[At]) or (Cardinal(CodeStream[At+1]) shl 8) or
      (Cardinal(CodeStream[At+2]) shl 16) or (Cardinal(CodeStream[At+3]) shl 24);
    Inc(At, 4);
  end;
  procedure Append32(Value: Cardinal);
  var P: Integer;
  begin
    P := Integer(OutAt); PutLE(Result, P, Value, 4); OutAt := Cardinal(P);
  end;
begin
  Result := nil;
  if (Length(CodeStream) < Length(CodePrefix) + 4) or
    not CompareMem(@CodeStream[0], @CodePrefix[1], Length(CodePrefix)) then
    raise EArgumentException.Create(CozyText_CrcLayers_CRC_code_prefix_is_invalid_92b90716);
  if ((not Cryptographic) and (Length(CodeStream) > 64 * 1024 * 1024 + 4096)) or
    (Length(CodeStream) > 256 * 1024 * 1024 + 4096) then
    raise EArgumentException.Create(CozyText_CrcLayers_CRC_code_stream_is_too_large_a1ce6107);
  At := Length(CodePrefix);
  Count := Read32;
  if (Count = 0) or (Count > 96) then
    raise EArgumentException.Create(CozyText_CrcLayers_CRC_code_section_count_is_invalid_96d5a6cc);
  { At most two partial pages per section. The SHA manifest adds no raw
    code copy; it holds only bounded 72-byte page records. }
  if Cryptographic then begin Prefix := PageSHA512Prefix; EntrySize := 72; end
  else begin Prefix := PagePrefix; EntrySize := 12; end;
  SetLength(Result, Length(Prefix) + 8 + ((Length(CodeStream) div 4096) + Integer(Count) * 2 + 1) * EntrySize);
  Move(Prefix[1], Result[0], Length(Prefix));
  OutAt := Length(Prefix); Append32(4096); Append32(0);
  PageCount := 0; EndAt := 0;
  for Section := 1 to Count do
  begin
    RVA := Read32; Span := Read32;
    if (Span = 0) or (UInt64(At) + Span > UInt64(Length(CodeStream))) or
      (UInt64(RVA) + Span > High(Cardinal)) or (RVA < EndAt) then
      raise EArgumentException.Create(CozyText_CrcLayers_CRC_code_section_is_invalid_49ceb458);
    EndAt := RVA + Span;
    DataAt := At; Remaining := Span; PageRva := RVA;
    while Remaining <> 0 do
    begin
      if Assigned(Checkpoint) then Checkpoint(Context);
      PageSize := 4096 - (PageRva and 4095);
      if PageSize > Remaining then PageSize := Remaining;
      Append32(PageRva); Append32(PageSize);
      if Cryptographic then
      begin
        Move(Result[OutAt - 8], Frame[0], 8);
        Hasher := TSHA512Hasher.Create;
        try
          Hasher.Update(PageSHA512Domain[1], Length(PageSHA512Domain));
          Hasher.Update(Frame[0], SizeOf(Frame));
          Hasher.Update(CodeStream[DataAt], PageSize);
          Hash := Hasher.FinishBytes;
          Move(Hash[0], Result[OutAt], 64); Inc(OutAt, 64);
        finally
          if Length(Hash) <> 0 then FillChar(Hash[0], Length(Hash), 0);
          Hash := nil; Hasher.Free; FillChar(Frame, SizeOf(Frame), 0);
        end;
      end
      else
      begin
        CrcInit(State, ckCrc32C); CrcUpdate(State, @CodeStream[DataAt], PageSize);
        Append32(Cardinal(CrcFinal(State)));
      end;
      Inc(PageCount); Inc(DataAt, PageSize); Inc(PageRva, PageSize); Dec(Remaining, PageSize);
    end;
    Inc(At, Span);
  end;
  if At <> Cardinal(Length(CodeStream)) then
    raise EArgumentException.Create(CozyText_CrcLayers_CRC_code_trailing_bytes_are_invalid_7bcc9b98);
  SetLength(Result, OutAt);
  if Assigned(Checkpoint) then Checkpoint(Context);
  if Cryptographic then Prefix := PageSHA512Prefix else Prefix := PagePrefix;
  OutAt := Length(Prefix) + 4; Append32(PageCount);
end;

function CrcCodePageManifest(const CodeStream: TBytes;
  Checkpoint: TCrcCheckpoint; Context: Pointer): TBytes;
begin Result := BuildCodePageManifest(CodeStream, False, Checkpoint, Context); end;

function CodePageSHA512Manifest(const CodeStream: TBytes;
  Checkpoint: TCrcCheckpoint; Context: Pointer): TBytes;
begin Result := BuildCodePageManifest(CodeStream, True, Checkpoint, Context); end;

function CrcLayoutState(CodeBytes, HeaderBytes, ExportBytes: UInt64): TBytes;
var At: Integer;
begin
  SetLength(Result, 25); At := 0;
  PutLE(Result, At, 1, 1);
  PutLE(Result, At, CodeBytes, 8);
  PutLE(Result, At, HeaderBytes, 8);
  PutLE(Result, At, ExportBytes, 8);
end;

function CrcSelfTest: Boolean;
const Input: AnsiString = CozyText_CrcLayers_123456789_ae32cddf;
var Kind: TCrcKind; State: TCrcState; Mode: TCrc32CMode;
begin
  Result := False;
  for Kind := Low(TCrcKind) to High(TCrcKind) do
  begin
    CrcInit(State, Kind);
    CrcUpdate(State, @Input[1], 4);
    CrcUpdate(State, @Input[5], 5);
    if CrcFinal(State) <> Specs[Kind].Check then Exit;
  end;
  for Mode := Low(TCrc32CMode) to High(TCrc32CMode) do
  begin
    CrcInit(State, ckCrc32C, Mode); CrcUpdate(State, @Input[1], Length(Input));
    if CrcFinal(State) <> Specs[ckCrc32C].Check then Exit;
  end;
  Result := True;
end;

initialization
  InitializeTables;
end.
