unit Cozy.Hashes.XXH3;

{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$IFDEF FPC}{$MODE DELPHI}{$ENDIF}
{$B-}{$Q-}{$R-}

{ Portable scalar XXH3-128, seed zero, canonical high64 then low64 hex.
  Bounded-memory streaming; FinishHex is non-destructive.
  This checksum is not a MAC and never authorizes a session by itself. }
{
 * xxHash - Extremely Fast Hash algorithm
 * Header File
 * Copyright (C) 2012-2020 Yann Collet
 *
 * BSD 2-Clause License (https://www.opensource.org/licenses/bsd-license.php)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following disclaimer
 *      in the documentation and/or other materials provided with the
 *      distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * You can contact the author at:
 *   - xxHash homepage: https://www.xxhash.com
 *   - xxHash source repository: https://github.com/Cyan4973/xxHash
 *
 * Modified for hash-wasm by Dani Biró
 }
interface
uses
{ Cozy central text imports. }
  Cozy.Strings.Crypto,

{$IFDEF FPC} SysUtils; {$ELSE} System.SysUtils; {$ENDIF}
type
  TXXH3Acc = array[0..7] of UInt64;
  TXXHash3_128 = class
  private
    FAcc: TXXH3Acc;
    FBuffer: array[0..255] of Byte;
    FBuffered, FStripes: Integer;
    FLength: UInt64;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Update(const Buffer; Count: NativeUInt);
    function FinishHex: string;
  end;
function XXHash3_128Bytes(const Data: TBytes): string;
implementation
const
  P1: UInt64 = $9E3779B185EBCA87;
  P2: UInt64 = $C2B2AE3D27D4EB4F;
  P3: UInt64 = $165667B19E3779F9;
  P4: UInt64 = $85EBCA77C2B2AE63;
  P5: UInt64 = $27D4EB2F165667C5;
  Secret: array[0..191] of Byte = ($b8, $fe, $6c, $39, $23, $a4, $4b, $be, $7c, $01, $81, $2c,
  $f7, $21, $ad, $1c, $de, $d4, $6d, $e9, $83, $90, $97, $db,
  $72, $40, $a4, $a4, $b7, $b3, $67, $1f, $cb, $79, $e6, $4e,
  $cc, $c0, $e5, $78, $82, $5a, $d0, $7d, $cc, $ff, $72, $21,
  $b8, $08, $46, $74, $f7, $43, $24, $8e, $e0, $35, $90, $e6,
  $81, $3a, $26, $4c, $3c, $28, $52, $bb, $91, $c3, $00, $cb,
  $88, $d0, $65, $8b, $1b, $53, $2e, $a3, $71, $64, $48, $97,
  $a2, $0d, $f9, $4e, $38, $19, $ef, $46, $a9, $de, $ac, $d8,
  $a8, $fa, $76, $3f, $e3, $9c, $34, $3f, $f9, $dc, $bb, $c7,
  $c7, $0b, $4f, $1d, $8a, $51, $e0, $4b, $cd, $b4, $59, $31,
  $c8, $9f, $7e, $c9, $d9, $78, $73, $64, $ea, $c5, $ac, $83,
  $34, $d3, $eb, $c3, $c5, $81, $a0, $ff, $fa, $13, $63, $eb,
  $17, $0d, $dd, $51, $b7, $f0, $da, $49, $d3, $16, $55, $26,
  $29, $d4, $68, $9e, $2b, $16, $be, $58, $7d, $47, $a1, $fc,
  $8f, $f8, $b8, $d1, $7a, $d0, $31, $ce, $45, $cb, $3a, $8f,
  $95, $16, $04, $28, $af, $d7, $fb, $ca, $bb, $4b, $40, $7e);
type
  TH128 = record Lo, Hi: UInt64; end;
function Ptr(P: PByte; Offset: NativeUInt): PByte; 
begin Result := PByte(NativeUInt(P) + Offset); end;
function LE32(P: PByte): UInt32; 
var I: Integer;
begin
  Result := 0;
  for I := 0 to 3 do begin Result := Result or (UInt32(P^) shl (8 * I)); Inc(P); end;
end;
function LE64(P: PByte): UInt64; 
var I: Integer;
begin
  Result := 0;
  for I := 0 to 7 do begin Result := Result or (UInt64(P^) shl (8 * I)); Inc(P); end;
end;
function Swap64(V: UInt64): UInt64; 
var I: Integer;
begin Result := 0; for I := 0 to 7 do begin Result := (Result shl 8) or (V and $FF); V := V shr 8; end; end;
function Swap32(V: UInt32): UInt32; 
begin Result := (V shl 24) or ((V shl 8) and $00FF0000) or ((V shr 8) and $0000FF00) or (V shr 24); end;
function Avalanche64(V: UInt64): UInt64; 
begin V := (V xor (V shr 33)) * P2; V := (V xor (V shr 29)) * P3; Result := V xor (V shr 32); end;
function Avalanche3(V: UInt64): UInt64; 
begin V := (V xor (V shr 37)) * UInt64($165667919E3779F9); Result := V xor (V shr 32); end;
function Mul128(A, B: UInt64): TH128; 
var LL, HL, LH, HH, Cross: UInt64;
begin
  LL := (A and $FFFFFFFF) * (B and $FFFFFFFF);
  HL := (A shr 32) * (B and $FFFFFFFF);
  LH := (A and $FFFFFFFF) * (B shr 32);
  HH := (A shr 32) * (B shr 32);
  Cross := (LL shr 32) + (HL and $FFFFFFFF) + LH;
  Result.Hi := (HL shr 32) + (Cross shr 32) + HH;
  Result.Lo := (Cross shl 32) or (LL and $FFFFFFFF);
end;
function Fold(A, B: UInt64): UInt64; 
var R: TH128;
begin R := Mul128(A, B); Result := R.Lo xor R.Hi; end;
function Mix16(Input, Key: PByte): UInt64; 
begin Result := Fold(LE64(Input) xor LE64(Key), LE64(Ptr(Input, 8)) xor LE64(Ptr(Key, 8))); end;
procedure Mix32(var A: TH128; Input1, Input2, Key: PByte); 
begin
  A.Lo := (A.Lo + Mix16(Input1, Key)) xor (LE64(Input2) + LE64(Ptr(Input2, 8)));
  A.Hi := (A.Hi + Mix16(Input2, Ptr(Key, 16))) xor (LE64(Input1) + LE64(Ptr(Input1, 8)));
end;
function SmallHash(Input: PByte; Len: Integer): TH128;
var A, M: TH128; L, H, K: UInt64; C, D: UInt32; I: Integer;
begin
  if Len = 0 then begin
    Result.Lo := Avalanche64(LE64(@Secret[64]) xor LE64(@Secret[72]));
    Result.Hi := Avalanche64(LE64(@Secret[80]) xor LE64(@Secret[88])); Exit;
  end;
  if Len <= 3 then begin
    C := (UInt32(Input^) shl 16) or (UInt32(Ptr(Input, Len shr 1)^) shl 24) or UInt32(Ptr(Input, Len - 1)^) or (UInt32(Len) shl 8);
    D := Swap32(C); D := (D shl 13) or (D shr 19);
    Result.Lo := Avalanche64(UInt64(C) xor UInt64(LE32(@Secret[0]) xor LE32(@Secret[4])));
    Result.Hi := Avalanche64(UInt64(D) xor UInt64(LE32(@Secret[8]) xor LE32(@Secret[12]))); Exit;
  end;
  if Len <= 8 then begin
    K := (UInt64(LE32(Input)) + (UInt64(LE32(Ptr(Input, Len - 4))) shl 32)) xor (LE64(@Secret[16]) xor LE64(@Secret[24]));
    Result := Mul128(K, P1 + UInt64(Len shl 2));
    Result.Hi := Result.Hi + (Result.Lo shl 1);
    Result.Lo := Result.Lo xor (Result.Hi shr 3);
    Result.Lo := (Result.Lo xor (Result.Lo shr 35)) * UInt64($9FB21C651E98DF25);
    Result.Lo := Result.Lo xor (Result.Lo shr 28);
    Result.Hi := Avalanche3(Result.Hi); Exit;
  end;
  if Len <= 16 then begin
    L := LE64(Input); H := LE64(Ptr(Input, Len - 8));
    M := Mul128(L xor H xor (LE64(@Secret[32]) xor LE64(@Secret[40])), P1);
    M.Lo := M.Lo + (UInt64(Len - 1) shl 54);
    H := H xor (LE64(@Secret[48]) xor LE64(@Secret[56]));
    M.Hi := M.Hi + H + ((H and $FFFFFFFF) * UInt64($85EBCA76));
    M.Lo := M.Lo xor Swap64(M.Hi);
    Result := Mul128(M.Lo, P2);
    Result.Hi := Result.Hi + M.Hi * P2;
    Result.Lo := Avalanche3(Result.Lo); Result.Hi := Avalanche3(Result.Hi); Exit;
  end;
  A.Lo := UInt64(Len) * P1; A.Hi := 0;
  if Len <= 128 then begin
    if Len > 32 then begin
      if Len > 64 then begin
        if Len > 96 then Mix32(A, Ptr(Input, 48), Ptr(Input, Len - 64), @Secret[96]);
        Mix32(A, Ptr(Input, 32), Ptr(Input, Len - 48), @Secret[64]);
      end;
      Mix32(A, Ptr(Input, 16), Ptr(Input, Len - 32), @Secret[32]);
    end;
    Mix32(A, Input, Ptr(Input, Len - 16), @Secret[0]);
  end else begin
    for I := 0 to 3 do Mix32(A, Ptr(Input, 32 * I), Ptr(Input, 32 * I + 16), @Secret[32 * I]);
    A.Lo := Avalanche3(A.Lo); A.Hi := Avalanche3(A.Hi);
    for I := 4 to (Len div 32) - 1 do Mix32(A, Ptr(Input, 32 * I), Ptr(Input, 32 * I + 16), @Secret[3 + 32 * (I - 4)]);
    Mix32(A, Ptr(Input, Len - 16), Ptr(Input, Len - 32), @Secret[103]);
  end;
  Result.Lo := Avalanche3(A.Lo + A.Hi);
  Result.Hi := UInt64(0) - Avalanche3(A.Lo * P1 + A.Hi * P4 + UInt64(Len) * P2);
end;
procedure Accumulate(var Acc: TXXH3Acc; Input, Key: PByte);
var I: Integer; Data, K: UInt64;
begin
  for I := 0 to 7 do begin
    Data := LE64(Ptr(Input, 8 * I)); K := Data xor LE64(Ptr(Key, 8 * I));
    Acc[I xor 1] := Acc[I xor 1] + Data;
    Acc[I] := Acc[I] + (K and $FFFFFFFF) * (K shr 32);
  end;
end;
procedure Consume(var Acc: TXXH3Acc; var Stripes: Integer; Input: PByte; Count: Integer);
var I, J: Integer; V: UInt64;
begin
  for I := 1 to Count do begin
    Accumulate(Acc, Input, @Secret[Stripes * 8]); Inc(Input, 64); Inc(Stripes);
    if Stripes = 16 then begin
      for J := 0 to 7 do begin
        V := Acc[J]; V := (V xor (V shr 47)) xor LE64(@Secret[128 + J * 8]);
        Acc[J] := V * UInt64($9E3779B1);
      end;
      Stripes := 0;
    end;
  end;
end;
function Merge(const Acc: TXXH3Acc; Key: PByte; Start: UInt64): UInt64;
var I: Integer;
begin
  Result := Start;
  for I := 0 to 3 do Result := Result + Fold(Acc[2 * I] xor LE64(Ptr(Key, 16 * I)), Acc[2 * I + 1] xor LE64(Ptr(Key, 16 * I + 8)));
  Result := Avalanche3(Result);
end;
constructor TXXHash3_128.Create;
begin
  inherited Create;
  FAcc[0] := $C2B2AE3D; FAcc[1] := P1; FAcc[2] := P2; FAcc[3] := P3;
  FAcc[4] := P4; FAcc[5] := $85EBCA77; FAcc[6] := P5; FAcc[7] := $9E3779B1;
end;
destructor TXXHash3_128.Destroy;
begin
  FillChar(FAcc, SizeOf(FAcc), 0); FillChar(FBuffer, SizeOf(FBuffer), 0);
  FLength := 0; FBuffered := 0; FStripes := 0;
  inherited;
end;
procedure TXXHash3_128.Update(const Buffer; Count: NativeUInt);
var Input: PByte; Take: NativeUInt;
begin
  if Count = 0 then Exit;
  if UInt64(Count) > High(UInt64) - FLength then raise ERangeError.Create(CozyText_Hashes_XXH3_XXH3_input_length_overflow_f56c4374);
  Inc(FLength, UInt64(Count)); Input := @Buffer;
  if Count <= NativeUInt(256 - FBuffered) then begin
    Move(Input^, FBuffer[FBuffered], Count); Inc(FBuffered, Integer(Count)); Exit;
  end;
  if FBuffered <> 0 then begin
    Take := 256 - FBuffered; Move(Input^, FBuffer[FBuffered], Take);
    Inc(Input, Take); Dec(Count, Take);
    Consume(FAcc, FStripes, @FBuffer[0], 4); FBuffered := 0;
  end;
  while Count > 256 do begin
    Consume(FAcc, FStripes, Input, 4);
    Move(Ptr(Input, 192)^, FBuffer[192], 64);
    Inc(Input, 256); Dec(Count, 256);
  end;
  Move(Input^, FBuffer[0], Count); FBuffered := Integer(Count);
end;
function TXXHash3_128.FinishHex: string;
var Acc: TXXH3Acc; R: TH128; N, CatchUp, I: Integer; Last: array[0..63] of Byte;
  V: UInt64;
const Digits = CozyText_Hashes_XXH3_0123456789abcdef_1affd556;
begin
  if FLength <= 240 then R := SmallHash(@FBuffer[0], Integer(FLength))
  else begin
    Acc := FAcc; N := FStripes;
    if FBuffered >= 64 then begin
      Consume(Acc, N, @FBuffer[0], (FBuffered - 1) div 64);
      Accumulate(Acc, @FBuffer[FBuffered - 64], @Secret[121]);
    end else begin
      CatchUp := 64 - FBuffered;
      Move(FBuffer[256 - CatchUp], Last[0], CatchUp);
      Move(FBuffer[0], Last[CatchUp], FBuffered);
      Accumulate(Acc, @Last[0], @Secret[121]);
    end;
    R.Lo := Merge(Acc, @Secret[11], FLength * P1);
    R.Hi := Merge(Acc, @Secret[117], not (FLength * P2));
  end;
  SetLength(Result, 32);
  for I := 0 to 31 do begin
    if I < 16 then V := R.Hi else V := R.Lo;
    Result[I + 1] := Digits[Integer((V shr ((15 - (I mod 16)) * 4)) and 15) + 1];
  end;
  FillChar(Acc, SizeOf(Acc), 0); FillChar(Last, SizeOf(Last), 0); FillChar(R, SizeOf(R), 0);
end;
function XXHash3_128Bytes(const Data: TBytes): string;
var H: TXXHash3_128;
begin H := TXXHash3_128.Create; try if Length(Data) <> 0 then H.Update(Data[0], Length(Data)); Result := H.FinishHex; finally H.Free; end; end;
end.
