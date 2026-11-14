unit Cozy.Hashes.SHA512;
{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$IFDEF FPC}{$MODE DELPHI}{$ENDIF}
{$B-}{$Q-}{$R-}
{ FIPS 180-4 SHA-512. Portable bounded-memory streaming; finalization does
  not change the object. Supports up to 2^64-1 input bytes, with a correct
  128-bit bit-length field. No platform cryptography DLL dependency. }
interface
uses
{ Cozy central text imports. }
  Cozy.Strings.Crypto,

{$IFDEF FPC} SysUtils; {$ELSE} System.SysUtils; {$ENDIF}
type
  TSHA512State = array[0..7] of UInt64;
  TSHA512Hasher = class
  private
    FState: TSHA512State;
    FBuffer: array[0..127] of Byte;
    FBuffered: Integer;
    FLength: UInt64;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Update(const Buffer; Count: NativeUInt);
    function FinishBytes: TBytes;
    function FinishHex: string;
  end;
function SHA512Bytes(const Data: TBytes): string;
implementation
const
  K: array[0..79] of UInt64 = ($428a2f98d728ae22, $7137449123ef65cd, $b5c0fbcfec4d3b2f,
  $e9b5dba58189dbbc, $3956c25bf348b538, $59f111f1b605d019,
  $923f82a4af194f9b, $ab1c5ed5da6d8118, $d807aa98a3030242,
  $12835b0145706fbe, $243185be4ee4b28c, $550c7dc3d5ffb4e2,
  $72be5d74f27b896f, $80deb1fe3b1696b1, $9bdc06a725c71235,
  $c19bf174cf692694, $e49b69c19ef14ad2, $efbe4786384f25e3,
  $0fc19dc68b8cd5b5, $240ca1cc77ac9c65, $2de92c6f592b0275,
  $4a7484aa6ea6e483, $5cb0a9dcbd41fbd4, $76f988da831153b5,
  $983e5152ee66dfab, $a831c66d2db43210, $b00327c898fb213f,
  $bf597fc7beef0ee4, $c6e00bf33da88fc2, $d5a79147930aa725,
  $06ca6351e003826f, $142929670a0e6e70, $27b70a8546d22ffc,
  $2e1b21385c26c926, $4d2c6dfc5ac42aed, $53380d139d95b3df,
  $650a73548baf63de, $766a0abb3c77b2a8, $81c2c92e47edaee6,
  $92722c851482353b, $a2bfe8a14cf10364, $a81a664bbc423001,
  $c24b8b70d0f89791, $c76c51a30654be30, $d192e819d6ef5218,
  $d69906245565a910, $f40e35855771202a, $106aa07032bbd1b8,
  $19a4c116b8d2d0c8, $1e376c085141ab53, $2748774cdf8eeb99,
  $34b0bcb5e19b48a8, $391c0cb3c5c95a63, $4ed8aa4ae3418acb,
  $5b9cca4f7763e373, $682e6ff3d6b2b8a3, $748f82ee5defb2fc,
  $78a5636f43172f60, $84c87814a1f0ab72, $8cc702081a6439ec,
  $90befffa23631e28, $a4506cebde82bde9, $bef9a3f7b2c67915,
  $c67178f2e372532b, $ca273eceea26619c, $d186b8c721c0c207,
  $eada7dd6cde0eb1e, $f57d4f7fee6ed178, $06f067aa72176fba,
  $0a637dc5a2c898a6, $113f9804bef90dae, $1b710b35131c471b,
  $28db77f523047d84, $32caab7b40c72493, $3c9ebe0a15c9bebc,
  $431d67c49c100d4c, $4cc5d4becb3e42b6, $597f299cfc657e2a,
  $5fcb6fab3ad6faec, $6c44198c4a475817);
  IV: TSHA512State = ($6a09e667f3bcc908, $bb67ae8584caa73b, $3c6ef372fe94f82b,
    $a54ff53a5f1d36f1, $510e527fade682d1, $9b05688c2b3e6c1f,
    $1f83d9abfb41bd6b, $5be0cd19137e2179);
function ROR64(V: UInt64; N: Integer): UInt64; inline;
begin Result := (V shr N) or (V shl (64 - N)); end;
procedure PutBE(P: PByte; V: UInt64);
var I: Integer;
begin for I := 7 downto 0 do begin P^ := Byte(V shr (I * 8)); Inc(P); end; end;
procedure Compress(var S: TSHA512State; P: PByte);
var W: array[0..79] of UInt64; A, B, C, D, E, F, G, H, T1, T2, S0, S1: UInt64; I, J: Integer;
begin
  for I := 0 to 15 do begin
    W[I] := 0; for J := 0 to 7 do begin W[I] := (W[I] shl 8) or P^; Inc(P); end;
  end;
  for I := 16 to 79 do begin
    S0 := ROR64(W[I - 15], 1) xor ROR64(W[I - 15], 8) xor (W[I - 15] shr 7);
    S1 := ROR64(W[I - 2], 19) xor ROR64(W[I - 2], 61) xor (W[I - 2] shr 6);
    W[I] := W[I - 16] + S0 + W[I - 7] + S1;
  end;
  A := S[0]; B := S[1]; C := S[2]; D := S[3]; E := S[4]; F := S[5]; G := S[6]; H := S[7];
  for I := 0 to 79 do begin
    S1 := ROR64(E, 14) xor ROR64(E, 18) xor ROR64(E, 41);
    T1 := H + S1 + ((E and F) xor ((not E) and G)) + K[I] + W[I];
    S0 := ROR64(A, 28) xor ROR64(A, 34) xor ROR64(A, 39);
    T2 := S0 + ((A and B) xor (A and C) xor (B and C));
    H := G; G := F; F := E; E := D + T1; D := C; C := B; B := A; A := T1 + T2;
  end;
  S[0] := S[0] + A; S[1] := S[1] + B; S[2] := S[2] + C; S[3] := S[3] + D;
  S[4] := S[4] + E; S[5] := S[5] + F; S[6] := S[6] + G; S[7] := S[7] + H;
  FillChar(W, SizeOf(W), 0);
end;
constructor TSHA512Hasher.Create;
begin inherited Create; FState := IV; end;
destructor TSHA512Hasher.Destroy;
begin FillChar(FState, SizeOf(FState), 0); FillChar(FBuffer, SizeOf(FBuffer), 0); FLength := 0; FBuffered := 0; inherited; end;
procedure TSHA512Hasher.Update(const Buffer; Count: NativeUInt);
var P: PByte; Take: NativeUInt;
begin
  if Count = 0 then Exit;
  if UInt64(Count) > High(UInt64) - FLength then raise ERangeError.Create(CozyText_Hashes_SHA512_SHA512_input_length_overflow_138f0d73);
  Inc(FLength, UInt64(Count)); P := @Buffer;
  if FBuffered <> 0 then begin
    Take := 128 - FBuffered; if Take > Count then Take := Count;
    Move(P^, FBuffer[FBuffered], Take); Inc(FBuffered, Integer(Take)); Inc(P, Take); Dec(Count, Take);
    if FBuffered = 128 then begin Compress(FState, @FBuffer[0]); FBuffered := 0; FillChar(FBuffer, SizeOf(FBuffer), 0); end;
  end;
  while Count >= 128 do begin Compress(FState, P); Inc(P, 128); Dec(Count, 128); end;
  if Count <> 0 then begin Move(P^, FBuffer[0], Count); FBuffered := Integer(Count); end;
end;
function TSHA512Hasher.FinishBytes: TBytes;
var S: TSHA512State; Last: array[0..255] of Byte; EndOffset, I: Integer;
begin
  Result := nil; S := FState; FillChar(Last, SizeOf(Last), 0);
  try
    if FBuffered <> 0 then Move(FBuffer[0], Last[0], FBuffered);
    Last[FBuffered] := $80;
    if FBuffered < 112 then EndOffset := 128 else EndOffset := 256;
    PutBE(@Last[EndOffset - 16], FLength shr 61);
    PutBE(@Last[EndOffset - 8], FLength shl 3);
    Compress(S, @Last[0]); if EndOffset = 256 then Compress(S, @Last[128]);
    SetLength(Result, 64); for I := 0 to 7 do PutBE(@Result[I * 8], S[I]);
  finally FillChar(S, SizeOf(S), 0); FillChar(Last, SizeOf(Last), 0); end;
end;
function TSHA512Hasher.FinishHex: string;
var B: TBytes; I: Integer;
const Digits = CozyText_Hashes_SHA512_0123456789abcdef_bd95c923;
begin
  B := FinishBytes;
  try
    SetLength(Result, 128);
    for I := 0 to 63 do begin Result[2 * I + 1] := Digits[(B[I] shr 4) + 1]; Result[2 * I + 2] := Digits[(B[I] and 15) + 1]; end;
  finally FillChar(B[0], Length(B), 0); B := nil; end;
end;
function SHA512Bytes(const Data: TBytes): string;
var H: TSHA512Hasher;
begin H := TSHA512Hasher.Create; try if Length(Data) <> 0 then H.Update(Data[0], Length(Data)); Result := H.FinishHex; finally H.Free; end; end;
end.
