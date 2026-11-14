unit Cozy.NHW.Export.ImageReader;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows, System.SysUtils, Cozy.NHW.ExportRules, Cozy.NHW.PERules;

const
  MAX_PE_IMAGE = Cardinal(512 * 1024 * 1024);
  HASH_SEED = UInt64($CBF29CE484222325);

type
  TImageInfo = record
    Base: NativeUInt;
    Size: Cardinal;
    ExportRVA: Cardinal;
    ExportSize: Cardinal;
    DelayRVA: Cardinal;
    DelaySize: Cardinal;
  end;

function WithinImage(const Image: TImageInfo; RVA, Bytes: Cardinal): Boolean;
function ReadableLocal(Address, Bytes: NativeUInt): Boolean;
function SafeRead(Address: NativeUInt; var Dest; Bytes: NativeUInt): Boolean;
function ReadU16(Address: NativeUInt; out Value: Word): Boolean;
function ReadU32(Address: NativeUInt; out Value: Cardinal): Boolean;
function ReadU64(Address: NativeUInt; out Value: UInt64): Boolean;
function MapAddress(const Image: TImageInfo; RVA, Bytes: Cardinal;
  out Address: NativeUInt): Boolean;
function ReadImageU32(const Image: TImageInfo; RVA: Cardinal;
  out Value: Cardinal): Boolean;
function ReadImageU16(const Image: TImageInfo; RVA: Cardinal;
  out Value: Word): Boolean;
function ReadAsciiRVA(const Image: TImageInfo; RVA: Cardinal;
  MaxLength: Cardinal; out S: AnsiString): Boolean;
function HashText(Hash: UInt64; const S: AnsiString): UInt64;
function ReadImageInfo(Base: NativeUInt; out Image: TImageInfo): Boolean;
function ExecutableMappedImage(Address: NativeUInt): Boolean;

implementation

uses
  Cozy.NHW.WinPointers, Cozy.NHW.AllocationNative;

function WithinImage(const Image: TImageInfo; RVA, Bytes: Cardinal): Boolean;
begin
  Result := (RVA < Image.Size) and (Bytes <= Image.Size - RVA);
end;

function ReadableLocal(Address, Bytes: NativeUInt): Boolean;
var
  Region: TVirtualRegion;
  Offset: NativeUInt;
begin
  Result := False;
  if (Address < $10000) or (Bytes = 0) or
     (Address > High(NativeUInt) - Bytes) then Exit;
  if not QueryVirtualRegion(WinCurrentProcess, Address, Region) then Exit;
  if Region.State <> ALLOC_MEM_COMMIT then Exit;
  if (Region.Protect and ALLOC_PAGE_GUARD) <> 0 then Exit;
  if (Region.Protect and $FF) = $01 then Exit;
  if Address < Region.BaseAddress then Exit;
  Offset := Address - Region.BaseAddress;
  Result := (Offset < Region.Size) and (Bytes <= Region.Size - Offset);
end;

function SafeRead(Address: NativeUInt; var Dest; Bytes: NativeUInt): Boolean;
begin
  Result := False;
  if not ReadableLocal(Address, Bytes) then Exit;
  try
    Move(PByte(Pointer(Address))^, Dest, Bytes);
    Result := True;
  except
    Result := False;
  end;
end;

function ReadU16(Address: NativeUInt; out Value: Word): Boolean;
begin
  Value := 0;
  Result := SafeRead(Address, Value, SizeOf(Value));
end;

function ReadU32(Address: NativeUInt; out Value: Cardinal): Boolean;
begin
  Value := 0;
  Result := SafeRead(Address, Value, SizeOf(Value));
end;

function ReadU64(Address: NativeUInt; out Value: UInt64): Boolean;
begin
  Value := 0;
  Result := SafeRead(Address, Value, SizeOf(Value));
end;

function MapAddress(const Image: TImageInfo; RVA, Bytes: Cardinal;
  out Address: NativeUInt): Boolean;
begin
  Address := 0;
  Result := WithinImage(Image, RVA, Bytes) and
    (NativeUInt(RVA) <= High(NativeUInt) - Image.Base);
  if Result then Address := Image.Base + RVA;
end;

function ReadImageU32(const Image: TImageInfo; RVA: Cardinal;
  out Value: Cardinal): Boolean;
var
  A: NativeUInt;
begin
  Result := MapAddress(Image, RVA, 4, A) and ReadU32(A, Value);
end;

function ReadImageU16(const Image: TImageInfo; RVA: Cardinal;
  out Value: Word): Boolean;
var
  A: NativeUInt;
begin
  Result := MapAddress(Image, RVA, 2, A) and ReadU16(A, Value);
end;

function ReadAsciiRVA(const Image: TImageInfo; RVA: Cardinal;
  MaxLength: Cardinal; out S: AnsiString): Boolean;
var
  A: NativeUInt;
  MaxBytes, I: Cardinal;
  P: PByte;
  Region: TVirtualRegion;
  Remain: NativeUInt;
begin
  S := '';
  Result := False;
  if not WithinImage(Image, RVA, 1) then Exit;
  MaxBytes := Image.Size - RVA;
  if MaxBytes > MaxLength then MaxBytes := MaxLength;
  if not MapAddress(Image, RVA, 1, A) then Exit;
  // Names often end near a read-only VAD boundary. Requiring the entire
  // 160-byte cap to be accessible would misclassify valid short names.
  if not QueryVirtualRegion(WinCurrentProcess, A, Region) then Exit;
  if (Region.State <> ALLOC_MEM_COMMIT) or
     ((Region.Protect and ALLOC_PAGE_GUARD) <> 0) or
     ((Region.Protect and $FF) = $01) or
     (A < Region.BaseAddress) or
     (A - Region.BaseAddress >= Region.Size) then Exit;
  Remain := Region.Size - (A - Region.BaseAddress);
  if NativeUInt(MaxBytes) > Remain then MaxBytes := Cardinal(Remain);
  if MaxBytes = 0 then Exit;
  try
    P := Pointer(A);
    for I := 0 to MaxBytes - 1 do
    begin
      if P^ = 0 then Exit(True);
      if (P^ < 32) or (P^ > 126) then Exit;
      S := S + AnsiChar(P^);
      Inc(P);
    end;
  except
    Result := False;
    S := '';
  end;
end;

function HashText(Hash: UInt64; const S: AnsiString): UInt64;
var
  I: Integer;
begin
  Result := ExportHash(Hash, Length(S));
  for I := 1 to Length(S) do
    Result := PEHashByte(Result, Byte(S[I]));
end;

function ReadImageInfo(Base: NativeUInt; out Image: TImageInfo): Boolean;
var
  MZ, Machine, Magic, OptSize: Word;
  PEOffset, Signature, Size, DirCount: Cardinal;
  PE, Opt: NativeUInt;
begin
  Image := Default(TImageInfo);
  Result := False;
  if (Base < $10000) or not ReadU16(Base, MZ) or (MZ <> $5A4D) then Exit;
  if not ReadU32(Base + $3C, PEOffset) or
     (PEOffset < $40) or (PEOffset > $2000) then Exit;
  PE := Base + PEOffset;
  if (PE < Base) or not ReadU32(PE, Signature) or
     (Signature <> $00004550) then Exit;
  if not ReadU16(PE + 4, Machine) or (Machine <> $8664) then Exit;
  if not ReadU16(PE + 20, OptSize) or
     (OptSize < 120) or (OptSize > $500) then Exit;
  Opt := PE + 24;
  if (Opt < PE) or not ReadableLocal(Opt, OptSize) or
     not ReadU16(Opt, Magic) or (Magic <> $020B) then Exit;
  if not ReadU32(Opt + 56, Size) or (Size < $1000) or
     (Size > MAX_PE_IMAGE) or
     not ReadU32(Opt + 108, DirCount) then Exit;
  if (DirCount > Cardinal(OptSize - 112) div 8) then Exit;
  Image.Base := Base;
  Image.Size := Size;
  if DirCount > 0 then
  begin
    if not ReadU32(Opt + 112, Image.ExportRVA) or
       not ReadU32(Opt + 116, Image.ExportSize) then Exit;
  end;
  if DirCount > 13 then
  begin
    if not ReadU32(Opt + 112 + 13 * 8, Image.DelayRVA) or
       not ReadU32(Opt + 116 + 13 * 8, Image.DelaySize) then Exit;
  end;
  Result := True;
end;

function ExecutableMappedImage(Address: NativeUInt): Boolean;
var
  Region: TVirtualRegion;
begin
  Result := QueryVirtualRegion(WinCurrentProcess, Address, Region) and
    (Region.RegionType = ALLOC_MEM_IMAGE) and
    RegionIsExecutable(Region);
end;

end.
