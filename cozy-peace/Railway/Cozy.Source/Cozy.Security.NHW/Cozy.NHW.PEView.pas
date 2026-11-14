unit Cozy.NHW.PEView;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows;

type
  TPEDataRange = record
    RVA: Cardinal;
    Size: Cardinal;
  end;

  TPEView = record
    Base: NativeUInt;
    ImageSize: Cardinal;
    Directory: array[0..15] of TPEDataRange;
  end;

  TCodeLocation = (clUnknown, clImage, clMapped, clPrivate);

function LocalRead(Address: NativeUInt; var Dest; Bytes: NativeUInt): Boolean;
function ReadLocal64(Address: NativeUInt; out Value: UInt64): Boolean;
function LoadPEView(Base: NativeUInt; out View: TPEView): Boolean;
function PEAddress(const View: TPEView; RVA, Bytes: Cardinal;
  out Address: NativeUInt): Boolean;
function PEDataAddress(const View: TPEView; DirIndex: Integer;
  MinimumBytes: Cardinal; out Address: NativeUInt;
  out Bytes: Cardinal): Boolean;
function DescribeCodeAddress(Address: NativeUInt; out Kind: TCodeLocation;
  out RegionBase: NativeUInt): Boolean;
function PEHash(H, Value: UInt64): UInt64;

implementation

uses Cozy.NHW.AllocationNative, Cozy.NHW.ExceptionNative, Cozy.NHW.WinPointers,
  Cozy.NHW.NativeSafety;

function LocalRead(Address: NativeUInt; var Dest; Bytes: NativeUInt): Boolean;
begin
  Result := False;
  if not NHWAddressSpan(Address, Bytes) or
     not IsReadableLocalRange(Address, Bytes) then Exit;
  try
    Move(PByte(Pointer(Address))^, Dest, Bytes);
    Result := True;
  except
    Result := False;
  end;
end;

function ReadLocal64(Address: NativeUInt; out Value: UInt64): Boolean;
begin
  Value := 0;
  Result := LocalRead(Address, Value, SizeOf(Value));
end;

function LocatePEHeader(Base: NativeUInt; out PE: NativeUInt): Boolean;
var
  MZ: Word;
  HeaderOffset: Cardinal;
begin
  Result := False;
  PE := 0;
  if not NHWAddressSpan(Base, $3000) then Exit;
  if not LocalRead(Base, MZ, 2) or (MZ <> $5A4D) or
     not LocalRead(Base + $3C, HeaderOffset, 4) or
     (HeaderOffset < $40) or (HeaderOffset > $2000) or
     (Base > High(NativeUInt) - HeaderOffset - 24) then Exit;
  PE := Base + HeaderOffset;
  Result := True;
end;

function LocateOptionalHeader(PE: NativeUInt; out Opt: NativeUInt;
  out OptionalSize: Word): Boolean;
var
  Machine: Word;
  Signature: Cardinal;
begin
  Result := False;
  Opt := 0;
  OptionalSize := 0;
  if not LocalRead(PE, Signature, 4) or (Signature <> $00004550) or
     not LocalRead(PE + 4, Machine, 2) or (Machine <> $8664) or
     not LocalRead(PE + 20, OptionalSize, 2) or
     (OptionalSize < 112) or (OptionalSize > $500) then Exit;
  Opt := PE + 24;
  Result := True;
end;

function ReadOptionalImage(Opt: NativeUInt; OptionalSize: Word;
  Base: NativeUInt; var Candidate: TPEView; out DirCount: Cardinal): Boolean;
var Magic: Word;
begin
  Result := False;
  DirCount := 0;
  if not LocalRead(Opt, Magic, 2) or (Magic <> $020B) or
     not IsReadableLocalRange(Opt, OptionalSize) or
     not LocalRead(Opt + 56, Candidate.ImageSize, 4) or
     (Candidate.ImageSize < $1000) or
     (Candidate.ImageSize > 512 * 1024 * 1024) or
     not LocalRead(Opt + 108, DirCount, 4) or
     (DirCount > Cardinal(OptionalSize - 112) div 8) then Exit;
  Candidate.Base := Base;
  Result := True;
end;

function ReadPEDirectories(Opt: NativeUInt; DirCount: Cardinal;
  var Candidate: TPEView): Boolean;
var I: Integer;
begin
  Result := False;
  for I := 0 to 15 do
  begin
    if Cardinal(I) >= DirCount then Break;
    if not LocalRead(Opt + 112 + NativeUInt(I) * 8,
       Candidate.Directory[I], SizeOf(TPEDataRange)) then Exit;
  end;
  Result := True;
end;

function LoadPEView(Base: NativeUInt; out View: TPEView): Boolean;
var
  OptionalSize: Word;
  DirCount: Cardinal;
  PE, Opt: NativeUInt;
  Candidate: TPEView;
begin
  View := Default(TPEView);
  Candidate := Default(TPEView);
  Result := False;
  if not LocatePEHeader(Base, PE) then Exit;
  if not LocateOptionalHeader(PE, Opt, OptionalSize) then Exit;
  if not ReadOptionalImage(Opt, OptionalSize, Base, Candidate, DirCount) then Exit;
  if not ReadPEDirectories(Opt, DirCount, Candidate) then Exit;
  View := Candidate; // publish only a fully validated header
  Result := True;
end;

function PEAddress(const View: TPEView; RVA, Bytes: Cardinal;
  out Address: NativeUInt): Boolean;
begin
  Address := 0;
  Result := False;
  if (View.Base < $10000) or (RVA >= View.ImageSize) or
     (Bytes = 0) then Exit;
  if (Bytes > View.ImageSize - RVA) or
     (NativeUInt(RVA) > High(NativeUInt) - View.Base) then Exit;
  if not NHWTryAddAddress(View.Base, NativeUInt(RVA), Address) then Exit;
  Result := NHWContainedSpan(View.Base, View.ImageSize, Address, Bytes);
  if not Result then Address := 0;
end;

function PEDataAddress(const View: TPEView; DirIndex: Integer;
  MinimumBytes: Cardinal; out Address: NativeUInt;
  out Bytes: Cardinal): Boolean;
begin
  Address := 0;
  Bytes := 0;
  Result := False;
  if (DirIndex < 0) or (DirIndex > 15) then Exit;
  Bytes := View.Directory[DirIndex].Size;
  if Bytes < MinimumBytes then Exit;
  Result := PEAddress(View, View.Directory[DirIndex].RVA,
    Bytes, Address);
  if not Result then Bytes := 0;
end;

function DescribeCodeAddress(Address: NativeUInt; out Kind: TCodeLocation;
  out RegionBase: NativeUInt): Boolean;
var
  R: TVirtualRegion;
begin
  Kind := clUnknown;
  RegionBase := 0;
  Result := QueryVirtualRegion(WinCurrentProcess, Address, R);
  if not Result then Exit;
  RegionBase := R.BaseAddress;
  if not RegionIsExecutable(R) then Exit;
  case R.RegionType of
    ALLOC_MEM_IMAGE: Kind := clImage;
    ALLOC_MEM_PRIVATE: Kind := clPrivate;
    ALLOC_MEM_MAPPED: Kind := clMapped;
  end;
end;

function PEHash(H, Value: UInt64): UInt64;
begin
  Result := (H xor Value) * UInt64($00000100000001B3);
end;

end.
