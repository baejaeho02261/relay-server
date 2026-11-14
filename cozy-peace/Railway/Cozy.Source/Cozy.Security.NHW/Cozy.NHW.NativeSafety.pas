unit Cozy.NHW.NativeSafety;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

// Shared arithmetic contracts. These routines never dereference a foreign
// pointer and do not turn address validation into a permission guarantee.
function NHWTryAddAddress(Base, Offset: NativeUInt;
  out Address: NativeUInt): Boolean;
function NHWTryMultiplySize(Count, ElementBytes: NativeUInt;
  out Bytes: NativeUInt): Boolean;
function NHWBufferSpan(BufferBytes, Offset, Bytes: NativeUInt): Boolean;
function NHWAddressSpan(Address, Bytes: NativeUInt): Boolean;
function NHWContainedSpan(Base, SpanBytes, Address, Bytes: NativeUInt): Boolean;
function NHWNextBufferSize(Current, Required, Cap: Cardinal;
  out Next: Cardinal): Boolean;
function NHWExpired(Stamp, NowTick, LifetimeMS: UInt64): Boolean;
function NHWSaturatingAdd(A, B: UInt64): UInt64;

implementation

function NHWTryAddAddress(Base, Offset: NativeUInt;
  out Address: NativeUInt): Boolean;
begin
  Address := 0;
  Result := Offset <= High(NativeUInt) - Base;
  if Result then Address := Base + Offset;
end;

function NHWTryMultiplySize(Count, ElementBytes: NativeUInt;
  out Bytes: NativeUInt): Boolean;
begin
  Bytes := 0;
  if (Count = 0) or (ElementBytes = 0) then Exit(True);
  Result := Count <= High(NativeUInt) div ElementBytes;
  if Result then Bytes := Count * ElementBytes;
end;

function NHWBufferSpan(BufferBytes, Offset, Bytes: NativeUInt): Boolean;
begin
  Result := False;
  if Offset > BufferBytes then Exit;
  Result := Bytes <= BufferBytes - Offset;
end;

function NHWAddressSpan(Address, Bytes: NativeUInt): Boolean;
begin
  // Use an exclusive end, reject empty ranges and signed Move-size overflow.
  Result := (Address >= $10000) and (Bytes <> 0) and
    (Bytes <= NativeUInt(High(NativeInt))) and
    (Bytes <= High(NativeUInt) - Address);
end;

function NHWContainedSpan(Base, SpanBytes, Address, Bytes: NativeUInt): Boolean;
begin
  Result := False;
  if not NHWAddressSpan(Address, Bytes) then Exit;
  if (Address < Base) or (SpanBytes > High(NativeUInt) - Base) then Exit;
  Result := NHWBufferSpan(SpanBytes, Address - Base, Bytes);
end;

function NHWNextBufferSize(Current, Required, Cap: Cardinal;
  out Next: Cardinal): Boolean;
var Candidate: UInt64;
begin
  Next := 0;
  Result := False;
  if (Current = 0) or (Current >= Cap) or
     (Cap > Cardinal(High(Integer))) or (Required > Cap) then Exit;
  Candidate := UInt64(Current) * UInt64(2);
  if Required > Current then Candidate := UInt64(Required) + UInt64(65536);
  if Candidate > UInt64(Cap) then Candidate := UInt64(Cap);
  if Candidate <= UInt64(Current) then Exit;
  Next := Cardinal(Candidate);
  Result := True;
end;

function NHWExpired(Stamp, NowTick, LifetimeMS: UInt64): Boolean;
begin
  // A backwards clock is an incomparable epoch, not a gigantic elapsed time.
  Result := (NowTick < Stamp) or
    ((LifetimeMS <> 0) and (NowTick >= Stamp) and
     (NowTick - Stamp > LifetimeMS));
end;

function NHWSaturatingAdd(A, B: UInt64): UInt64;
begin
  if B > High(UInt64) - A then Result := High(UInt64)
  else Result := A + B;
end;

end.
