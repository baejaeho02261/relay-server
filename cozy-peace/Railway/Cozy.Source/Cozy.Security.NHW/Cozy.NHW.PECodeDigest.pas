unit Cozy.NHW.PECodeDigest;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows;

type
  TCodeImageDigest = record
    Value: UInt64;
    SectionCount: Cardinal;
    BytesHashed: Cardinal;
    Valid: Boolean;
  end;

  TCodeSectionSpan = record
    RVA: Cardinal;
    Bytes: Cardinal;
  end;

  TCodeImageLayout = record
    ModuleBase: NativeUInt;
    ImageSize: Cardinal;
    TimeDateStamp: Cardinal;
    SectionCount: Cardinal;
    TotalBytes: Cardinal;
    LayoutDigest: UInt64;
    Sections: array[0..63] of TCodeSectionSpan;
  end;

  TCodeScanProgress = record
    Active: Boolean;
    Layout: TCodeImageLayout;
    SectionIndex: Cardinal;
    SectionOffset: Cardinal;
    BytesHashed: Cardinal;
    Hash: UInt64;
  end;


const
  CODE_MAX_IMAGE_SIZE = 512 * 1024 * 1024;
  CODE_MAX_SECTIONS = 64;
  CODE_SCAN_BUDGET = 24 * 1024 * 1024; // per module, per Examine; not image cap
  PE_EXECUTABLE_FLAG = $20000000;
  PE_WRITABLE_FLAG = $80000000;
  PE32_PLUS_MAGIC = $20B;
  PE_SIGNATURE = $00004550;
  DOS_SIGNATURE = $5A4D;
  CODE_HASH_BASIS = UInt64($CBF29CE484222325);


type
  TCodeScanResult = (csrFailed, csrPending, csrComplete);
  TCodeSectionHeader = packed record
    Name: array[0..7] of Byte;
    VirtualSize, RVA, RawSize, RawPointer: Cardinal;
    RelocPointer, LinePointer: Cardinal;
    RelocCount, LineCount: Word;
    Characteristics: Cardinal;
  end;

{$IFDEF NHW_NATIVE5F_TESTS}
type
  TCodeReadHook = function(Address: NativeUInt; var Dest;
    Bytes: NativeUInt): Boolean;
var
  CodeReadHook: TCodeReadHook = nil;
{$ENDIF}

function CodeRead(Address: NativeUInt; var Dest; Bytes: NativeUInt): Boolean;
function CaptureCodeLayout(Module: HMODULE;
  out Layout: TCodeImageLayout): Boolean;
function SameCodeLayout(const A, B: TCodeImageLayout): Boolean;
function HashMappedBytes(Address: NativeUInt; Bytes: Cardinal;
  var Hash: UInt64): Boolean;
function AdvanceCodeDigest(Module: HMODULE; Budget: Cardinal;
  var Progress: TCodeScanProgress; out Digest: TCodeImageDigest;
  out Restarted: Boolean): TCodeScanResult;
function CaptureExecutableCodeDigest(Module: HMODULE;
  out Digest: TCodeImageDigest): Boolean;

implementation

uses
  System.SysUtils, Cozy.NHW.PEView, Cozy.NHW.NativeSafety, Cozy.NHW.PERules;

function CodeRead(Address: NativeUInt; var Dest; Bytes: NativeUInt): Boolean;
begin
  Result := False;
  if not NHWAddressSpan(Address, Bytes) then Exit;
{$IFDEF NHW_NATIVE5F_TESTS}
  if Assigned(CodeReadHook) then Exit(CodeReadHook(Address, Dest, Bytes));
{$ENDIF}
  Result := LocalRead(Address, Dest, Bytes);
end;

function CaptureCodeLayout(Module: HMODULE;
  out Layout: TCodeImageLayout): Boolean;
var
  Candidate: TCodeImageLayout;
  Base, PE, Opt, SecTable: NativeUInt;
  HeaderRVA, Signature, Bytes: Cardinal;
  Magic, Machine, NumberOfSections, OptionalSize: Word;
  S: TCodeSectionHeader;
  I, J: Integer;
  H: UInt64;
begin
  Result := False;
  Layout := Default(TCodeImageLayout);
  Candidate := Default(TCodeImageLayout);
  S := Default(TCodeSectionHeader);
  Magic := 0; Machine := 0; NumberOfSections := 0; OptionalSize := 0;
  HeaderRVA := 0; Signature := 0;
  Base := NativeUInt(Module);
  if not NHWAddressSpan(Base, $3000) then Exit;
  if not CodeRead(Base, Magic, SizeOf(Magic)) or (Magic <> DOS_SIGNATURE) or
    not CodeRead(Base + $3C, HeaderRVA, SizeOf(HeaderRVA)) or
    (HeaderRVA < $40) or (HeaderRVA > $2000) then Exit;
  PE := Base + HeaderRVA;
  if not CodeRead(PE, Signature, SizeOf(Signature)) or
    (Signature <> PE_SIGNATURE) or
    not CodeRead(PE + 4, Machine, SizeOf(Machine)) or (Machine <> $8664) or
    not CodeRead(PE + 6, NumberOfSections, SizeOf(NumberOfSections)) or
    (NumberOfSections = 0) or (NumberOfSections > CODE_MAX_SECTIONS) or
    not CodeRead(PE + 8, Candidate.TimeDateStamp, SizeOf(Cardinal)) or
    not CodeRead(PE + 20, OptionalSize, SizeOf(OptionalSize)) or
    (OptionalSize < 112) or (OptionalSize > $500) then Exit;
  Opt := PE + 24;
  if not CodeRead(Opt, Magic, SizeOf(Magic)) or (Magic <> PE32_PLUS_MAGIC) or
    not CodeRead(Opt + 56, Candidate.ImageSize, SizeOf(Cardinal)) or
    (Candidate.ImageSize < $1000) or
    (Candidate.ImageSize > CODE_MAX_IMAGE_SIZE) or
    not NHWAddressSpan(Base, Candidate.ImageSize) then Exit;
  SecTable := Opt + OptionalSize;
  if not NHWContainedSpan(Base, Candidate.ImageSize, SecTable,
    NativeUInt(NumberOfSections) * SizeOf(S)) then Exit;
  Candidate.ModuleBase := Base;
  H := PEHashInteger(CODE_HASH_BASIS, Candidate.ImageSize);
  H := PEHashInteger(H, Candidate.TimeDateStamp);
  H := PEHashInteger(H, HeaderRVA);
  H := PEHashInteger(H, OptionalSize);
  H := PEHashInteger(H, NumberOfSections);
  for I := 0 to Integer(NumberOfSections) - 1 do
  begin
    if not CodeRead(SecTable + NativeUInt(I) * SizeOf(S), S, SizeOf(S)) then Exit;
    // Metadata participates in pass identity, even for excluded sections.
    H := PEHashInteger(H, S.RVA);
    H := PEHashInteger(H, S.VirtualSize);
    H := PEHashInteger(H, S.RawSize);
    H := PEHashInteger(H, S.Characteristics);
    if ((S.Characteristics and PE_EXECUTABLE_FLAG) = 0) or
      ((S.Characteristics and PE_WRITABLE_FLAG) <> 0) then Continue;
    // Preserve the existing executable/non-writable, file-backed byte scope.
    Bytes := S.VirtualSize;
    if Bytes > S.RawSize then Bytes := S.RawSize;
    if Bytes = 0 then Continue;
    if (S.RVA >= Candidate.ImageSize) or
      (Bytes > Candidate.ImageSize - S.RVA) then Exit;
    for J := 0 to Integer(Candidate.SectionCount) - 1 do
      if (UInt64(S.RVA) < UInt64(Candidate.Sections[J].RVA) +
           Candidate.Sections[J].Bytes) and
         (UInt64(Candidate.Sections[J].RVA) < UInt64(S.RVA) + Bytes) then Exit;
    if Bytes > Candidate.ImageSize - Candidate.TotalBytes then Exit;
    Candidate.Sections[Candidate.SectionCount].RVA := S.RVA;
    Candidate.Sections[Candidate.SectionCount].Bytes := Bytes;
    Inc(Candidate.SectionCount);
    Inc(Candidate.TotalBytes, Bytes);
  end;
  if Candidate.SectionCount = 0 then Exit;
  Candidate.LayoutDigest := H;
  Layout := Candidate;
  Result := True;
end;

function SameCodeLayout(const A, B: TCodeImageLayout): Boolean;
var I: Integer;
begin
  Result := (A.ModuleBase = B.ModuleBase) and
    (A.ImageSize = B.ImageSize) and (A.TimeDateStamp = B.TimeDateStamp) and
    (A.SectionCount = B.SectionCount) and (A.TotalBytes = B.TotalBytes) and
    (A.LayoutDigest = B.LayoutDigest);
  if not Result then Exit;
  for I := 0 to Integer(A.SectionCount) - 1 do
    if (A.Sections[I].RVA <> B.Sections[I].RVA) or
      (A.Sections[I].Bytes <> B.Sections[I].Bytes) then Exit(False);
end;

function HashMappedBytes(Address: NativeUInt; Bytes: Cardinal;
  var Hash: UInt64): Boolean;
var
  Buffer: array[0..4095] of Byte;
  Cursor: NativeUInt;
  Remaining, Portion: Cardinal;
  I: Integer;
  H: UInt64;
begin
  Result := False;
  if not NHWAddressSpan(Address, Bytes) then Exit;
  Cursor := Address;
  Remaining := Bytes;
  H := Hash;
  while Remaining <> 0 do
  begin
    // Do not span a 4 KiB page boundary in one copy. LocalRead verifies the
    // whole subrange and catches an access violation if it becomes unreadable.
    Portion := Cardinal($1000 - (Cursor and $FFF));
    if Portion > Remaining then Portion := Remaining;
    if not CodeRead(Cursor, Buffer[0], Portion) then Exit;
    for I := 0 to Integer(Portion) - 1 do H := PEHashByte(H, Buffer[I]);
    Inc(Cursor, Portion);
    Dec(Remaining, Portion);
  end;
  Hash := H; // commit no partial hash on read failure
  Result := True;
end;

function AdvanceCodeDigest(Module: HMODULE; Budget: Cardinal;
  var Progress: TCodeScanProgress; out Digest: TCodeImageDigest;
  out Restarted: Boolean): TCodeScanResult;
var
  Current, Verify: TCodeImageLayout;
  Remaining, Portion: Cardinal;
  Address: NativeUInt;
begin
  Result := csrFailed;
  Digest := Default(TCodeImageDigest);
  Restarted := False;
  try
    if (Budget = 0) or not CaptureCodeLayout(Module, Current) then Exit;
    if Progress.Active and not SameCodeLayout(Progress.Layout, Current) then
    begin
      Progress := Default(TCodeScanProgress);
      Restarted := True;
    end;
    if not Progress.Active then
    begin
      Progress := Default(TCodeScanProgress);
      Progress.Active := True;
      Progress.Layout := Current;
      Progress.Hash := PEHashInteger(CODE_HASH_BASIS, Current.LayoutDigest);
    end;
    Remaining := Budget;
    while (Remaining <> 0) and
      (Progress.SectionIndex < Current.SectionCount) do
    begin
      if Progress.SectionOffset = 0 then
      begin
        Progress.Hash := PEHashInteger(Progress.Hash,
          Current.Sections[Progress.SectionIndex].RVA);
        Progress.Hash := PEHashInteger(Progress.Hash,
          Current.Sections[Progress.SectionIndex].Bytes);
      end;
      Portion := Current.Sections[Progress.SectionIndex].Bytes -
        Progress.SectionOffset;
      if Portion > Remaining then Portion := Remaining;
      Address := Current.ModuleBase +
        Current.Sections[Progress.SectionIndex].RVA + Progress.SectionOffset;
      if not HashMappedBytes(Address, Portion, Progress.Hash) then Exit;
      Inc(Progress.SectionOffset, Portion);
      Inc(Progress.BytesHashed, Portion);
      Dec(Remaining, Portion);
      if Progress.SectionOffset = Current.Sections[Progress.SectionIndex].Bytes then
      begin
        Inc(Progress.SectionIndex);
        Progress.SectionOffset := 0;
      end;
    end;
    if not CaptureCodeLayout(Module, Verify) or
      not SameCodeLayout(Current, Verify) then Exit;
    if Progress.SectionIndex < Current.SectionCount then
      Result := csrPending
    else
    begin
      if Progress.BytesHashed <> Current.TotalBytes then Exit;
      Digest.Value := Progress.Hash;
      Digest.SectionCount := Current.SectionCount;
      Digest.BytesHashed := Progress.BytesHashed;
      Digest.Valid := True;
      Progress := Default(TCodeScanProgress);
      Result := csrComplete;
    end;
  finally
    if Result = csrFailed then
    begin
      Progress := Default(TCodeScanProgress);
      Digest := Default(TCodeImageDigest);
    end;
  end;
end;

function CaptureExecutableCodeDigest(Module: HMODULE;
  out Digest: TCodeImageDigest): Boolean;
var
  Progress: TCodeScanProgress;
  Restarted: Boolean;
begin
  Progress := Default(TCodeScanProgress);
  Digest := Default(TCodeImageDigest);
  try
    Result := AdvanceCodeDigest(Module, CODE_MAX_IMAGE_SIZE,
      Progress, Digest, Restarted) = csrComplete;
    Result := Result and not Restarted;
  except
    Digest := Default(TCodeImageDigest);
    Result := False;
  end;
end;

end.
