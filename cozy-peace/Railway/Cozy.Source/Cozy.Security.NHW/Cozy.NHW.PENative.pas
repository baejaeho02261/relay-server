unit Cozy.NHW.PENative;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  Cozy.NHW.PERules;

// Inspect the mapped PE of the current executable only.
// No code pages are read, no loader structures are altered, and no
// library is injected. All metadata reads are bounded by a valid VAD.
function CapturePEImage(out Snapshot: TPEImageSnapshot): Boolean;

implementation

uses
  Cozy.NHW.ExceptionNative,
  Cozy.NHW.AllocationNative,
  Cozy.NHW.WinPointers,
  Cozy.NHW.NativeSafety;

const
  PE_HASH_START = UInt64($CBF29CE484222325);
  PE_IMAGE_MAX = Cardinal(512 * 1024 * 1024);
  PE_MAX_SECTIONS = 96;
  PE_DIRECTORY_MAX = 16;
  PE_MAX_RELOCATION_BYTES = 16 * 1024 * 1024;
  PE_MAX_RELOCATION_ENTRIES = 1000000;
  PE_MAX_TLS_CALLBACKS = 64;
  PE_MAX_CONFIG_BYTES = 4096;
  PE_SECTION_HEADER_SIZE = 40;

function SafeCopy(Address: NativeUInt; var Output; Size: NativeUInt): Boolean;
begin
  Result := False;
  if not NHWAddressSpan(Address, Size) then Exit;
  if not IsReadableLocalRange(Address, Size) then Exit;
  try
    Move(PByte(Pointer(Address))^, Output, Size);
    Result := True;
  except
    Result := False;
  end;
end;

function Read16(Address: NativeUInt; out Value: Word): Boolean;
begin
  Value := 0;
  Result := SafeCopy(Address, Value, SizeOf(Value));
end;

function Read32(Address: NativeUInt; out Value: Cardinal): Boolean;
begin
  Value := 0;
  Result := SafeCopy(Address, Value, SizeOf(Value));
end;

function Read64(Address: NativeUInt; out Value: UInt64): Boolean;
begin
  Value := 0;
  Result := SafeCopy(Address, Value, SizeOf(Value));
end;

function HashBlock(Address: NativeUInt; Bytes: Cardinal;
  out Hash: UInt64): Boolean;
var
  I: Cardinal;
  P: PByte;
begin
  Result := False;
  Hash := PE_HASH_START;
  if Bytes = 0 then Exit(True);
  if not IsReadableLocalRange(Address, Bytes) then Exit;
  try
    P := Pointer(Address);
    for I := 0 to Bytes - 1 do
    begin
      Hash := PEHashByte(Hash, P^);
      Inc(P);
    end;
    Result := True;
  except
    Result := False;
  end;
end;

function HashStream(Address: NativeUInt; Bytes: Cardinal;
  var Hash: UInt64): Boolean;
var
  H: UInt64;
begin
  Result := HashBlock(Address, Bytes, H);
  if Result then Hash := PEHashInteger(Hash, H);
end;

function BoundAddress(Base: NativeUInt; RVA, Bytes, ImageSize: Cardinal;
  out Address: NativeUInt): Boolean;
begin
  Address := 0;
  Result := False;
  if not PERangeInImage(RVA, Bytes, ImageSize) then Exit;
  if not NHWTryAddAddress(Base, RVA, Address) then Exit;
  Result := NHWContainedSpan(Base, ImageSize, Address, Bytes);
  if not Result then Address := 0;
end;

function CapturePEImage(out Snapshot: TPEImageSnapshot): Boolean;
var
  Base, PE, Opt, SecTable: NativeUInt;
  EntryPoint, HeaderOffset, ImageSize: Cardinal;
  SectionAlign, HeadersSize, DirectoryCount, AvailableCount: Cardinal;
  RelocRVA, RelocSize, TLSRVA, TLSSize, LoadRVA, LoadSize: Cardinal;
  MZ: Word;
  Signature, OptMagic: Cardinal;
  COFF: array[0..19] of Byte;
  Machine, NumSections, OptionalBytes: Word;
  ValidDirectories: Boolean;
  Dir: array[0..15,0..1] of Cardinal;

  function CaptureHeaderDigest: Boolean;
  var
    HeaderHash: UInt64;
  begin
    Result := True;
    HeaderHash := PE_HASH_START;
    if not HashStream(Base, 64, HeaderHash) or
       not HashStream(PE, 24, HeaderHash) or
       not HashStream(Opt, OptionalBytes, HeaderHash) then
    begin
      Result := False;
      Exit;
    end;
    Snapshot.Header.Valid := True;
    Snapshot.Header.Digest := PEHashInteger(HeaderHash, UInt64(Base));
  end;

  procedure CaptureSections;
  var
    SectionHash: UInt64;
    ValidSections, HaveSectionData: Boolean;
    LastSectionEnd, Span, VSize, RawSize, SecRVA: Cardinal;
    SectionAddr: NativeUInt;
    SecBytes: array[0..39] of Byte;
    Region: TVirtualRegion;
    I, J: Integer;
  begin
    SectionHash := PE_HASH_START;
    ValidSections := True;
    HaveSectionData := True;
    LastSectionEnd := 0;
    for I := 0 to NumSections - 1 do
    begin
      SectionAddr := SecTable + NativeUInt(I) * PE_SECTION_HEADER_SIZE;
      if not SafeCopy(SectionAddr, SecBytes, SizeOf(SecBytes)) then
      begin
        HaveSectionData := False;
        Break;
      end;
      for J := 0 to High(SecBytes) do
        SectionHash := PEHashByte(SectionHash, SecBytes[J]);
      Move(SecBytes[8], VSize, 4);
      Move(SecBytes[12], SecRVA, 4);
      Move(SecBytes[16], RawSize, 4);
      Span := VSize;
      if Span = 0 then Span := RawSize;
      if (SecRVA < HeadersSize) or
         not PERangeInImage(SecRVA, Span, ImageSize) or
         ((I > 0) and (SecRVA < LastSectionEnd)) then
        ValidSections := False;
      // Do not compare RegionSize or writable/page protection: v24 covers
      // protection transitions, and normal COW may split VAD regions.
      if (Span <> 0) and PERangeInImage(SecRVA, 1, ImageSize) and
         ((SecBytes[39] and $02) = 0) then
      begin
        if not QueryVirtualRegion(WinCurrentProcess, Base + SecRVA, Region) then
        begin
          HaveSectionData := False;
          Break;
        end;
        SectionHash := PEHashInteger(SectionHash, Region.State);
        SectionHash := PEHashInteger(SectionHash, Region.RegionType);
        // Discardable .reloc regions can legitimately be freed after loading.
        if (Region.State <> ALLOC_MEM_FREE) and
           (Region.AllocationBase <> Base) then ValidSections := False;
      end;
      if SecRVA <= High(Cardinal) - Span then
        LastSectionEnd := SecRVA + Span
      else
        ValidSections := False;
    end;
    if HaveSectionData then
    begin
      Snapshot.Sections.Available := True;
      Snapshot.Sections.Valid := ValidSections;
      Snapshot.Sections.Digest := SectionHash;
    end;
  end;

  function CaptureDirectories: Boolean;
  var
    DirectoryHash: UInt64;
    Address: NativeUInt;
    RV, SZ: Cardinal;
    I: Integer;
  begin
    Result := True;
    DirectoryHash := PE_HASH_START;
    ValidDirectories := True;
    AvailableCount := DirectoryCount;
    if AvailableCount > PE_DIRECTORY_MAX then AvailableCount := PE_DIRECTORY_MAX;
    if (112 + UInt64(AvailableCount) * 8 > OptionalBytes) then
      ValidDirectories := False;
    if ValidDirectories then
    begin
      for I := 0 to Integer(AvailableCount) - 1 do
      begin
        Address := Opt + 112 + NativeUInt(I) * 8;
        if not Read32(Address, RV) or not Read32(Address + 4, SZ) then
        begin
          Result := False;
          Exit;
        end;
        Dir[I,0] := RV;
        Dir[I,1] := SZ;
        DirectoryHash := PEHashInteger(DirectoryHash, RV);
        DirectoryHash := PEHashInteger(DirectoryHash, SZ);
        // Entry 4 is the certificate table: a FILE offset, not an RVA.
        if (I <> 4) and ((RV <> 0) or (SZ <> 0)) and
           not PERangeInImage(RV, SZ, ImageSize) then
          ValidDirectories := False;
      end;
    end;
    Snapshot.Directories.Available := True;
    Snapshot.Directories.Valid := ValidDirectories;
    Snapshot.Directories.Digest := DirectoryHash;
  end;

  procedure SelectFeatureDirectories;
  begin
    RelocRVA := 0; RelocSize := 0;
    TLSRVA := 0; TLSSize := 0;
    LoadRVA := 0; LoadSize := 0;
    if AvailableCount > 5 then
    begin RelocRVA := Dir[5,0]; RelocSize := Dir[5,1]; end;
    if AvailableCount > 9 then
    begin TLSRVA := Dir[9,0]; TLSSize := Dir[9,1]; end;
    if AvailableCount > 10 then
    begin LoadRVA := Dir[10,0]; LoadSize := Dir[10,1]; end;
  end;

  procedure CaptureRelocations;
  var
    ValidRelocs, HaveRelocs: Boolean;
    RelocHash: UInt64;
    RelocOffset, EntryCount, BlockRVA, BlockSize, PageOffset: Cardinal;
    RelocEntry, RelocType: Word;
    J: Integer;
  begin
    // Rebase blocks: validate 4K page block structure and expected DIR64
    // targets; no relocation operand values are read or rewritten.
    ValidRelocs := True;
    HaveRelocs := True;
    RelocHash := PE_HASH_START;
    RelocHash := PEHashInteger(RelocHash, RelocRVA);
    RelocHash := PEHashInteger(RelocHash, RelocSize);
    if (RelocRVA <> 0) or (RelocSize <> 0) then
    begin
      if (RelocRVA = 0) or (RelocSize < 8) or
         (RelocSize > PE_MAX_RELOCATION_BYTES) then
        ValidRelocs := False
      else
      begin
        RelocOffset := 0;
        EntryCount := 0;
        while RelocOffset < RelocSize do
        begin
          if not PERangeInImage(RelocRVA + RelocOffset, 8, ImageSize) then
          begin
            ValidRelocs := False;
            Break;
          end;
          if not Read32(Base + RelocRVA + RelocOffset, BlockRVA) then
          begin
            HaveRelocs := False;
            Break;
          end;
          if not Read32(Base + RelocRVA + RelocOffset + 4, BlockSize) then
          begin
            HaveRelocs := False;
            Break;
          end;
          if (BlockSize < 8) or ((BlockSize and 1) <> 0) or
             (BlockSize > RelocSize - RelocOffset) or
             ((BlockRVA and $FFF) <> 0) then
          begin
            ValidRelocs := False;
            Break;
          end;
          if not PERangeInImage(BlockRVA, 1, ImageSize) then
          begin
            ValidRelocs := False;
            Break;
          end;
          RelocHash := PEHashInteger(RelocHash, BlockRVA);
          RelocHash := PEHashInteger(RelocHash, BlockSize);
          for J := 0 to Integer((BlockSize - 8) div 2) - 1 do
          begin
            if not Read16(Base + RelocRVA + RelocOffset + 8 +
              NativeUInt(J) * 2, RelocEntry) then
            begin
              HaveRelocs := False;
              Break;
            end;
            RelocHash := PEHashInteger(RelocHash, RelocEntry);
            RelocType := RelocEntry shr 12;
            PageOffset := RelocEntry and $0FFF;
            // Unknown machine-specific relocation types are not attributed
            // to tampering: skip the feature rather than a false positive.
            if (RelocType <> 0) and (RelocType <> 10) and
               (RelocType <> 3) then
            begin
              HaveRelocs := False;
              Break;
            end;
            if (RelocType = 10) and
               not PERangeInImage(BlockRVA + PageOffset, 8, ImageSize) then
              ValidRelocs := False;
            if (RelocType = 3) and
               not PERangeInImage(BlockRVA + PageOffset, 4, ImageSize) then
              ValidRelocs := False;
            Inc(EntryCount);
            if EntryCount > PE_MAX_RELOCATION_ENTRIES then
            begin
              HaveRelocs := False;
              Break;
            end;
          end;
          if not HaveRelocs then Break;
          Inc(RelocOffset, BlockSize);
        end;
      end;
    end;
    if HaveRelocs then
    begin
      Snapshot.Relocations.Available := True;
      Snapshot.Relocations.Valid := ValidRelocs;
      Snapshot.Relocations.Digest := RelocHash;
    end;
  end;

  procedure CaptureTLSDirectory;
  var
    ValidTLS, HaveTLS: Boolean;
    TLSHash, TLSStart, TLSEnd, TLSIndex, TLSCallbacks, Callback: UInt64;
    TLSAddr: NativeUInt;
    K: Integer;
  begin
    // Loader TLS directory (PE32+): raw fields are absolute VAs, not RVAs.
    ValidTLS := True;
    HaveTLS := True;
    TLSHash := PE_HASH_START;
    TLSHash := PEHashInteger(TLSHash, TLSRVA);
    TLSHash := PEHashInteger(TLSHash, TLSSize);
    if (TLSRVA <> 0) or (TLSSize <> 0) then
    begin
      if (TLSRVA = 0) or (TLSSize < 40) or
         not PERangeInImage(TLSRVA, 40, ImageSize) then
        ValidTLS := False
      else
      begin
        TLSAddr := Base + TLSRVA;
        if not Read64(TLSAddr, TLSStart) or
           not Read64(TLSAddr + 8, TLSEnd) or
           not Read64(TLSAddr + 16, TLSIndex) or
           not Read64(TLSAddr + 24, TLSCallbacks) then
          HaveTLS := False
        else
        begin
          TLSHash := PEHashInteger(TLSHash, TLSStart);
          TLSHash := PEHashInteger(TLSHash, TLSEnd);
          TLSHash := PEHashInteger(TLSHash, TLSIndex);
          TLSHash := PEHashInteger(TLSHash, TLSCallbacks);
          if (TLSStart > TLSEnd) then ValidTLS := False;
          // Callbacks are an optional null-terminated table of image VAs.
          // Do not enumerate Windows' private TLS/FLS state.
          if (TLSCallbacks <> 0) then
          begin
            if (TLSCallbacks < UInt64(Base)) or
               (TLSCallbacks - UInt64(Base) >= UInt64(ImageSize)) then
              HaveTLS := False
            else
            begin
              K := 0;
              while K < PE_MAX_TLS_CALLBACKS do
              begin
                if not Read64(NativeUInt(TLSCallbacks) + NativeUInt(K) * 8,
                   Callback) then
                begin
                  HaveTLS := False;
                  Break;
                end;
                TLSHash := PEHashInteger(TLSHash, Callback);
                if Callback = 0 then Break;
                Inc(K);
              end;
              if K >= PE_MAX_TLS_CALLBACKS then HaveTLS := False;
            end;
          end;
        end;
      end;
    end;
    if HaveTLS then
    begin
      Snapshot.TLSDirectory.Available := True;
      Snapshot.TLSDirectory.Valid := ValidTLS;
      Snapshot.TLSDirectory.Digest := TLSHash;
    end;
  end;

  procedure CaptureLoadConfiguration;
  var
    ValidConfig, HaveConfig: Boolean;
    LoadHash, Hash: UInt64;
    LoadedConfigSize, LengthToHash: Cardinal;
  begin
    // Loader configuration: hash bounded declaration bytes, not the current
    // security-cookie value or the runtime GuardCFDispatch pointer target.
    ValidConfig := True;
    HaveConfig := True;
    LoadHash := PE_HASH_START;
    LoadHash := PEHashInteger(LoadHash, LoadRVA);
    LoadHash := PEHashInteger(LoadHash, LoadSize);
    if (LoadRVA <> 0) or (LoadSize <> 0) then
    begin
      if (LoadRVA = 0) or (LoadSize < 4) or
         not PERangeInImage(LoadRVA, 4, ImageSize) then
        ValidConfig := False
      else
      begin
        if not Read32(Base + LoadRVA, LoadedConfigSize) then
          HaveConfig := False
        else if (LoadedConfigSize < 4) or
                (LoadedConfigSize > PE_MAX_CONFIG_BYTES) then
          ValidConfig := False
        else
        begin
          LengthToHash := LoadedConfigSize;
          if LengthToHash > LoadSize then LengthToHash := LoadSize;
          if LengthToHash > 512 then LengthToHash := 512;
          if not PERangeInImage(LoadRVA, LengthToHash, ImageSize) or
             not HashBlock(Base + LoadRVA, LengthToHash, Hash) then
            HaveConfig := False
          else
            LoadHash := PEHashInteger(LoadHash, Hash);
        end;
      end;
    end;
    if HaveConfig then
    begin
      Snapshot.LoadConfig.Available := True;
      Snapshot.LoadConfig.Valid := ValidConfig;
      Snapshot.LoadConfig.Digest := LoadHash;
    end;
  end;

begin
  Snapshot := Default(TPEImageSnapshot);
  Result := False;
  Base := NativeUInt(HInstance);
  if not NHWAddressSpan(Base, PE_IMAGE_MAX) or not Read16(Base, MZ) then Exit;
  Result := True;
  Snapshot.Header.Available := True;
  if MZ <> $5A4D then Exit;
  if not Read32(Base + $3C, HeaderOffset) then
  begin
    Result := False;
    Exit;
  end;
  if (HeaderOffset < $40) or (HeaderOffset > $2000) then Exit;
  PE := Base + HeaderOffset;
  if not Read32(PE, Signature) then
  begin
    Result := False;
    Exit;
  end;
  if Signature <> $00004550 then Exit;
  if not SafeCopy(PE + 4, COFF, SizeOf(COFF)) then
  begin
    Result := False;
    Exit;
  end;
  Machine := PWord(@COFF[0])^;
  NumSections := PWord(@COFF[2])^;
  OptionalBytes := PWord(@COFF[16])^;
  if (Machine <> $8664) or (NumSections = 0) or
     (NumSections > PE_MAX_SECTIONS) or
     (OptionalBytes < 112) or (OptionalBytes > $500) then Exit;
  Opt := PE + 24;
  if not Read32(Opt, OptMagic) then
  begin
    Result := False;
    Exit;
  end;
  if (OptMagic and $FFFF) <> $020B then Exit;
  if not SafeCopy(Opt, OptMagic, SizeOf(OptMagic)) then
  begin
    Result := False;
    Exit;
  end;
  if not Read32(Opt + 56, ImageSize) or
     not Read32(Opt + 60, HeadersSize) or
     not Read32(Opt + 32, SectionAlign) or
     not Read32(Opt + 16, EntryPoint) or
     not Read32(Opt + 108, DirectoryCount) then
  begin
    Result := False;
    Exit;
  end;
  if (ImageSize < $1000) or (ImageSize > PE_IMAGE_MAX) or
     (HeadersSize < $200) or (HeadersSize > ImageSize) or
     (SectionAlign = 0) or
     (DirectoryCount > 128) then Exit;
  SecTable := Opt + OptionalBytes;
  // The loader can set writable values in memory. Hash only bounded PE
  // metadata, and compare it to a post-startup baseline (never disk-layout
  // fields against relocated in-memory VAs).
  if not CaptureHeaderDigest then Exit(False);
  CaptureSections;
  if not CaptureDirectories then Exit(False);
  if not ValidDirectories then Exit;
  SelectFeatureDirectories;
  CaptureRelocations;
  CaptureTLSDirectory;
  CaptureLoadConfiguration;
end;

end.
