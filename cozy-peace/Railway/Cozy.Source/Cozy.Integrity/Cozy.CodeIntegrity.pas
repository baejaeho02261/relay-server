unit Cozy.CodeIntegrity;

{$I ..\Cozy.Configuration\Cozy.Metadata.inc}

{$B-}

interface

uses
{ Cozy central text imports. }
  Cozy.Strings.Integrity,

  Winapi.Windows, System.SysUtils, System.JSON, Cozy.SelfImageHeaders, Cozy.Measurement, Cozy.Lifetime, Cozy.CrcLayers;

type
  ECodeIntegrity = class(Exception);
  TCodeIntegrityMeasurement = record
    Algorithm, SHA512, CRC64, XXH3_128, Blake3: string;
    Size: UInt64;
    Sections: Integer;
    function ToJSON: TJSONObject;
  end;
  TCodeExportCoverage = record
    ExecutableSections, ExportCount, CodeExportCount, ForwardedExportCount: Integer;
    Status: string;
  end;
  TCodeSection = record
    RVA, Span: Cardinal;
  end;
  TCodeRelocation = record
    RVA: Cardinal;
    Width: Integer;
    ExpectedValue: UInt64;
  end;
  { Immutable measurement plan is built from the verified on-disk image before
    its directory entry is removed. Live, changeable PE headers are not trusted.
    A software report is not hardware attestation. Writable data is excluded.
    Relocation operands are checked against the pristine value plus ASLR delta
    locally before zero normalization for the shared server code digest. }
  TCodeIntegrity = class
  private
    FGate: TGameCallGate;
    FModule: HMODULE;
    { Only the default Module=0 construction is a required own-image plan.
      Explicit module inventory measurements retain their diagnostic behavior. }
    FOwnImage: Boolean;
    FOwnHeaderPlan: TSelfImageHeaderPlan;
    FImageSize: Cardinal;
    FMaximumFileBytes, FMaximumImageBytes, FMaximumCodeBytes: UInt64;
    FPreferredImageBase: UInt64;
    FSections: TArray<TCodeSection>;
    FRelocations: TArray<TCodeRelocation>;
    FFileMeasurement: TCodeIntegrityMeasurement;
    FFilePageSHA512: TBytes;
    FCheckerRanges: array[0..2] of TArray<TCodeSection>;
    FCheckerAnchorRVA: Cardinal;
    FCheckerMagic: array[0..15] of Byte;
    FCheckerTargets: array[0..5] of Cardinal;
    FExportCoverage: TCodeExportCoverage;
    FExportDirectoryOffset, FExportRVA, FExportSize: Cardinal;
    FExportTableReady: Boolean;
    FExportTableStatus: string;
    FFileExportMeasurement: TCodeIntegrityMeasurement;
{$IFDEF GAME_CRC_PE_PROBE}
    { Isolated single-thread probe only: retained bytes never exist in A/B/O.
      The probe owns this plan exclusively. FGate tracks call lifetime; it is
      not a mutex and FProbeFileMode must not be shared with other callers. }
    FProbeFileMode: Boolean;
    FProbeFileBytes, FProbeCodeBytes: TBytes;
    FProbeExportRaw: Cardinal;
{$ENDIF}
    procedure BuildCrcLayerInput(Index: Integer; const Code: TBytes;
      const Budget: TMeasurementBudget; out First, Second: TBytes);
    procedure VerifyCodePages(const Code: TBytes; const Budget: TMeasurementBudget);
    procedure UpdateCheckerCrc(Role: Integer; const Code: TBytes;
      const Budget: TMeasurementBudget; var State: TCrcState);
    procedure VerifyOwnHeaders(const Budget: TMeasurementBudget);
    function BuildCrcHeaderStream(const Budget: TMeasurementBudget): TBytes;
    function BuildCheckerStream(Role: Integer; const Code: TBytes; const Budget: TMeasurementBudget): TBytes;
    function BuildExportStream(const FileBytes: TBytes; RawOffset: Cardinal;
      FromMemory: Boolean; const Budget: TMeasurementBudget): TBytes;
    function BuildStream(const FileBytes: TBytes;
      const RawOffsets, RawSizes: TArray<Cardinal>; FromMemory: Boolean; const Budget: TMeasurementBudget): TBytes;
    function MeasureNowCore(const Budget: TMeasurementBudget): TCodeIntegrityMeasurement;
    function MeasureExportTableCore(const Budget: TMeasurementBudget): TCodeIntegrityMeasurement;
    function MeasureCrcLayersCore(const Code: TBytes; const Budget: TMeasurementBudget): TJSONObject;
    function GetFileMeasurement: TCodeIntegrityMeasurement;
    function GetExportCoverage: TCodeExportCoverage;
    function GetFileExportMeasurement: TCodeIntegrityMeasurement;
    function GetExportTableStatus: string;
    function GetIsOwnImage: Boolean;
  public
    destructor Destroy; override;
    procedure MeasureBundle(out Code: TCodeIntegrityMeasurement; out Layers: TJSONObject;
      const Budget: TMeasurementBudget);
    constructor Create(Handle: THandle; Module: HMODULE = 0); overload;
    constructor Create(Handle: THandle; Module: HMODULE; const Budget: TMeasurementBudget); overload;
    function MeasureNow: TCodeIntegrityMeasurement; overload;
    function MeasureNow(const Budget: TMeasurementBudget): TCodeIntegrityMeasurement; overload;
    function MeasureExportTableNow: TCodeIntegrityMeasurement; overload;
    function MeasureExportTableNow(const Budget: TMeasurementBudget): TCodeIntegrityMeasurement; overload;
    function MeasureCrcLayersNow: TJSONObject; overload;
    function MeasureCrcLayersNow(const Budget: TMeasurementBudget): TJSONObject; overload;
{$IFDEF GAME_CRC_PE_PROBE}
    function CaptureCrcProbeSnapshot(FileMode: Boolean): TJSONObject;
{$ENDIF}
    property IsOwnImage: Boolean read GetIsOwnImage;
    property FileMeasurement: TCodeIntegrityMeasurement read GetFileMeasurement;
    { Structural counts from the retained disk image. Code hashes cover whole
      immutable executable sections, not guessed function lengths. Forwarders
      have no implementation bytes here; their destination module is measured
      separately by the inventory. These counts are diagnostic, not attestation. }
    property ExportCoverage: TCodeExportCoverage read GetExportCoverage;
    property FileExportMeasurement: TCodeIntegrityMeasurement read GetFileExportMeasurement;
    property ExportTableStatus: string read GetExportTableStatus;
  end;

implementation

uses
  System.Classes, System.Generics.Collections, System.Generics.Defaults,
  Cozy.Integrity, Cozy.Hashes, Cozy.Api.Contracts,
  Cozy.WinApi, Cozy.Platform.ExportResolver, Cozy.Api.ROR13, Cozy.Api.Pointer;

{ Private API pointers: initialized before application code starts. }
var
  ApiSlot_GetModuleHandle: TEncodedApiPointer;


const
{$I Cozy.ModuleLimits.inc}
  MaximumFileBytes = 64 * 1024 * 1024;
  MaximumImageBytes = 128 * 1024 * 1024;
  MaximumCodeBytes = 64 * 1024 * 1024;
  CodePrefix: AnsiString = CozyText_CodeIntegrity_GAME_CODE_V1_5051d75c;
  CodeAlgorithm = CozyText_CodeIntegrity_PE64_CODE_V1_7b472aad;
  ExportPrefix: AnsiString = CozyText_CodeIntegrity_GAME_EXPORT_V1_4566b15c;
  ExportAlgorithm = CozyText_CodeIntegrity_PE64_EXPORT_V1_3e95759c;
  MaximumExportBytes = 8 * 1024 * 1024;

type
  TNativeMemoryRegion = record
    BaseAddress, AllocationBase: Pointer;
    AllocationProtect, PartitionAndPadding: DWORD;
    RegionSize: NativeUInt;
    State, Protect, Kind, TrailingPadding: DWORD;
  end;
  TFileSection = record
    RVA, Span, Mapped, Raw, RawSize, Flags: Cardinal;
    ProtectedCode: Boolean;
  end;

type
  TResolved_QueryMemory = function(Address: Pointer; out Region: TNativeMemoryRegion;
  Size: NativeUInt): NativeUInt; stdcall;
var
  ApiSlot_QueryMemory: TEncodedApiPointer;

{ POINTER WRAPPERS 1 BEGIN }
function GetModuleHandle(ModuleName: PWideChar): HMODULE; stdcall;
var
  ApiTarget: TApiGetModuleHandle;
begin
  ApiTarget := TApiGetModuleHandle(DecodeApiPointer(ApiSlot_GetModuleHandle));
  Result := ApiTarget(ModuleName);
end;

function QueryMemory(Address: Pointer; out Region: TNativeMemoryRegion;
  Size: NativeUInt): NativeUInt; stdcall;
var
  ApiTarget: TResolved_QueryMemory;
begin
  ApiTarget := TResolved_QueryMemory(DecodeApiPointer(ApiSlot_QueryMemory));
  Result := ApiTarget(Address, Region, Size);
end;
{ POINTER WRAPPERS 1 END }

procedure CrcBudgetCheckpoint(Context: Pointer);
type PBudget = ^TMeasurementBudget;
begin PBudget(Context)^.Check(0, 0); end;

procedure Require(Condition: Boolean);
begin
  if not Condition then
    raise ECodeIntegrity.Create(CozyText_CodeIntegrity_Executable_code_measurement_failed_76ccef49);
end;

procedure ClearBytes(var Bytes: TBytes);
begin
  if Length(Bytes) > 0 then FillChar(Bytes[0], Length(Bytes), 0);
  Bytes := nil;
end;

function U16(const Bytes: TBytes; At: UInt64): Word;
begin
  Require((At <= UInt64(Length(Bytes))) and
    (UInt64(Length(Bytes)) - At >= 2));
  Move(Bytes[NativeInt(At)], Result, SizeOf(Result));
end;

function U32(const Bytes: TBytes; At: UInt64): Cardinal;
begin
  Require((At <= UInt64(Length(Bytes))) and
    (UInt64(Length(Bytes)) - At >= 4));
  Move(Bytes[NativeInt(At)], Result, SizeOf(Result));
end;

function U64(const Bytes: TBytes; At: UInt64): UInt64;
begin
  Require((At <= UInt64(Length(Bytes))) and
    (UInt64(Length(Bytes)) - At >= 8));
  Move(Bytes[NativeInt(At)], Result, SizeOf(Result));
end;

{$PUSHOPT}
{$Q-}
{$R-}
function RelocatedOperand(Original, PreferredBase: UInt64;
  ActualBase: NativeUInt; Width: Integer): UInt64;
begin
  { PE base relocations intentionally use modulo 2^64 or 2^32 arithmetic. }
  Result := Original + UInt64(ActualBase) - PreferredBase;
  if Width = 4 then Result := Result and UInt64($FFFFFFFF);
end;
{$POPOPT}

{$PUSHOPT}{$STACKFRAMES ON}
function Digest(const Bytes: TBytes; SectionCount: Integer;
  const Budget: TMeasurementBudget): TCodeIntegrityMeasurement;
var Hasher: TIntegrityHasher; Hashes: TIntegrityHashResult;
  State: TCrcState; At, Take: Integer;
begin
  Result := Default(TCodeIntegrityMeasurement);
  Hasher := TIntegrityHasher.Create;
  try
    CrcInit(State, ckEcma182); At := 0;
    while At < Length(Bytes) do
    begin
      Take := Length(Bytes) - At; if Take > 65536 then Take := 65536;
      Budget.Check(UInt64(At), UInt64(Take));
      Hasher.Update(Bytes[At], Take); CrcUpdate(State, @Bytes[At], Take);
      Inc(At, Take);
    end;
    Budget.Check(UInt64(At), 0); Hashes := Hasher.Finish;
    Budget.Check(UInt64(At), 0);
    Result.Algorithm := CodeAlgorithm; Result.SHA512 := Hashes.SHA512;
    Result.CRC64 := CrcFinalHex(State); Result.XXH3_128 := Hashes.XXH3_128;
    Result.Blake3 := Hashes.Blake3; Result.Size := Hashes.Size;
    Result.Sections := SectionCount;
  finally Hasher.Free; end;
end;

function TCodeIntegrityMeasurement.ToJSON: TJSONObject;
begin
  Result := TJSONObject.Create;
  Result.AddPair(CozyText_CodeIntegrity_algorithm_9e87e55d, Algorithm);
  Result.AddPair(CozyText_CodeIntegrity_codeSha512_4bb1f02c, SHA512);
  Result.AddPair(CozyText_CodeIntegrity_codeCrc64_37a786ac, CRC64);
  Result.AddPair(CozyText_CodeIntegrity_codeXxh3_128_3a667fcc, XXH3_128);
  Result.AddPair(CozyText_CodeIntegrity_codeBlake3_11dc7232, Blake3);
  Result.AddPair(CozyText_CodeIntegrity_codeBytes_2dda197e, TJSONNumber.Create(Int64(Size)));
  Result.AddPair(CozyText_CodeIntegrity_codeSections_9a607d44, TJSONNumber.Create(Sections));
end;

procedure ReadMappedBytes(Module: HMODULE; ImageSize, RVA, Count: Cardinal;
  Destination: PByte; DestinationCapacity: NativeUInt; const Budget: TMeasurementBudget; RequireExecutable: Boolean = False;
  AllowWritableMetadata: Boolean = False);
var
  Address, Last, Next: NativeUInt;
  Region, AfterRegion: TNativeMemoryRegion;
  Chunk: NativeUInt;
  Protection: DWORD; Span: TApiBuffer; DestinationOffset: NativeUInt;
begin
  Span := TApiBuffer.Borrow(Destination, DestinationCapacity, True);
  Span.Write(0, Count); DestinationOffset := 0;
  Require((Module <> 0) and (UInt64(RVA) + Count <= ImageSize));
  Address := NativeUInt(Module) + RVA;
  Require(Address >= NativeUInt(Module));
  Last := Address + Count;
  Require(Last >= Address);
  try
  while Address < Last do
  begin
    Budget.Check(0, 0);
    FillChar(Region, SizeOf(Region), 0);
    Require(QueryMemory(Pointer(Address), Region, SizeOf(Region)) = SizeOf(Region));
    Protection := Region.Protect and $FF;
    Require((Region.State = MEM_COMMIT) and (Region.AllocationBase = Pointer(Module)) and
      (Region.Kind = MEM_IMAGE) and ((Region.Protect and PAGE_GUARD) = 0) and
      (Protection <> PAGE_NOACCESS) and (Protection <> PAGE_EXECUTE_READWRITE) and
      (Protection <> PAGE_EXECUTE_WRITECOPY));
    if AllowWritableMetadata then
      { Delphi places this const anchor in .data. Only the bounded metadata
        read opts in; its fields are checked against the retained file plan. }
      Require(not RequireExecutable and
        ((Protection = PAGE_READONLY) or (Protection = PAGE_READWRITE) or
         (Protection = PAGE_WRITECOPY)))
    else
      Require((Protection <> PAGE_READWRITE) and (Protection <> PAGE_WRITECOPY));
    if RequireExecutable then
      Require((Protection = PAGE_EXECUTE) or (Protection = PAGE_EXECUTE_READ));
    Require((NativeUInt(Region.BaseAddress) <= Address) and
      (Region.RegionSize <= High(NativeUInt) - NativeUInt(Region.BaseAddress)));
    Next := NativeUInt(Region.BaseAddress) + Region.RegionSize;
    Require(Next > Address);
    if Next > Last then Next := Last;
    if Next - Address > 65536 then Next := Address + 65536;
    Chunk := Next - Address;
    Budget.Check(UInt64(Address - NativeUInt(Module) - RVA), UInt64(Chunk));
    { Current process only. Move is a compiler/RTL memory primitive, not a
      process-reading API. Page metadata is a precondition, NOT an atomic lock:
      an unload/protection race can still fault and must fail this measurement. }
    try
      Move(PByte(Address)^, Span.Write(DestinationOffset, Chunk)^, Chunk);
    except
      on E: EAccessViolation do
        raise EMeasurement.Create(msReadError, CozyText_CodeIntegrity_MAPPED_READ_FAILED_f6c5a1a1);
    end;
    FillChar(AfterRegion, SizeOf(AfterRegion), 0);
    Require(QueryMemory(Pointer(Address), AfterRegion, SizeOf(AfterRegion)) =
      SizeOf(AfterRegion));
    Require((AfterRegion.BaseAddress = Region.BaseAddress) and
      (AfterRegion.AllocationBase = Region.AllocationBase) and
      (AfterRegion.RegionSize = Region.RegionSize) and
      (AfterRegion.State = Region.State) and
      (AfterRegion.Protect = Region.Protect) and
      (AfterRegion.Kind = Region.Kind));
    Budget.Check(UInt64(Address - NativeUInt(Module) - RVA), UInt64(Chunk));
    Span.Completed(Chunk, Chunk); Inc(DestinationOffset, Chunk);
    Address := Next;
  end;
  except
    { Never let partially copied bytes escape as a completed measurement. }
    if Count <> 0 then FillChar(Span.Write(0, Count)^, Count, 0);
    raise;
  end;
end;

{$POPOPT}

type
  TCrcCheckerAnchor = packed record
    Magic: array[0..15] of Byte;
    Version, Count: Cardinal;
    Targets: array[0..5] of Pointer;
  end;

{$PUSHOPT}{$J-}
const
  { This record is retained because its address/targets are checked at runtime.
    Pointer relocations bind named routines to their pristine PE .pdata entries.
    Delphi may place this const in writable .data. The server and client scan
    file-backed non-executable sections and reject a second marker. Live fields
    are compared to the retained file plan, never used to select code ranges.
    There is no guessed function length or client-selected RVA. }
  CrcCheckerAnchor: TCrcCheckerAnchor = (
    Magic: ($47,$43,$52,$43,$41,$4E,$43,$48,$03,$8D,$47,$91,$2A,$60,$B5,$EC);
    Version: 1; Count: 6;
    Targets: (@CrcUpdate, @Digest, @ReadMappedBytes, @CrcInit,
      @CrcBufferHex, @CrcCodePageManifest));
{$POPOPT}

function TCodeIntegrity.BuildStream(const FileBytes: TBytes;
  const RawOffsets, RawSizes: TArray<Cardinal>; FromMemory: Boolean; const Budget: TMeasurementBudget): TBytes;
var
  Count, I, J, CopyCount: Integer;
  Total: UInt64;
  At, StartAt: NativeInt;
  Value: Cardinal;
  Operand: UInt64;
begin
  Total := UInt64(Length(CodePrefix)) + 4;
  for I := 0 to High(FSections) do Inc(Total, UInt64(FSections[I].Span) + 8);
  Require(Total <= FMaximumCodeBytes + 96 * 8 + UInt64(Length(CodePrefix)) + 4);
  Budget.Check(0, Total);
  SetLength(Result, NativeInt(Total));
  try
    At := Length(CodePrefix);
    Move(CodePrefix[1], Result[0], At);
    Value := Cardinal(Length(FSections));
    Move(Value, Result[At], 4);
    Inc(At, 4);
    J := 0;
    for I := 0 to High(FSections) do
    begin
      Budget.Check(0, 0);
      Value := FSections[I].RVA;
      Move(Value, Result[At], 4);
      Inc(At, 4);
      Value := FSections[I].Span;
      Move(Value, Result[At], 4);
      Inc(At, 4);
      StartAt := At;
      Count := Integer(FSections[I].Span);
      if FromMemory then
        ReadMappedBytes(FModule, FImageSize, FSections[I].RVA,
          FSections[I].Span, @Result[At], NativeUInt(Length(Result) - At), Budget, FOwnImage)
      else
      begin
        Require((I < Length(RawOffsets)) and (I < Length(RawSizes)));
        CopyCount := Integer(RawSizes[I]);
        if CopyCount > Count then CopyCount := Count;
        Require(UInt64(RawOffsets[I]) + Cardinal(CopyCount) <= UInt64(Length(FileBytes)));
        if CopyCount > 0 then Move(FileBytes[RawOffsets[I]], Result[At], CopyCount);
        if CopyCount < Count then FillChar(Result[At + CopyCount], Count - CopyCount, 0);
      end;
      while (J < Length(FRelocations)) and
        (FRelocations[J].RVA < UInt64(FSections[I].RVA) + FSections[I].Span) do
      begin
        Budget.Check(0, 0);
        Require(FRelocations[J].RVA >= FSections[I].RVA);
        if FromMemory then
        begin
          Operand := 0;
          Move(Result[StartAt + FRelocations[J].RVA - FSections[I].RVA],
            Operand, FRelocations[J].Width);
          Require(Operand = FRelocations[J].ExpectedValue);
        end;
        FillChar(Result[StartAt + FRelocations[J].RVA - FSections[I].RVA],
          FRelocations[J].Width, 0);
        Inc(J);
      end;
      Inc(At, Count);
    end;
    Require((At = Length(Result)) and (J = Length(FRelocations)));
  except
    ClearBytes(Result);
    raise;
  end;
end;

function TCodeIntegrity.BuildExportStream(const FileBytes: TBytes;
  RawOffset: Cardinal; FromMemory: Boolean; const Budget: TMeasurementBudget): TBytes;
var
  At: NativeInt;
  Total: UInt64;
begin
{$IFDEF GAME_CRC_PE_PROBE}
  if FromMemory and FProbeFileMode then
    Exit(BuildExportStream(FProbeFileBytes, FProbeExportRaw, False, Budget));
{$ENDIF}
  Require(FExportTableReady and (FExportSize > 0) and
    (FExportSize <= MaximumExportBytes));
  Total := UInt64(Length(ExportPrefix)) + 4 + 8 + FExportSize;
  SetLength(Result, NativeInt(Total));
  try
    At := Length(ExportPrefix);
    Move(ExportPrefix[1], Result[0], At);
    Move(FExportDirectoryOffset, Result[At], 4);
    Inc(At, 4);
    if FromMemory then
    begin
      { Use the retained original directory address and extent. Neither live
        section headers nor a modified export pointer choose the scan range. }
      ReadMappedBytes(FModule, FImageSize, FExportDirectoryOffset, 8, @Result[At], NativeUInt(Length(Result) - At), Budget);
      Inc(At, 8);
      ReadMappedBytes(FModule, FImageSize, FExportRVA, FExportSize, @Result[At], NativeUInt(Length(Result) - At), Budget);
    end
    else
    begin
      Require((UInt64(FExportDirectoryOffset) + 8 <= UInt64(Length(FileBytes))) and
        (UInt64(RawOffset) + FExportSize <= UInt64(Length(FileBytes))));
      Move(FileBytes[FExportDirectoryOffset], Result[At], 8);
      Inc(At, 8);
      Move(FileBytes[RawOffset], Result[At], FExportSize);
    end;
  except
    ClearBytes(Result);
    raise;
  end;
end;

constructor TCodeIntegrity.Create(Handle: THandle; Module: HMODULE);
begin
  if Module = 0 then
    Create(Handle, Module, TMeasurementBudget.Start(MaximumFileBytes, 30000))
  else
    Create(Handle, Module, TMeasurementBudget.Start(InventoryPeFileLimit, 30000));
end;

constructor TCodeIntegrity.Create(Handle: THandle; Module: HMODULE;
  const Budget: TMeasurementBudget);
var
  FileBytes, Normalized: TBytes;
  FileSize: Int64;
  PE, Optional, OptionalSize, TableAt, HeaderSize, DirectoryCount: Cardinal;
  RelocRVA, RelocSize, Cursor, RelocEnd, BlockSize, Page, Target: Cardinal;
  SectionCount, I, J, K, At, ProtectedCount, Kind, Width: Integer;
  Entry: Word;
  CodeTotal, TargetEnd, OriginalOperand: UInt64;
  Sections: TArray<TFileSection>;
  TempSection: TFileSection;
  RawOffsets, RawSizes: TArray<Cardinal>;
  Slots: TList<TCodeRelocation>;
  Slot: TCodeRelocation;
  Found: Boolean;
  function RawAt(RVA, Count: Cardinal): Cardinal;
  var K: Integer;
  begin
    if (RVA < HeaderSize) and (UInt64(RVA) + Count <= HeaderSize) then Exit(RVA);
    for K := 0 to High(Sections) do
      if (RVA >= Sections[K].RVA) and
        (UInt64(RVA) + Count <= UInt64(Sections[K].RVA) + Sections[K].RawSize) then
        Exit(Sections[K].Raw + RVA - Sections[K].RVA);
    Require(False);
    Result := 0;
  end;
  procedure ValidateExceptionDirectory;
  var RVA, Size, Cursor, Limit, First, Last, Unwind, Previous: Cardinal;
    function Located(R, N: Cardinal; Code, Table: Boolean): Boolean;
    var Index: Integer; RawSpan: Cardinal;
    begin
      Result := False;
      for Index := 0 to High(Sections) do
      begin
        RawSpan := Sections[Index].RawSize;
        if RawSpan > Sections[Index].Span then RawSpan := Sections[Index].Span;
        if (R >= Sections[Index].RVA) and
          (UInt64(R) + N <= UInt64(Sections[Index].RVA) + RawSpan) then
        begin
          if Code then Exit((Sections[Index].Flags and $A0000000) = $20000000);
          if Table then Exit((Sections[Index].Flags and $A0000000) = 0);
          Exit((Sections[Index].Flags and $60000000) = $40000000);
        end;
      end;
    end;
  begin
    if DirectoryCount <= 3 then Exit;
    RVA := U32(FileBytes, Optional + 136); Size := U32(FileBytes, Optional + 140);
    if (RVA = 0) and (Size = 0) then Exit;
    Require((RVA <> 0) and ((RVA mod 4) = 0) and (Size <> 0) and
      ((Size mod 12) = 0) and (Size <= 16 * 1024 * 1024) and Located(RVA, Size, False, True));
    Cursor := RawAt(RVA, Size); Limit := Cursor + Size; Previous := 0;
    while Cursor < Limit do
    begin
      Budget.Check(0, UInt64(Length(FileBytes)));
      First := U32(FileBytes, Cursor); Last := U32(FileBytes, Cursor + 4);
      Unwind := U32(FileBytes, Cursor + 8); Inc(Cursor, 12);
      Require((Last > First) and (First >= Previous) and ((Unwind mod 4) = 0) and
        Located(First, Last - First, True, False) and Located(Unwind, 4, False, False));
      Previous := Last;
    end;
  end;
  procedure ReadExportCoverage;
  const
    MaximumExportEntries = 131072;
    MaximumExportStringBytes = 4096;
    MaximumExportStringWork = 16 * 1024 * 1024;
  var
    ExportAt, FunctionCount, FunctionTable, FunctionAt, FunctionRVA,
      NameCount, NameTable, OrdinalTable, NameAt, OrdinalAt, NameRVA: Cardinal;
    ExportEnd: UInt64;
    EntryIndex, SectionIndex: Integer;
    StringWork: Cardinal;
    ReadOnlySpan: Boolean;
    function WithinExport(RVA, Count: Cardinal): Cardinal;
    begin
      Require((RVA >= FExportRVA) and (UInt64(RVA) + Count <= ExportEnd));
      Result := RawAt(RVA, Count);
    end;
    procedure ExportString(RVA: Cardinal; Forwarder: Boolean);
    var Index: Integer; At: Cardinal; Character: Byte; Terminated: Boolean;
    begin
      Terminated := False;
      At := WithinExport(RVA, 1);
      { The whole export span was already validated as one file-backed range;
        avoid re-walking every section for every byte of each symbol name. }
      for Index := 0 to MaximumExportStringBytes - 1 do
      begin
        Require(UInt64(RVA) + Cardinal(Index) < ExportEnd);
        Require(UInt64(At) + Cardinal(Index) < UInt64(Length(FileBytes)));
        Inc(StringWork);
        Require(StringWork <= MaximumExportStringWork);
        if (Index and $FF) = 0 then Budget.Check(0, 0);
        Character := FileBytes[At + Cardinal(Index)];
        if Character = 0 then
        begin
          Require(Index > 0);
          Terminated := True;
          Break;
        end;
        Require((Character >= 32) and (Character <= 126));
        if Forwarder then Require(Character <> 32);
      end;
      Require(Terminated);
    end;
  begin
    StringWork := 0;
    FExportCoverage := Default(TCodeExportCoverage);
    FExportCoverage.ExecutableSections := Length(FSections);
    FExportCoverage.Status := CozyText_CodeIntegrity_NO_EXPORTS_69dffb13;
    FExportTableStatus := CozyText_CodeIntegrity_NO_EXPORTS_69dffb13;
    FExportTableReady := False;
    if DirectoryCount = 0 then Exit;
    FExportDirectoryOffset := Optional + 112;
    try
      FExportRVA := U32(FileBytes, FExportDirectoryOffset);
      FExportSize := U32(FileBytes, FExportDirectoryOffset + 4);
      Require((FExportRVA = 0) = (FExportSize = 0));
      if FExportRVA = 0 then Exit;
      ExportEnd := UInt64(FExportRVA) + FExportSize;
      Require((FExportSize >= 40) and (FExportSize <= MaximumExportBytes) and
        (ExportEnd <= FImageSize));
      ExportAt := RawAt(FExportRVA, FExportSize);
      ReadOnlySpan := False;
      for SectionIndex := 0 to High(Sections) do
        if (FExportRVA >= Sections[SectionIndex].RVA) and
          (ExportEnd <= UInt64(Sections[SectionIndex].RVA) + Sections[SectionIndex].Span) and
          ((Sections[SectionIndex].Flags and $80000000) = 0) then
        begin
          ReadOnlySpan := True;
          Break;
        end;
      Require(ReadOnlySpan);
      FunctionCount := U32(FileBytes, ExportAt + 20);
      NameCount := U32(FileBytes, ExportAt + 24);
      FunctionTable := U32(FileBytes, ExportAt + 28);
      NameTable := U32(FileBytes, ExportAt + 32);
      OrdinalTable := U32(FileBytes, ExportAt + 36);
      { Names are mapped through 16-bit ordinal indexes. Multiple names may
        address one function; validate each index, not names <= functions. }
      Require((FunctionCount <= MaximumExportEntries) and
        (NameCount <= MaximumExportEntries));
      ExportString(U32(FileBytes, ExportAt + 12), False);
      if FunctionCount > 0 then
      begin
        FunctionAt := WithinExport(FunctionTable, FunctionCount * 4);
        for EntryIndex := 0 to Integer(FunctionCount) - 1 do
        begin
          FunctionRVA := U32(FileBytes, UInt64(FunctionAt) + Cardinal(EntryIndex) * 4);
          { Zero entries are unused ordinals, not exported functions. }
          if FunctionRVA = 0 then Continue;
          Inc(FExportCoverage.ExportCount);
          if (FunctionRVA >= FExportRVA) and (UInt64(FunctionRVA) < ExportEnd) then
          begin
            ExportString(FunctionRVA, True);
            Inc(FExportCoverage.ForwardedExportCount);
          end
          else
          begin
            Require(FunctionRVA < FImageSize);
            { Exported data is counted but never called executable API code. }
            for SectionIndex := 0 to High(FSections) do
              if (FunctionRVA >= FSections[SectionIndex].RVA) and
                (UInt64(FunctionRVA) < UInt64(FSections[SectionIndex].RVA) +
                  FSections[SectionIndex].Span) then
              begin
                Inc(FExportCoverage.CodeExportCount);
                Break;
              end;
          end;
        end;
      end;
      if NameCount > 0 then
      begin
        NameAt := WithinExport(NameTable, NameCount * 4);
        OrdinalAt := WithinExport(OrdinalTable, NameCount * 2);
        for EntryIndex := 0 to Integer(NameCount) - 1 do
        begin
          NameRVA := U32(FileBytes, UInt64(NameAt) + Cardinal(EntryIndex) * 4);
          ExportString(NameRVA, False);
          Require(U16(FileBytes, UInt64(OrdinalAt) + Cardinal(EntryIndex) * 2) < FunctionCount);
        end;
      end;
      FExportCoverage.Status := CozyText_CodeIntegrity_SECTION_HASHED_4877d6d5;
      FExportTableReady := True;
      FExportTableStatus := CozyText_CodeIntegrity_MEASURED_5fea97ed;
    except
      on E: ECodeIntegrity do
      begin
        { An unsupported export layout does not erase valid code evidence.
          A strict required-module policy rejects this explicit status. }
        FExportCoverage.ExportCount := 0;
        FExportCoverage.CodeExportCount := 0;
        FExportCoverage.ForwardedExportCount := 0;
        FExportCoverage.Status := CozyText_CodeIntegrity_INVALID_EXPORT_TABLE_af4c32f0;
        FExportTableReady := False;
        FExportTableStatus := CozyText_CodeIntegrity_UNSUPPORTED_EXPORT_LAYOUT_5ab14cab;
      end;
    end;
  end;
  procedure ReadCheckerCoverage;
  var
    SectionIndex, TargetIndex, Role, RoleStart, RoleCount, R, N: Integer;
    AnchorAt, AnchorRVA, ScanAt, ScanEnd, MappedRaw, ExceptionRVA,
      ExceptionSize, ExceptionAt, ExceptionEnd, BeginRVA, EndRVA,
      UnwindRVA, PreviousEnd, RelocAt, RelocLimit, LocalRelocRVA,
      LocalRelocSize, LocalPage, LocalBlock, P, LocalTarget: Cardinal;
    PointerVA: UInt64;
    LocalEntry: Word;
    LocalKind, LocalWidth: Integer;
    Seen: array[0..5] of Boolean;
    Located: array[0..5] of TCodeSection;
    Valid: Boolean;
    Temp: TCodeSection;
    function CheckerFileRange(RVA, Size: Cardinal; Executable: Boolean;
      RequireNonExecutable: Boolean = False;
      AllowWritableMetadata: Boolean = False): Boolean;
    var S: Integer; RawSpan: Cardinal;
    begin
      Result := False;
      if Size = 0 then Exit;
      for S := 0 to High(Sections) do
      begin
        RawSpan := Sections[S].RawSize;
        if RawSpan > Sections[S].Span then RawSpan := Sections[S].Span;
        if (RVA >= Sections[S].RVA) and
          (UInt64(RVA) + Size <= UInt64(Sections[S].RVA) + RawSpan) and
          (((Sections[S].Flags and $80000000) = 0) or
            (AllowWritableMetadata and RequireNonExecutable and not Executable)) and
          (not AllowWritableMetadata or
            ((Sections[S].Flags and $60000000) = $40000000)) and
          (not Executable or ((Sections[S].Flags and $20000000) <> 0)) and
          (not RequireNonExecutable or ((Sections[S].Flags and $20000000) = 0)) then
          Exit(True);
      end;
    end;
  begin
    FCheckerAnchorRVA := 0;
    AnchorAt := 0; AnchorRVA := 0;
    for SectionIndex := 0 to High(Sections) do
      if (Sections[SectionIndex].Flags and $60000000) = $40000000 then
      begin
        MappedRaw := Sections[SectionIndex].RawSize;
        if MappedRaw > Sections[SectionIndex].Span then MappedRaw := Sections[SectionIndex].Span;
        ScanAt := Sections[SectionIndex].Raw;
        ScanEnd := ScanAt + MappedRaw;
        while UInt64(ScanAt) + 16 <= ScanEnd do
        begin
          if (ScanAt and $FFFF) = 0 then Budget.Check(0, UInt64(FileSize));
          if (FileBytes[ScanAt] = CrcCheckerAnchor.Magic[0]) and
            CompareMem(@FileBytes[ScanAt], @CrcCheckerAnchor.Magic[0], 16) then
          begin
            Require((AnchorAt = 0) and (UInt64(ScanAt) + SizeOf(TCrcCheckerAnchor) <= ScanEnd));
            AnchorAt := ScanAt;
            AnchorRVA := Sections[SectionIndex].RVA + ScanAt - Sections[SectionIndex].Raw;
          end;
          Inc(ScanAt);
        end;
      end;
    if AnchorAt = 0 then Exit;
    Require((U32(FileBytes, AnchorAt + 16) = 1) and (U32(FileBytes, AnchorAt + 20) = 6));
    Move(FileBytes[AnchorAt], FCheckerMagic[0], SizeOf(FCheckerMagic));
    for TargetIndex := 0 to 5 do
    begin
      PointerVA := U64(FileBytes, AnchorAt + 24 + Cardinal(TargetIndex) * 8);
      Require((PointerVA >= FPreferredImageBase) and
        (PointerVA - FPreferredImageBase < FImageSize));
      FCheckerTargets[TargetIndex] := Cardinal(PointerVA - FPreferredImageBase);
      Require(CheckerFileRange(FCheckerTargets[TargetIndex], 1, True));
      if FOwnImage then
        Require(NativeUInt(CrcCheckerAnchor.Targets[TargetIndex]) =
          NativeUInt(FModule) + FCheckerTargets[TargetIndex]);
    end;
    if FOwnImage then Require(NativeUInt(@CrcCheckerAnchor) = NativeUInt(FModule) + AnchorRVA);
    Require(DirectoryCount > 5);
    LocalRelocRVA := U32(FileBytes, Optional + 152);
    LocalRelocSize := U32(FileBytes, Optional + 156);
    Require((LocalRelocRVA <> 0) and (LocalRelocSize <> 0) and
      (LocalRelocSize <= 16 * 1024 * 1024) and
      CheckerFileRange(LocalRelocRVA, LocalRelocSize, False));
    RelocAt := RawAt(LocalRelocRVA, LocalRelocSize);
    RelocLimit := RelocAt + LocalRelocSize;
    FillChar(Seen, SizeOf(Seen), 0);
    while RelocAt < RelocLimit do
    begin
      Require(UInt64(RelocAt) + 8 <= RelocLimit);
      LocalPage := U32(FileBytes, RelocAt); LocalBlock := U32(FileBytes, RelocAt + 4);
      Require((LocalPage < FImageSize) and (LocalBlock >= 8) and
        ((LocalBlock mod 2) = 0) and (UInt64(RelocAt) + LocalBlock <= RelocLimit));
      P := RelocAt + 8;
      while P < RelocAt + LocalBlock do
      begin
        LocalEntry := U16(FileBytes, P); Inc(P, 2); LocalKind := LocalEntry shr 12;
        if LocalKind = 0 then Continue;
        LocalTarget := LocalPage + (LocalEntry and $FFF);
        LocalWidth := 1;
        if LocalKind = 10 then LocalWidth := 8 else if LocalKind = 3 then LocalWidth := 4;
        if (LocalTarget < UInt64(AnchorRVA) + 72) and
          (UInt64(LocalTarget) + Cardinal(LocalWidth) > UInt64(AnchorRVA) + 24) then
        begin
          Require((LocalKind = 10) and (LocalTarget >= AnchorRVA + 24) and
            (UInt64(LocalTarget) + 8 <= UInt64(AnchorRVA) + 72) and
            (((LocalTarget - AnchorRVA - 24) mod 8) = 0));
          TargetIndex := Integer((LocalTarget - AnchorRVA - 24) div 8);
          Require(not Seen[TargetIndex]); Seen[TargetIndex] := True;
        end;
      end;
      Inc(RelocAt, LocalBlock);
    end;
    for TargetIndex := 0 to 5 do Require(Seen[TargetIndex]);
    FCheckerAnchorRVA := AnchorRVA;
    ExceptionRVA := U32(FileBytes, Optional + 136);
    ExceptionSize := U32(FileBytes, Optional + 140);
    if (ExceptionRVA = 0) and (ExceptionSize = 0) then Exit;
    Require((ExceptionRVA <> 0) and ((ExceptionRVA mod 4) = 0) and (ExceptionSize <> 0) and
      ((ExceptionSize mod 12) = 0) and (ExceptionSize <= 16 * 1024 * 1024) and
      CheckerFileRange(ExceptionRVA, ExceptionSize, False, True));
    ExceptionAt := RawAt(ExceptionRVA, ExceptionSize);
    ExceptionEnd := ExceptionAt + ExceptionSize; PreviousEnd := 0;
    FillChar(Located, SizeOf(Located), 0);
    while ExceptionAt < ExceptionEnd do
    begin
      BeginRVA := U32(FileBytes, ExceptionAt); EndRVA := U32(FileBytes, ExceptionAt + 4);
      UnwindRVA := U32(FileBytes, ExceptionAt + 8); Inc(ExceptionAt, 12);
      Require((EndRVA > BeginRVA) and (BeginRVA >= PreviousEnd));
      Require(CheckerFileRange(BeginRVA, EndRVA - BeginRVA, True) and
        { Unwind records are parsed from the verified file, not live .data. }
        ((UnwindRVA mod 4) = 0) and CheckerFileRange(UnwindRVA, 4, False, True, True));
      PreviousEnd := EndRVA;
      for TargetIndex := 0 to 5 do
        if (FCheckerTargets[TargetIndex] >= BeginRVA) and (FCheckerTargets[TargetIndex] < EndRVA) then
        begin
          Located[TargetIndex].RVA := BeginRVA;
          Located[TargetIndex].Span := EndRVA - BeginRVA;
        end;
    end;
    for Role := 0 to 2 do
    begin
      RoleStart := 0; RoleCount := 1;
      if Role = 1 then begin RoleStart := 1; RoleCount := 2; end;
      if Role = 2 then begin RoleStart := 3; RoleCount := 3; end;
      Valid := True;
      for TargetIndex := RoleStart to RoleStart + RoleCount - 1 do
        if Located[TargetIndex].Span = 0 then Valid := False;
      if not Valid then Continue;
      SetLength(FCheckerRanges[Role], RoleCount);
      for R := 0 to RoleCount - 1 do FCheckerRanges[Role][R] := Located[RoleStart + R];
      for R := 1 to RoleCount - 1 do
      begin
        Temp := FCheckerRanges[Role][R]; N := R - 1;
        while (N >= 0) and (FCheckerRanges[Role][N].RVA > Temp.RVA) do
        begin FCheckerRanges[Role][N + 1] := FCheckerRanges[Role][N]; Dec(N); end;
        FCheckerRanges[Role][N + 1] := Temp;
      end;
      N := 0;
      for R := 0 to RoleCount - 1 do
        if (N = 0) or (FCheckerRanges[Role][R].RVA <> FCheckerRanges[Role][N - 1].RVA) then
        begin FCheckerRanges[Role][N] := FCheckerRanges[Role][R]; Inc(N); end;
      SetLength(FCheckerRanges[Role], N);
    end;
  end;

begin
  inherited Create;
  FGate := TGameCallGate.Create;
  FOwnImage := Module = 0;
  if FOwnImage then
  begin
    FMaximumFileBytes := OwnPeFileLimit;
    FMaximumImageBytes := OwnPeImageLimit;
    FMaximumCodeBytes := OwnPeCodeLimit;
  end
  else
  begin
    FMaximumFileBytes := InventoryPeFileLimit;
    FMaximumImageBytes := InventoryPeImageLimit;
    FMaximumCodeBytes := InventoryPeCodeLimit;
  end;
  FModule := Module;
  if FModule = 0 then FModule := GetModuleHandle(nil);
  Require((Handle <> 0) and (Handle <> INVALID_HANDLE_VALUE) and (FModule <> 0));
  { The reader, PE plan and header plan use the same resource profile.
    Do not restart the caller's absolute deadline between these phases. }
  FileBytes := ReadMeasurementBytesBounded(Handle, Budget, FMaximumFileBytes);
  FileSize := Length(FileBytes);
  Require((FileSize >= 512) and (UInt64(FileSize) <= FMaximumFileBytes));
  Budget.Check(0, UInt64(FileSize));
  Slots := TList<TCodeRelocation>.Create;
  try
    Require(U16(FileBytes, 0) = $5A4D);
    PE := U32(FileBytes, $3C);
    Require((PE >= 64) and (UInt64(PE) + 24 <= UInt64(Length(FileBytes))) and
      (U32(FileBytes, PE) = $4550) and (U16(FileBytes, PE + 4) = $8664));
    SectionCount := U16(FileBytes, PE + 6);
    Optional := PE + 24;
    OptionalSize := U16(FileBytes, PE + 20);
    TableAt := Optional + OptionalSize;
    Require((SectionCount >= 1) and (SectionCount <= 96) and (OptionalSize >= 160) and
      (UInt64(TableAt) + UInt64(SectionCount) * 40 <= UInt64(Length(FileBytes))) and
      (U16(FileBytes, Optional) = $20B));
    FPreferredImageBase := U64(FileBytes, Optional + 24);
    FImageSize := U32(FileBytes, Optional + 56);
    HeaderSize := U32(FileBytes, Optional + 60);
    DirectoryCount := U32(FileBytes, Optional + 108);
    Require((FImageSize >= 4096) and (UInt64(FImageSize) <= FMaximumImageBytes) and
      (HeaderSize >= TableAt + Cardinal(SectionCount) * 40) and
      (HeaderSize <= Cardinal(Length(FileBytes))) and (DirectoryCount <= 16) and
      (112 + DirectoryCount * 8 <= OptionalSize));
    SetLength(Sections, SectionCount);
    CodeTotal := 0;
    ProtectedCount := 0;
    for I := 0 to SectionCount - 1 do
    begin
      At := Integer(TableAt) + I * 40;
      Sections[I].Span := U32(FileBytes, At + 8);
      Sections[I].RVA := U32(FileBytes, At + 12);
      Sections[I].RawSize := U32(FileBytes, At + 16);
      Sections[I].Raw := U32(FileBytes, At + 20);
      Sections[I].Flags := U32(FileBytes, At + 36);
      if Sections[I].Span = 0 then Sections[I].Span := Sections[I].RawSize;
      Sections[I].Mapped := Sections[I].Span;
      if Sections[I].RawSize > Sections[I].Mapped then Sections[I].Mapped := Sections[I].RawSize;
      Require((Sections[I].Span > 0) and (Sections[I].RVA >= HeaderSize) and
        (UInt64(Sections[I].RVA) + Sections[I].Mapped <= FImageSize));
      if Sections[I].RawSize > 0 then
        Require((Sections[I].Raw >= HeaderSize) and
          (UInt64(Sections[I].Raw) + Sections[I].RawSize <= UInt64(Length(FileBytes))));
      for J := 0 to I - 1 do
      begin
        Require(not ((Sections[I].RVA < UInt64(Sections[J].RVA) + Sections[J].Mapped) and
          (UInt64(Sections[I].RVA) + Sections[I].Mapped > Sections[J].RVA)));
        if (Sections[I].RawSize > 0) and (Sections[J].RawSize > 0) then
          Require(not ((Sections[I].Raw < UInt64(Sections[J].Raw) + Sections[J].RawSize) and
            (UInt64(Sections[I].Raw) + Sections[I].RawSize > Sections[J].Raw)));
      end;
      Sections[I].ProtectedCode := ((Sections[I].Flags and $20000000) <> 0) and
        ((Sections[I].Flags and $80000000) = 0);
      if Sections[I].ProtectedCode then
      begin
        Inc(CodeTotal, Sections[I].Span);
        Inc(ProtectedCount);
        Require(CodeTotal <= FMaximumCodeBytes);
      end;
    end;
    Require(ProtectedCount > 0);
    { Stable bounded insertion sort avoids platform comparer dependencies. }
    for I := 1 to High(Sections) do
    begin
      TempSection := Sections[I];
      J := I - 1;
      while (J >= 0) and (Sections[J].RVA > TempSection.RVA) do
      begin
        Sections[J + 1] := Sections[J];
        Dec(J);
      end;
      Sections[J + 1] := TempSection;
    end;
    SetLength(FSections, ProtectedCount);
    SetLength(RawOffsets, ProtectedCount);
    SetLength(RawSizes, ProtectedCount);
    J := 0;
    for I := 0 to High(Sections) do
      if Sections[I].ProtectedCode then
      begin
        FSections[J].RVA := Sections[I].RVA;
        FSections[J].Span := Sections[I].Span;
        RawOffsets[J] := Sections[I].Raw;
        RawSizes[J] := Sections[I].RawSize;
        Inc(J);
      end;
    ValidateExceptionDirectory;
    ReadExportCoverage;
    ReadCheckerCoverage;
    RelocRVA := 0;
    RelocSize := 0;
    if DirectoryCount > 5 then
    begin
      RelocRVA := U32(FileBytes, Optional + 152);
      RelocSize := U32(FileBytes, Optional + 156);
    end;
    Require(((RelocRVA = 0) = (RelocSize = 0)) and (RelocSize <= 16 * 1024 * 1024));
    if RelocSize > 0 then
    begin
      { The export baseline format intentionally supports section-backed
        relocation directories only. Code normalization remains independent. }
      if FExportTableReady and (RelocRVA < HeaderSize) then
      begin
        FExportTableReady := False;
        FExportTableStatus := CozyText_CodeIntegrity_UNSUPPORTED_EXPORT_LAYOUT_5ab14cab;
      end;
      Cursor := RawAt(RelocRVA, RelocSize);
      RelocEnd := Cursor + RelocSize;
      Require(RelocEnd <= Cardinal(Length(FileBytes)));
      while Cursor < RelocEnd do
      begin
        Budget.Check(0, UInt64(FileSize));
        Require(UInt64(Cursor) + 8 <= RelocEnd);
        Page := U32(FileBytes, Cursor);
        BlockSize := U32(FileBytes, Cursor + 4);
        Require((BlockSize >= 8) and ((BlockSize mod 2) = 0) and
          (UInt64(Cursor) + BlockSize <= RelocEnd) and (Page < FImageSize));
        At := Integer(Cursor) + 8;
        while At < Integer(Cursor + BlockSize) do
        begin
          Entry := U16(FileBytes, At);
          Kind := Entry shr 12;
          Target := Page + (Entry and $FFF);
          Inc(At, 2);
          if Kind = 0 then Continue;
          Width := 1;
          if Kind = 10 then Width := 8
          else if Kind = 3 then Width := 4;
          TargetEnd := UInt64(Target) + Cardinal(Width);
          { Export RVAs/strings are loader-invariant. An overlapping relocation
            makes this bounded export layout unsupported, never normalized. }
          if FExportTableReady and
            (Target < UInt64(FExportRVA) + FExportSize) and (TargetEnd > FExportRVA) then
          begin
            FExportTableReady := False;
            FExportTableStatus := CozyText_CodeIntegrity_UNSUPPORTED_EXPORT_LAYOUT_5ab14cab;
          end;
          Found := False;
          for J := 0 to High(FSections) do
            if (Target < UInt64(FSections[J].RVA) + FSections[J].Span) and
              (TargetEnd > FSections[J].RVA) then
            begin
              Require(((Kind = 10) or (Kind = 3)) and
                (Target >= FSections[J].RVA) and
                (TargetEnd <= UInt64(FSections[J].RVA) + FSections[J].Span));
              Found := True;
              Break;
            end;
          if not Found then Continue;
          Slot.RVA := Target;
          Slot.Width := Width;
          OriginalOperand := 0;
          { A base relocation can point into virtual zero fill. Mirror the
            loader's raw-byte/zero-fill mapping before applying ASLR. }
          for K := 0 to Width - 1 do
            if UInt64(Target - FSections[J].RVA) + Cardinal(K) < RawSizes[J] then
              OriginalOperand := OriginalOperand or
                (UInt64(FileBytes[RawOffsets[J] + Target - FSections[J].RVA + Cardinal(K)]) shl (K * 8));
          Slot.ExpectedValue := RelocatedOperand(OriginalOperand,
            FPreferredImageBase, NativeUInt(FModule), Width);
          Slots.Add(Slot);
          Require(Slots.Count <= 1000000);
        end;
        Inc(Cursor, BlockSize);
      end;
    end;
    Slots.Sort(TComparer<TCodeRelocation>.Construct(
      function(const Left, Right: TCodeRelocation): Integer
      begin
        if Left.RVA < Right.RVA then Result := -1
        else if Left.RVA > Right.RVA then Result := 1
        else Result := 0;
      end));
    for I := 1 to Slots.Count - 1 do
      Require(UInt64(Slots[I - 1].RVA) + Cardinal(Slots[I - 1].Width) <= Slots[I].RVA);
    FRelocations := Slots.ToArray;
    Normalized := BuildStream(FileBytes, RawOffsets, RawSizes, False, Budget);
    FFileMeasurement := Digest(Normalized, Length(FSections), Budget);
    { The verified disk image is the sole origin of each page baseline. A live
      image cannot silently replace it. The full code digest remains required. }
    FFilePageSHA512 := CodePageSHA512Manifest(Normalized, CrcBudgetCheckpoint, @Budget);
    if FExportTableReady then
    begin
      ClearBytes(Normalized);
      Normalized := BuildExportStream(FileBytes, RawAt(FExportRVA, FExportSize), False, Budget);
      FFileExportMeasurement := Digest(Normalized, 0, Budget);
      FFileExportMeasurement.Algorithm := ExportAlgorithm;
    end;
    if FOwnImage then FOwnHeaderPlan.Initialize(FileBytes)
    else FOwnHeaderPlan.InitializeBounded(FileBytes,
      FMaximumFileBytes, FMaximumImageBytes);
{$IFDEF GAME_CRC_PE_PROBE}
    FProbeFileBytes := Copy(FileBytes, 0, Length(FileBytes));
    FProbeCodeBytes := BuildStream(FileBytes, RawOffsets, RawSizes, False, Budget);
    if FExportTableReady then FProbeExportRaw := RawAt(FExportRVA, FExportSize);
{$ENDIF}
    Budget.Check(0, UInt64(FileSize));
  finally
    Slots.Free;
    ClearBytes(FileBytes);
    ClearBytes(Normalized);
  end;
end;

procedure TCodeIntegrity.VerifyCodePages(const Code: TBytes;
  const Budget: TMeasurementBudget);
var Actual: TBytes;
begin
  Require(Length(FFilePageSHA512) > 0);
  Actual := CodePageSHA512Manifest(Code, CrcBudgetCheckpoint, @Budget);
  try
    Budget.Check(0, 0);
    if (Length(Actual) <> Length(FFilePageSHA512)) or
      not CompareMem(@Actual[0], @FFilePageSHA512[0], Length(Actual)) then
      raise EMeasurement.Create(msChanged, CozyText_CodeIntegrity_OWN_CODE_PAGE_SHA512_CHANGED_2a5f9076);
  finally ClearBytes(Actual); end;
end;

procedure TCodeIntegrity.VerifyOwnHeaders(const Budget: TMeasurementBudget);
var
  Index: Integer;
  Count: Cardinal;
  Actual: array[0..127] of Byte;
begin
  if not FOwnImage then Exit;
  Require(FOwnHeaderPlan.IsReady and (FOwnHeaderPlan.ImageSize = FImageSize));
  try
    for Index := 0 to FOwnHeaderPlan.RangeCount - 1 do
    begin
      Count := FOwnHeaderPlan.RangeSize(Index);
      Require((Count > 0) and (Count <= SizeOf(Actual)));
      ReadMappedBytes(FModule, FImageSize, FOwnHeaderPlan.RangeOffset(Index),
        Count, @Actual[0], SizeOf(Actual), Budget);
      if not FOwnHeaderPlan.RangeMatches(Index, @Actual[0], Count) then
        raise ECodeIntegrity.Create(CozyText_CodeIntegrity_Executable_image_layout_changed_94e093a1);
    end;
  finally
    FillChar(Actual, SizeOf(Actual), 0);
  end;
end;

function TCodeIntegrity.BuildCrcHeaderStream(const Budget: TMeasurementBudget): TBytes;
var I, At: Integer; Offset, Count: Cardinal;
begin
  Require(FOwnHeaderPlan.IsReady);
  SetLength(Result, Integer(FOwnHeaderPlan.ComparedBytes) + FOwnHeaderPlan.RangeCount * 8);
  At := 0;
  try
    for I := 0 to FOwnHeaderPlan.RangeCount - 1 do
    begin
      Budget.Check(0, 0);
      Offset := FOwnHeaderPlan.RangeOffset(I);
      Count := FOwnHeaderPlan.RangeSize(I);
      Move(Offset, Result[At], 4); Inc(At, 4);
      Move(Count, Result[At], 4); Inc(At, 4);
{$IFDEF GAME_CRC_PE_PROBE}
      if FProbeFileMode then
      begin
        Require(UInt64(Offset) + Count <= UInt64(Length(FProbeFileBytes)));
        Move(FProbeFileBytes[Offset], Result[At], Count);
      end
      else
{$ENDIF}
        ReadMappedBytes(FModule, FImageSize, Offset, Count, @Result[At], NativeUInt(Length(Result) - At), Budget);
      Require(FOwnHeaderPlan.RangeMatches(I, @Result[At], Count));
      Inc(At, Integer(Count));
    end;
    Require(At = Length(Result));
  except
    ClearBytes(Result);
    raise;
  end;
end;

function TCodeIntegrity.BuildCheckerStream(Role: Integer; const Code: TBytes; const Budget: TMeasurementBudget): TBytes;
const Prefix: AnsiString = CozyText_CodeIntegrity_CRC_CHECKERS_V1_6dd8f3d3;
var I, J, At, CodeAt, SourceAt, Total: Integer; Count, Value: Cardinal;
    Anchor: TCrcCheckerAnchor; Found: Boolean;
begin
  Result := nil;
  Require((Role >= 0) and (Role <= 2));
  if Length(FCheckerRanges[Role]) = 0 then Exit;
  Require(FCheckerAnchorRVA <> 0);
{$IFDEF GAME_CRC_PE_PROBE}
  if not FProbeFileMode then
{$ENDIF}
  begin
    ReadMappedBytes(FModule, FImageSize, FCheckerAnchorRVA, SizeOf(Anchor),
      @Anchor, SizeOf(Anchor), Budget, False, True);
    Require(CompareMem(@Anchor.Magic[0], @FCheckerMagic[0], SizeOf(FCheckerMagic)) and
      (Anchor.Version = 1) and (Anchor.Count = 6));
    for I := 0 to 5 do Require(NativeUInt(Anchor.Targets[I]) = NativeUInt(FModule) + FCheckerTargets[I]);
  end;
  Total := Length(Prefix) + 4;
  for I := 0 to High(FCheckerRanges[Role]) do
  begin
    Require(FCheckerRanges[Role][I].Span <= MaximumCodeBytes);
    Inc(Total, 8 + Integer(FCheckerRanges[Role][I].Span));
    Require(Total <= MaximumCodeBytes + 4096);
  end;
  SetLength(Result, Total);
  try
    Move(Prefix[1], Result[0], Length(Prefix)); At := Length(Prefix);
    Count := Length(FCheckerRanges[Role]); Move(Count, Result[At], 4); Inc(At, 4);
    for I := 0 to High(FCheckerRanges[Role]) do
    begin
      Budget.Check(0, 0);
      Value := FCheckerRanges[Role][I].RVA; Move(Value, Result[At], 4); Inc(At, 4);
      Count := FCheckerRanges[Role][I].Span; Move(Count, Result[At], 4); Inc(At, 4);
      CodeAt := Length(CodePrefix) + 4; Found := False;
      for J := 0 to High(FSections) do
      begin
        Inc(CodeAt, 8);
        if (Value >= FSections[J].RVA) and
          (UInt64(Value) + Count <= UInt64(FSections[J].RVA) + FSections[J].Span) then
        begin
          SourceAt := CodeAt + Integer(Value - FSections[J].RVA);
          Require(UInt64(SourceAt) + Count <= UInt64(Length(Code)));
          Move(Code[SourceAt], Result[At], Count); Found := True; Break;
        end;
        Inc(CodeAt, Integer(FSections[J].Span));
      end;
      Require(Found); Inc(At, Integer(Count));
    end;
    Require(At = Length(Result));
  except
    ClearBytes(Result); raise;
  end;
end;

procedure TCodeIntegrity.UpdateCheckerCrc(Role: Integer; const Code: TBytes;
  const Budget: TMeasurementBudget; var State: TCrcState);
const Prefix: AnsiString = CozyText_CodeIntegrity_CRC_CHECKERS_V1_6dd8f3d3;
var I, J, CodeAt, SourceAt: Integer; Count, Value: Cardinal;
  Anchor: TCrcCheckerAnchor; Found: Boolean; Total: UInt64;
  procedure Feed(Buffer: Pointer; Size: Cardinal);
  var P: PByte; Take: Cardinal;
  begin
    P := PByte(Buffer);
    while Size <> 0 do
    begin
      Take := Size; if Take > 65536 then Take := 65536;
      Budget.Check(0, Take); CrcUpdate(State, P, Take);
      Inc(P, Take); Dec(Size, Take);
    end;
  end;
begin
  Require((Role >= 0) and (Role <= 2));
  Require(Length(FCheckerRanges[Role]) <> 0);
  Require(FCheckerAnchorRVA <> 0);
{$IFDEF GAME_CRC_PE_PROBE}
  if not FProbeFileMode then
{$ENDIF}
  begin
    ReadMappedBytes(FModule, FImageSize, FCheckerAnchorRVA, SizeOf(Anchor),
      @Anchor, SizeOf(Anchor), Budget, False, True);
    Require(CompareMem(@Anchor.Magic[0], @FCheckerMagic[0], SizeOf(FCheckerMagic)) and
      (Anchor.Version = 1) and (Anchor.Count = 6));
    for I := 0 to 5 do Require(NativeUInt(Anchor.Targets[I]) = NativeUInt(FModule) + FCheckerTargets[I]);
  end;
  Total := Length(Prefix) + 4;
  for I := 0 to High(FCheckerRanges[Role]) do
  begin
    Inc(Total, UInt64(FCheckerRanges[Role][I].Span) + 8);
    Require(Total <= MaximumCodeBytes + 4096);
  end;
  Feed(@Prefix[1], Length(Prefix));
  Count := Length(FCheckerRanges[Role]); Feed(@Count, 4);
  for I := 0 to High(FCheckerRanges[Role]) do
  begin
    Budget.Check(0, 0);
    Value := FCheckerRanges[Role][I].RVA; Count := FCheckerRanges[Role][I].Span;
    Feed(@Value, 4); Feed(@Count, 4);
    CodeAt := Length(CodePrefix) + 4; Found := False;
    for J := 0 to High(FSections) do
    begin
      Inc(CodeAt, 8);
      if (Value >= FSections[J].RVA) and
        (UInt64(Value) + Count <= UInt64(FSections[J].RVA) + FSections[J].Span) then
      begin
        SourceAt := CodeAt + Integer(Value - FSections[J].RVA);
        Require(UInt64(SourceAt) + Count <= UInt64(Length(Code)));
        Feed(@Code[SourceAt], Count); Found := True; Break;
      end;
      Inc(CodeAt, Integer(FSections[J].Span));
    end;
    Require(Found);
  end;
end;

procedure TCodeIntegrity.BuildCrcLayerInput(Index: Integer; const Code: TBytes;
  const Budget: TMeasurementBudget; out First, Second: TBytes);
var Extra, Headers, ExportBytes: TBytes; ParameterBytes: Integer;
begin
  First := nil; Second := nil;
  Require((Index >= 0) and (Index <= 8));
  try
    case Index of
      0: First := Copy(Code, 0, Length(Code));
      1: begin
        First := BuildCheckerStream(0, Code, Budget);
        Second := CrcTableBytes(ckEcma182);
      end;
      2: First := BuildCheckerStream(1, Code, Budget);
      3: begin
        First := BuildCrcHeaderStream(Budget);
        if FExportTableReady then Second := BuildExportStream(nil, 0, True, Budget);
      end;
      4: begin
        First := CrcAllTableBytes;
        Second := CrcParameterBytes;
        Extra := TEncoding.ASCII.GetBytes(FFileMeasurement.SHA512);
        Require(Length(Extra) = 128);
        ParameterBytes := Length(Second);
        SetLength(Second, ParameterBytes + Length(Extra));
        Move(Extra[0], Second[ParameterBytes], Length(Extra));
      end;
      5: First := BuildCheckerStream(2, Code, Budget);
      6: First := CrcCodePageManifest(Code, CrcBudgetCheckpoint, @Budget);
      7: First := CrcParameterBytes;
      8: begin
        Headers := BuildCrcHeaderStream(Budget);
        if FExportTableReady then ExportBytes := BuildExportStream(nil, 0, True, Budget);
        First := CrcLayoutState(Length(Code), Length(Headers), Length(ExportBytes));
      end;
    end;
  finally
    ClearBytes(Extra); ClearBytes(Headers); ClearBytes(ExportBytes);
  end;
end;

function TCodeIntegrity.MeasureCrcLayersCore(const Code: TBytes;
  const Budget: TMeasurementBudget): TJSONObject;
const Names: array[0..8] of string = (CozyText_CodeIntegrity_ecma182_45fdae3c,CozyText_CodeIntegrity_nvme_ad089a8c,CozyText_CodeIntegrity_jones_51b1b0ef,CozyText_CodeIntegrity_xz_92e6960f,CozyText_CodeIntegrity_we_a0818638,CozyText_CodeIntegrity_iso_42a71d65,CozyText_CodeIntegrity_crc32c_7efbc912,CozyText_CodeIntegrity_crc16_arc_9c838918,CozyText_CodeIntegrity_crc8_smbus_ca629586);
  Roles: array[0..8] of string = (CozyText_CodeIntegrity_normalized_code_0bf75e0e,CozyText_CodeIntegrity_ecma_checker_and_table_b27ea341,
    CozyText_CodeIntegrity_integrity_routine_code_3b12460c,CozyText_CodeIntegrity_header_ranges_and_export_d4c64b3f,CozyText_CodeIntegrity_crc_tables_parameters_and_baseline_ffc8bbfc,
    CozyText_CodeIntegrity_auxiliary_checker_code_bb68a67f,CozyText_CodeIntegrity_rva_aligned_code_pages_67a306de,CozyText_CodeIntegrity_crc_parameters_5b0bc0c2,CozyText_CodeIntegrity_layout_state_8f6272ab);
var First, Second: TBytes;
  Index: Integer; Item: TJSONObject; State: TCrcState; PageDigest: TCodeIntegrityMeasurement;
  procedure Update(const Bytes: TBytes);
  var At, Take: Integer;
  begin
    At := 0;
    while At < Length(Bytes) do
    begin
      Take := Length(Bytes) - At; if Take > 65536 then Take := 65536;
      Budget.Check(UInt64(At), UInt64(Take));
      CrcUpdate(State, @Bytes[At], Take); Inc(At, Take);
    end;
  end;
  procedure FailRole(Error: Exception);
  begin
    { Preserve all completed independent roles, with no exception text, path,
      pointer or stale digest. The server always rejects failed coverage. }
    Item.Free; Item := TJSONObject.Create;
    Item.AddPair(CozyText_CodeIntegrity_algorithm_9e87e55d, CrcKindName(TCrcKind(Index)));
    Item.AddPair(CozyText_CodeIntegrity_role_00b4bc31, Roles[Index]); Item.AddPair(CozyText_CodeIntegrity_status_af176b51, CozyText_CodeIntegrity_failed_c837c42b);
    Item.AddPair(CozyText_CodeIntegrity_reason_72c1f12f, MeasurementStatusName(MeasurementFailureStatus(Error)));
  end;
begin
  Result := TJSONObject.Create; Item := nil;
  try
    Result.AddPair(CozyText_CodeIntegrity_version_04ec885e, CozyText_CodeIntegrity_CRC_LAYERS_V1_86f28503);
    for Index := 0 to 8 do
    begin
      Item := TJSONObject.Create;
      try
        Item.AddPair(CozyText_CodeIntegrity_algorithm_9e87e55d, CrcKindName(TCrcKind(Index)));
        Item.AddPair(CozyText_CodeIntegrity_role_00b4bc31, Roles[Index]);
        try
          Budget.Check(0, 0);
          First := nil; Second := nil;
          case Index of
            0, 2, 5: ; { Stream directly below; do not duplicate code bytes. }
            1: Second := CrcTableBytes(ckEcma182);
          else BuildCrcLayerInput(Index, Code, Budget, First, Second);
          end;
          if ((Index = 2) and (Length(FCheckerRanges[1]) = 0)) or
            ((Index = 5) and (Length(FCheckerRanges[2]) = 0)) then
          begin
            Item.AddPair(CozyText_CodeIntegrity_status_af176b51, CozyText_CodeIntegrity_unavailable_0738e8a7); Item.AddPair(CozyText_CodeIntegrity_reason_72c1f12f, CozyText_CodeIntegrity_CHECKER_RANGES_REQUIRED_bfda29b8);
          end
          else
          begin
            if (Index = 1) and (Length(FCheckerRanges[0]) = 0) then
            begin
              Item.RemovePair(CozyText_CodeIntegrity_role_00b4bc31).Free; Item.AddPair(CozyText_CodeIntegrity_role_00b4bc31, CozyText_CodeIntegrity_ecma_lookup_table_c95d5a3f);
              Item.AddPair(CozyText_CodeIntegrity_status_af176b51, CozyText_CodeIntegrity_partial_ffbdaa25); Item.AddPair(CozyText_CodeIntegrity_reason_72c1f12f, CozyText_CodeIntegrity_CHECKER_RANGES_REQUIRED_bfda29b8);
            end
            else Item.AddPair(CozyText_CodeIntegrity_status_af176b51, CozyText_CodeIntegrity_measured_f1a110aa);
            if Index = 6 then
            begin
              PageDigest := Digest(First, 0, Budget);
              Item.AddPair(CozyText_CodeIntegrity_digest_be4bdba4, PageDigest.SHA512);
              Item.AddPair(CozyText_CodeIntegrity_digestAlgorithm_8dbc0ae4, CozyText_CodeIntegrity_SHA_512_PAGE_MANIFEST_0cda3b7b);
              Item.AddPair(CozyText_CodeIntegrity_pageSize_fd6eae72, TJSONNumber.Create(4096));
              Item.AddPair(CozyText_CodeIntegrity_pages_7b31319a, TJSONNumber.Create(Int64(U32(First, 17))));
              Item.AddPair(CozyText_CodeIntegrity_bytes_7bd6da7e, TJSONNumber.Create(Length(First)));
            end
            else
            begin
              CrcInit(State, TCrcKind(Index));
              case Index of
                0: Update(Code);
                1: if Length(FCheckerRanges[0]) <> 0 then
                     UpdateCheckerCrc(0, Code, Budget, State);
                2: UpdateCheckerCrc(1, Code, Budget, State);
                5: UpdateCheckerCrc(2, Code, Budget, State);
              else Update(First);
              end;
              Update(Second);
              Item.AddPair(CozyText_CodeIntegrity_digest_be4bdba4, CrcFinalHex(State));
              Item.AddPair(CozyText_CodeIntegrity_bytes_7bd6da7e, TJSONNumber.Create(Int64(State.Bytes)));
            end;
          end;
        except on E: Exception do FailRole(E); end;
        Result.AddPair(Names[Index], Item); Item := nil;
      finally
        Item.Free; Item := nil;
        ClearBytes(First); ClearBytes(Second);
      end;
    end;
  except Result.Free; raise; end;
end;

function TCodeIntegrity.MeasureNowCore(const Budget: TMeasurementBudget): TCodeIntegrityMeasurement;
var Bytes: TBytes; Empty: TArray<Cardinal>;
begin
  VerifyOwnHeaders(Budget);
  Empty := nil;
  Bytes := BuildStream(nil, Empty, Empty, True, Budget);
  try
    VerifyCodePages(Bytes, Budget);
    Result := Digest(Bytes, Length(FSections), Budget);
    VerifyOwnHeaders(Budget);
  finally
    ClearBytes(Bytes);
  end;
end;

function TCodeIntegrity.MeasureExportTableCore(const Budget: TMeasurementBudget): TCodeIntegrityMeasurement;
var Bytes: TBytes;
begin
  Require(FExportTableReady);
  Bytes := BuildExportStream(nil, 0, True, Budget);
  try
    Result := Digest(Bytes, 0, Budget);
    Result.Algorithm := ExportAlgorithm;
  finally
    ClearBytes(Bytes);
  end;
end;

{$IFDEF GAME_CRC_PE_PROBE}
function TCodeIntegrity.CaptureCrcProbeSnapshot(FileMode: Boolean): TJSONObject;
const Names: array[0..8] of string = (CozyText_CodeIntegrity_ecma182_45fdae3c,CozyText_CodeIntegrity_nvme_ad089a8c,CozyText_CodeIntegrity_jones_51b1b0ef,CozyText_CodeIntegrity_xz_92e6960f,CozyText_CodeIntegrity_we_a0818638,CozyText_CodeIntegrity_iso_42a71d65,CozyText_CodeIntegrity_crc32c_7efbc912,CozyText_CodeIntegrity_crc16_arc_9c838918,CozyText_CodeIntegrity_crc8_smbus_ca629586);
  RoleNames: array[0..2] of string = (CozyText_CodeIntegrity_nvme_ad089a8c,CozyText_CodeIntegrity_jones_51b1b0ef,CozyText_CodeIntegrity_iso_42a71d65);
var Budget: TMeasurementBudget; Code, First, Second, Combined: TBytes;
  Empty: TArray<Cardinal>; Inputs, Ranges, RoleRanges: TJSONObject;
  Entries: TJSONArray; Item: TJSONObject; I, J, N: Integer;
  function AddObject(Owner: TJSONObject; const Name: string): TJSONObject;
  begin
    Result := TJSONObject.Create;
    try Owner.AddPair(Name, Result);
    except Result.Free; raise; end;
  end;
  function AddArray(Owner: TJSONObject; const Name: string): TJSONArray;
  begin
    Result := TJSONArray.Create;
    try Owner.AddPair(Name, Result);
    except Result.Free; raise; end;
  end;
  procedure AddRange(List: TJSONArray; RVA, Span: Cardinal);
  var Row: TJSONObject;
  begin
    Row := TJSONObject.Create;
    try
      Row.AddPair(CozyText_CodeIntegrity_rva_042e7351, TJSONNumber.Create(Int64(RVA)));
      Row.AddPair(CozyText_CodeIntegrity_span_63fad6d4, TJSONNumber.Create(Int64(Span)));
      List.AddElement(Row);
    except Row.Free; raise; end;
  end;
begin
  Result := nil; Empty := nil;
  FGate.Enter;
  try
    try
      Budget := TMeasurementBudget.Start(512 * 1024 * 1024, 120000);
      FProbeFileMode := FileMode;
      if FileMode then Code := Copy(FProbeCodeBytes, 0, Length(FProbeCodeBytes))
      else begin
        Require(FOwnImage);
        VerifyOwnHeaders(Budget);
        Code := BuildStream(nil, Empty, Empty, True, Budget);
      end;
      Result := TJSONObject.Create;
      Result.AddPair(CozyText_CodeIntegrity_accepted_cae52b83, TJSONBool.Create(True));
      Result.AddPair(CozyText_CodeIntegrity_version_04ec885e, TJSONNumber.Create(1));
      Result.AddPair(CozyText_CodeIntegrity_codeSha512_4bb1f02c, SHA512Bytes(Code));
      First := CodePageSHA512Manifest(Code, CrcBudgetCheckpoint, @Budget);
      Result.AddPair(CozyText_CodeIntegrity_codePageSha512Manifest_56f1dd24, SHA512Bytes(First));
      Result.AddPair(CozyText_CodeIntegrity_codePageSha512BaselineMatches_33672398, TJSONBool.Create(
        (Length(First) = Length(FFilePageSHA512)) and
        CompareMem(@First[0], @FFilePageSHA512[0], Length(First))));
      Result.AddPair(CozyText_CodeIntegrity_codePageSha512ManifestBytes_26e0315f, TJSONNumber.Create(Length(First)));
      ClearBytes(First);
      { Conservative payload-array bound for MeasureBundle, excludes probe
        copies, constructor input, allocator/JSON overhead and process RSS. }
      Result.AddPair(CozyText_CodeIntegrity_bundlePayloadBoundBytes_c0514861, TJSONNumber.Create(Int64(
        Length(Code) + Length(FFilePageSHA512) + MaximumExportBytes + 65536)));
      Result.AddPair(CozyText_CodeIntegrity_maximumOwnBundlePayloadBoundBytes_c9757c06, TJSONNumber.Create(Int64(
        MaximumCodeBytes + 4096 +
        ((MaximumCodeBytes div 4096) + 96 * 2 + 1) * 72 + 64 +
        MaximumExportBytes + 65536)));
      Result.AddPair(CozyText_CodeIntegrity_exportStatus_ad39b295, FExportTableStatus);
      Inputs := AddObject(Result, CozyText_CodeIntegrity_inputs_77366a16);
      for I := 0 to 8 do
      begin
        BuildCrcLayerInput(I, Code, Budget, First, Second);
        N := Length(First); SetLength(Combined, N + Length(Second));
        if N <> 0 then Move(First[0], Combined[0], N);
        if Length(Second) <> 0 then Move(Second[0], Combined[N], Length(Second));
        Item := AddObject(Inputs, Names[I]);
        Item.AddPair(CozyText_CodeIntegrity_bytes_7bd6da7e, TJSONNumber.Create(Length(Combined)));
        Item.AddPair(CozyText_CodeIntegrity_sha512_33003893, SHA512Bytes(Combined));
        ClearBytes(First); ClearBytes(Second); ClearBytes(Combined);
      end;
      Ranges := AddObject(Result, CozyText_CodeIntegrity_ranges_93f9e255);
      Entries := AddArray(Ranges, CozyText_CodeIntegrity_code_bee07b77);
      for I := 0 to High(FSections) do AddRange(Entries, FSections[I].RVA, FSections[I].Span);
      Entries := AddArray(Ranges, CozyText_CodeIntegrity_headers_96c3406d);
      for I := 0 to FOwnHeaderPlan.RangeCount - 1 do
        AddRange(Entries, FOwnHeaderPlan.RangeOffset(I), FOwnHeaderPlan.RangeSize(I));
      Entries := AddArray(Ranges, CozyText_CodeIntegrity_codeRelocations_772c4af2);
      for I := 0 to High(FRelocations) do AddRange(Entries, FRelocations[I].RVA, Cardinal(FRelocations[I].Width));
      RoleRanges := AddObject(Ranges, CozyText_CodeIntegrity_checkers_c1ffea92);
      for I := 0 to 2 do
      begin
        Entries := AddArray(RoleRanges, RoleNames[I]);
        for J := 0 to High(FCheckerRanges[I]) do AddRange(Entries, FCheckerRanges[I][J].RVA, FCheckerRanges[I][J].Span);
      end;
      Item := MeasureCrcLayersCore(Code, Budget);
      try Result.AddPair(CozyText_CodeIntegrity_layers_91d175fe, Item);
      except Item.Free; raise; end;
    except
      Result.Free; Result := nil; raise;
    end;
  finally
    FProbeFileMode := False;
    ClearBytes(Code); ClearBytes(First); ClearBytes(Second); ClearBytes(Combined);
    FGate.Leave;
  end;
end;
{$ENDIF}

destructor TCodeIntegrity.Destroy;
begin
  if FGate <> nil then FGate.CloseAndWait;
  ClearBytes(FFilePageSHA512);
{$IFDEF GAME_CRC_PE_PROBE}
  ClearBytes(FProbeFileBytes); ClearBytes(FProbeCodeBytes);
{$ENDIF}
  FGate.Free;
  inherited;
end;
function TCodeIntegrity.GetFileMeasurement: TCodeIntegrityMeasurement;
begin
  FGate.Enter;
  try Result := FFileMeasurement; finally FGate.Leave; end;
end;
function TCodeIntegrity.GetExportCoverage: TCodeExportCoverage;
begin
  FGate.Enter;
  try Result := FExportCoverage; finally FGate.Leave; end;
end;
function TCodeIntegrity.GetFileExportMeasurement: TCodeIntegrityMeasurement;
begin
  FGate.Enter;
  try Result := FFileExportMeasurement; finally FGate.Leave; end;
end;
function TCodeIntegrity.GetExportTableStatus: string;
begin
  FGate.Enter;
  try Result := FExportTableStatus; finally FGate.Leave; end;
end;
function TCodeIntegrity.GetIsOwnImage: Boolean;
begin
  FGate.Enter;
  try Result := FOwnImage; finally FGate.Leave; end;
end;
function TCodeIntegrity.MeasureNow: TCodeIntegrityMeasurement;
begin Result := MeasureNow(TMeasurementBudget.Start(FMaximumImageBytes, 30000)); end;
function TCodeIntegrity.MeasureNow(const Budget: TMeasurementBudget): TCodeIntegrityMeasurement;
var ActiveBudget: TMeasurementBudget;
begin
  FGate.Enter;
  try
    ActiveBudget := Budget.WithCancellation(function: Boolean
      begin Result := FGate.IsClosing; end);
    Result := MeasureNowCore(ActiveBudget);
  finally FGate.Leave; end;
end;
function TCodeIntegrity.MeasureExportTableNow: TCodeIntegrityMeasurement;
begin Result := MeasureExportTableNow(TMeasurementBudget.Start(FMaximumImageBytes, 30000)); end;
function TCodeIntegrity.MeasureExportTableNow(const Budget: TMeasurementBudget): TCodeIntegrityMeasurement;
var ActiveBudget: TMeasurementBudget;
begin
  FGate.Enter;
  try
    ActiveBudget := Budget.WithCancellation(function: Boolean
      begin Result := FGate.IsClosing; end);
    Result := MeasureExportTableCore(ActiveBudget);
  finally FGate.Leave; end;
end;
procedure TCodeIntegrity.MeasureBundle(out Code: TCodeIntegrityMeasurement;
  out Layers: TJSONObject; const Budget: TMeasurementBudget);
var ActiveBudget: TMeasurementBudget; Bytes, AfterBytes: TBytes;
  Empty: TArray<Cardinal>; AfterDigest: TCodeIntegrityMeasurement;
begin
  Code := Default(TCodeIntegrityMeasurement); Layers := nil; Empty := nil;
  FGate.Enter;
  try
   try
    ActiveBudget := Budget.WithCancellation(function: Boolean
      begin Result := FGate.IsClosing; end);
    VerifyOwnHeaders(ActiveBudget);
    Bytes := BuildStream(nil, Empty, Empty, True, ActiveBudget);
    VerifyCodePages(Bytes, ActiveBudget);
    Code := Digest(Bytes, Length(FSections), ActiveBudget);
    Layers := MeasureCrcLayersCore(Bytes, ActiveBudget);
    { No atomic-snapshot claim: detect a changed normalized image across the
      interval, and use exactly the first captured bytes for hashes and CRCs. }
    { Only the first digest is needed for the second comparison. Releasing
      this buffer preserves the cryptographic before/after check without
      retaining two up-to-64-MiB normalized image copies concurrently. }
    ClearBytes(Bytes);
    AfterBytes := BuildStream(nil, Empty, Empty, True, ActiveBudget);
    VerifyCodePages(AfterBytes, ActiveBudget);
    AfterDigest := Digest(AfterBytes, Length(FSections), ActiveBudget);
    if (Code.SHA512 <> AfterDigest.SHA512) or (Code.Size <> AfterDigest.Size) then
      raise EMeasurement.Create(msChanged, CozyText_CodeIntegrity_OWN_CODE_GENERATION_CHANGED_415dee0a);
    VerifyOwnHeaders(ActiveBudget); ActiveBudget.Check(0, 0);
   except
    { Failed bundles transfer no partially populated digest or JSON ownership. }
    Code := Default(TCodeIntegrityMeasurement);
    Layers.Free; Layers := nil;
    raise;
   end;
  finally
    ClearBytes(Bytes); ClearBytes(AfterBytes); FGate.Leave;
  end;
end;
function TCodeIntegrity.MeasureCrcLayersNow: TJSONObject;
begin Result := MeasureCrcLayersNow(TMeasurementBudget.Start(FMaximumImageBytes, 30000)); end;
function TCodeIntegrity.MeasureCrcLayersNow(const Budget: TMeasurementBudget): TJSONObject;
var Code: TCodeIntegrityMeasurement;
begin
  Result := nil;
  try MeasureBundle(Code, Result, Budget);
  except Result.Free; Result := nil; raise; end;
end;

initialization
  { API binding only; original startup actions follow unchanged. }
  BindApiPointer(ApiSlot_GetModuleHandle, RequireProcAddressHash64(CozyText_CodeIntegrity_kernel32_dll_f9bafeda, HASH_GetModuleHandleW));
  BindApiPointer(ApiSlot_QueryMemory, RequireProcAddressHash64(CozyText_CodeIntegrity_kernel32_dll_f9bafeda, HASH_VirtualQuery));

end.
