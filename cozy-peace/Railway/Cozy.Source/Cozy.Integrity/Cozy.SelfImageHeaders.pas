unit Cozy.SelfImageHeaders;

{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}

interface

uses
{ Cozy central text imports. }
  Cozy.Strings.Integrity,

  System.SysUtils;

type
  ESelfImageHeader = class(Exception);

  { Immutable-by-interface copies of selected file header fields, not a hash
    of the entire mapped image and not an identification of debugging tools. }
  TSelfImageHeaderRange = record
    Offset: Cardinal;
    Expected: TBytes;
  end;

  TSelfImageHeaderPlan = record
  private
    FRanges: TArray<TSelfImageHeaderRange>;
    FComparedBytes: Cardinal;
    FImageSize: Cardinal;
    FReady: Boolean;
    procedure AddRange(const FileBytes: TBytes; Offset, Count,
      HeaderSize: Cardinal);
    procedure CheckIndex(Index: Integer);
  public
    { Call once with the retained, already verified executable file. The helper
      validates header bounds; the existing code-integrity parser still owns
      complete section/relocation validation. No mapped header chooses ranges. }
    procedure Initialize(const FileBytes: TBytes);
    { Same validation with explicit finite limits for inventory DLLs only.
      Default Initialize keeps the own-artifact limits unchanged. }
    procedure InitializeBounded(const FileBytes: TBytes;
      FileLimit, ImageLimit: UInt64);
    function RangeCount: Integer;
    function RangeOffset(Index: Integer): Cardinal;
    function RangeSize(Index: Integer): Cardinal;
    { Data must point to Count readable bytes supplied by the caller. A nil
      buffer or a length mismatch returns False, not a partial comparison. }
    function RangeMatches(Index: Integer; Data: Pointer;
      Count: NativeUInt): Boolean;
    property IsReady: Boolean read FReady;
    property ComparedBytes: Cardinal read FComparedBytes;
    property ImageSize: Cardinal read FImageSize;
  end;

implementation

const
{$I Cozy.ModuleLimits.inc}
  MaximumHeaderRanges = 202;
  MaximumRangeBytes = 128;
  MaximumComparedBytes = 2096;

procedure HeaderRequire(Condition: Boolean);
begin
  if not Condition then
    raise ESelfImageHeader.Create(CozyText_SelfImageHeaders_Executable_header_plan_is_invalid_161a2efe);
end;

function HeaderU16(const Bytes: TBytes; At: UInt64): Word;
begin
  HeaderRequire((At <= UInt64(Length(Bytes))) and
    (UInt64(Length(Bytes)) - At >= SizeOf(Result)));
  Move(Bytes[NativeInt(At)], Result, SizeOf(Result));
end;

function HeaderU32(const Bytes: TBytes; At: UInt64): Cardinal;
begin
  HeaderRequire((At <= UInt64(Length(Bytes))) and
    (UInt64(Length(Bytes)) - At >= SizeOf(Result)));
  Move(Bytes[NativeInt(At)], Result, SizeOf(Result));
end;

procedure TSelfImageHeaderPlan.AddRange(const FileBytes: TBytes;
  Offset, Count, HeaderSize: Cardinal);
var
  Index: Integer;
begin
  HeaderRequire((Count > 0) and (Count <= MaximumRangeBytes) and
    (UInt64(Offset) + Count <= HeaderSize) and
    (UInt64(Offset) + Count <= FImageSize) and
    (UInt64(Offset) + Count <= UInt64(Length(FileBytes))));
  Index := Length(FRanges);
  HeaderRequire((Index < MaximumHeaderRanges) and
    (UInt64(FComparedBytes) + Count <= MaximumComparedBytes));
  SetLength(FRanges, Index + 1);
  FRanges[Index].Offset := Offset;
  SetLength(FRanges[Index].Expected, Integer(Count));
  Move(FileBytes[NativeInt(Offset)], FRanges[Index].Expected[0], Count);
  Inc(FComparedBytes, Count);
end;

procedure TSelfImageHeaderPlan.CheckIndex(Index: Integer);
begin
  HeaderRequire(FReady and (Index >= 0) and (Index < Length(FRanges)));
end;

procedure TSelfImageHeaderPlan.Initialize(const FileBytes: TBytes);
begin
  InitializeBounded(FileBytes, OwnPeFileLimit, OwnPeImageLimit);
end;
procedure TSelfImageHeaderPlan.InitializeBounded(const FileBytes: TBytes;
  FileLimit, ImageLimit: UInt64);
var
  PE, Optional, OptionalSize, TableAt, HeaderSize, DirectoryCount: Cardinal;
  SectionCount, Index: Integer;
  At: Cardinal;
begin
  FRanges := nil;
  FComparedBytes := 0;
  FImageSize := 0;
  FReady := False;
  try
    HeaderRequire((FileLimit > 0) and (FileLimit <= InventoryPeFileLimit) and
      (ImageLimit > 0) and (ImageLimit <= InventoryPeImageLimit));
    HeaderRequire((Length(FileBytes) >= 64) and
      (UInt64(Length(FileBytes)) <= FileLimit));
    HeaderRequire(HeaderU16(FileBytes, 0) = $5A4D);
    PE := HeaderU32(FileBytes, $3C);
    HeaderRequire((PE >= 64) and
      (UInt64(PE) + 24 <= UInt64(Length(FileBytes))));
    HeaderRequire((HeaderU32(FileBytes, PE) = $4550) and
      (HeaderU16(FileBytes, PE + 4) = $8664));
    SectionCount := HeaderU16(FileBytes, PE + 6);
    OptionalSize := HeaderU16(FileBytes, PE + 20);
    Optional := PE + 24;
    TableAt := Optional + OptionalSize;
    HeaderRequire((SectionCount >= 1) and (SectionCount <= 96) and
      (OptionalSize >= 112) and
      (UInt64(TableAt) + UInt64(SectionCount) * 40 <= UInt64(Length(FileBytes))));
    HeaderRequire(HeaderU16(FileBytes, Optional) = $20B);
    FImageSize := HeaderU32(FileBytes, Optional + 56);
    HeaderSize := HeaderU32(FileBytes, Optional + 60);
    DirectoryCount := HeaderU32(FileBytes, Optional + 108);
    HeaderRequire((FImageSize >= 4096) and (UInt64(FImageSize) <= ImageLimit) and
      (UInt64(TableAt) + UInt64(SectionCount) * 40 <= HeaderSize) and
      (HeaderSize <= FImageSize) and
      (HeaderSize <= Cardinal(Length(FileBytes))) and
      (DirectoryCount <= 16) and (112 + DirectoryCount * 8 <= OptionalSize));

    AddRange(FileBytes, 0, 2, HeaderSize);                 // DOS signature
    AddRange(FileBytes, $3C, 4, HeaderSize);               // retained e_lfanew
    AddRange(FileBytes, PE, 8, HeaderSize);                // PE/machine/count
    AddRange(FileBytes, PE + 20, 4, HeaderSize);           // optional size/flags
    AddRange(FileBytes, Optional, 2, HeaderSize);          // PE32+ magic
    AddRange(FileBytes, Optional + 16, 8, HeaderSize);     // entry point/code RVA
    AddRange(FileBytes, Optional + 32, 8, HeaderSize);     // section/file alignment
    AddRange(FileBytes, Optional + 56, 8, HeaderSize);     // image/header sizes
    AddRange(FileBytes, Optional + 108, 4, HeaderSize);    // directory count
    if DirectoryCount > 0 then
      AddRange(FileBytes, Optional + 112, DirectoryCount * 8, HeaderSize);
    for Index := 0 to SectionCount - 1 do
    begin
      At := TableAt + Cardinal(Index) * 40;
      AddRange(FileBytes, At + 8, 16, HeaderSize);         // span/RVA/raw layout
      AddRange(FileBytes, At + 36, 4, HeaderSize);        // section permissions
    end;
    { ImageBase is deliberately excluded: ASLR addresses are handled by the
      existing relocation verifier. Timestamp, linker version, checksum, DOS
      stub, section names, debug strings, and IAT CONTENTS are not compared.
      DataDirectory entries are only coordinates, not resolved API pointers. }
    FReady := True;
  finally
    if not FReady then
    begin
      FRanges := nil;
      FComparedBytes := 0;
      FImageSize := 0;
    end;
  end;
end;

function TSelfImageHeaderPlan.RangeCount: Integer;
begin
  HeaderRequire(FReady);
  Result := Length(FRanges);
end;

function TSelfImageHeaderPlan.RangeOffset(Index: Integer): Cardinal;
begin
  CheckIndex(Index);
  Result := FRanges[Index].Offset;
end;

function TSelfImageHeaderPlan.RangeSize(Index: Integer): Cardinal;
begin
  CheckIndex(Index);
  Result := Cardinal(Length(FRanges[Index].Expected));
end;

function TSelfImageHeaderPlan.RangeMatches(Index: Integer; Data: Pointer;
  Count: NativeUInt): Boolean;
begin
  CheckIndex(Index);
  Result := False;
  if (Data = nil) or (Count <> NativeUInt(Length(FRanges[Index].Expected))) then
    Exit;
  Result := CompareMem(@FRanges[Index].Expected[0], Data, NativeInt(Count));
end;

end.
