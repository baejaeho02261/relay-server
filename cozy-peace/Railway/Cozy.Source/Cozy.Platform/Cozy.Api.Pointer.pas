unit Cozy.Api.Pointer;

{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$IFNDEF MSWINDOWS}
  {$MESSAGE FATAL 'Cozy.Api.Pointer requires Windows.'}
{$ENDIF}
{$IFNDEF CPUX64}
  {$MESSAGE FATAL 'Cozy.Api.Pointer requires the Delphi x64 compiler.'}
{$ENDIF}
{$ALIGN 8}
{$B-}

interface

uses
{ Cozy central text imports. }
  Cozy.Strings.Platform,
 System.SysUtils;

type
  { Records are stable handles to a dedicated arena, not address storage.
    Production slots are unit globals; moving/copying a bound slot is rejected. }
  TEncodedApiPointer = record
  private
    FIndex: Cardinal;
    FBound: Boolean;
    function GetEncodedValue: Pointer;
  public
    property IsBound: Boolean read FBound;
    property EncodedValue: Pointer read GetEncodedValue;
  end;

procedure InitializeApiPointerCodec(EncodeAddress, DecodeAddress,
  GetErrorAddress, SetErrorAddress: Pointer);
procedure ConfigureApiPointerStorage(AllocateAddress, ProtectAddress,
  FreeAddress, QueryAddress: Pointer);
procedure BindApiPointer(var Slot: TEncodedApiPointer; Address: Pointer);
function DecodeApiPointer(const [ref] Slot: TEncodedApiPointer): Pointer;
{ Call in the main DPR after ALL unit initializations, before application work. }
procedure SealApiPointerStorage;
function ApiPointerStorageIsSealed: Boolean;
function ApiPointerStorageCount: Cardinal;
function ApiPointerTargetsMatch(const Expected: array of Pointer): Boolean;
{ Only process-lifetime, statically registered slots; no arbitrary address input. }
function CaptureApiPointerGraph(out Slots, Depth: Cardinal): TBytes;
{$IFDEF COZY_POINTER_GRAPH_PROBE}
{ Isolated Windows fault probe only; excluded from every production project. }
function ProbeApiPointerGraphRejects(Fault: Cardinal): Boolean;
{$ENDIF}

implementation

uses
  Cozy.PointerGraph;

const
  MaxApiSlots = 1024;
  ArenaBytes = 65536;
  MemCommitReserve = $3000;
  MemRelease = $8000;
  PageReadWrite = $04;
  PageReadOnly = $02;

type
  TPointerTransform = function(Value: Pointer): Pointer; stdcall;
  TReadThreadError = function: Cardinal; stdcall;
  TWriteThreadError = procedure(Value: Cardinal); stdcall;
  TAllocatePages = function(Address: Pointer; Size: NativeUInt;
    AllocationType, Protection: Cardinal): Pointer; stdcall;
  TProtectPages = function(Address: Pointer; Size: NativeUInt;
    Protection: Cardinal; var Previous: Cardinal): LongBool; stdcall;
  TFreePages = function(Address: Pointer; Size: NativeUInt;
    FreeType: Cardinal): LongBool; stdcall;
  TQueryPages = function(Address, Information: Pointer;
    Size: NativeUInt): NativeUInt; stdcall;
  TCodec = record
    Encode, Decode: TPointerTransform;
    ReadError: TReadThreadError;
    WriteError: TWriteThreadError;
  end;
  PCodec = ^TCodec;
  TApiEntry = record
    Owner, Encoded, Original, OwnerBase, TargetBase: Pointer;
  end;
  TApiArena = record
    Codec: TCodec;
    Protect: TProtectPages;
    Release: TFreePages;
    Query: TQueryPages;
    Count: Cardinal;
    Entries: array[0..MaxApiSlots - 1] of TApiEntry;
  end;
  PApiArena = ^TApiArena;
  { Explicit MEMORY_BASIC_INFORMATION x64 ABI, including reserved padding. }
  TPageInformation = record
    BaseAddress, AllocationBase: Pointer;
    AllocationProtect: Cardinal;
    Alignment1: Cardinal;
    RegionSize: NativeUInt;
    State, Protect, Kind, Alignment2: Cardinal;
  end;

var
  BootstrapCodec: TCodec;
  ActiveCodec: PCodec;
  Arena: PApiArena;
  CodecReady, StorageSealed: Boolean;
  RegisteredOwners: array[0..MaxApiSlots-1] of Pointer;

procedure InitializeApiPointerCodec(EncodeAddress, DecodeAddress,
  GetErrorAddress, SetErrorAddress: Pointer);
begin
  if CodecReady then
    raise EInvalidOpException.Create(CozyText_Api_Pointer_API_pointer_codec_is_already_initialized_88eb4f5d);
  if (EncodeAddress = nil) or (DecodeAddress = nil) or
    (GetErrorAddress = nil) or (SetErrorAddress = nil) then
    raise EArgumentException.Create(CozyText_Api_Pointer_A_required_API_pointer_codec_address_is_missing_6c645288);
  BootstrapCodec.Encode := TPointerTransform(EncodeAddress);
  BootstrapCodec.Decode := TPointerTransform(DecodeAddress);
  BootstrapCodec.ReadError := TReadThreadError(GetErrorAddress);
  BootstrapCodec.WriteError := TWriteThreadError(SetErrorAddress);
  ActiveCodec := @BootstrapCodec;
  CodecReady := True;
end;

procedure ConfigureApiPointerStorage(AllocateAddress, ProtectAddress,
  FreeAddress, QueryAddress: Pointer);
var Allocate: TAllocatePages; SavedError: Cardinal; NewArena: PApiArena;
begin
  if not CodecReady or (Arena <> nil) then
    raise EInvalidOpException.Create(CozyText_Api_Pointer_API_storage_initialization_order_is_invalid_3505beb9);
  if (AllocateAddress = nil) or (ProtectAddress = nil) or
    (FreeAddress = nil) or (QueryAddress = nil) or (SizeOf(TApiArena) > ArenaBytes) then
    raise EArgumentException.Create(CozyText_Api_Pointer_API_storage_configuration_is_invalid_c8139d14);
  SavedError := ActiveCodec^.ReadError();
  try
    Allocate := TAllocatePages(AllocateAddress);
    NewArena := PApiArena(Allocate(nil, ArenaBytes, MemCommitReserve, PageReadWrite));
    if NewArena = nil then
      raise EOutOfMemory.Create(CozyText_Api_Pointer_Cannot_allocate_API_pointer_storage_eed600ef);
    { VirtualAlloc returns zero-initialized dedicated pages; never a heap page. }
    NewArena^.Codec := BootstrapCodec;
    NewArena^.Protect := TProtectPages(ProtectAddress);
    NewArena^.Release := TFreePages(FreeAddress);
    NewArena^.Query := TQueryPages(QueryAddress);
    Arena := NewArena;
    ActiveCodec := @Arena^.Codec;
    FillChar(BootstrapCodec, SizeOf(BootstrapCodec), 0);
  finally
    ActiveCodec^.WriteError(SavedError);
  end;
end;

function SlotValue(const [ref] Slot: TEncodedApiPointer): Pointer;
begin
  if not CodecReady or (Arena = nil) or not Slot.FBound or
    (Slot.FIndex = 0) or (Slot.FIndex > Arena^.Count) or
    (Slot.FIndex > MaxApiSlots) then
    raise EInvalidOpException.Create(CozyText_Api_Pointer_API_pointer_slot_is_not_bound_395aa09e);
  if Arena^.Entries[Slot.FIndex - 1].Owner <> @Slot then
    raise EInvalidOpException.Create(CozyText_Api_Pointer_API_pointer_slot_ownership_changed_9be03981);
  Result := Arena^.Entries[Slot.FIndex - 1].Encoded;
end;

function TEncodedApiPointer.GetEncodedValue: Pointer;
begin
  Result := SlotValue(Self);
end;

procedure BindApiPointer(var Slot: TEncodedApiPointer; Address: Pointer);
var SavedError, Index: Cardinal; Encoded: Pointer; OwnerInfo, TargetInfo: TPageInformation;
begin
  if not CodecReady then
    raise EInvalidOpException.Create(CozyText_Api_Pointer_API_pointer_codec_is_not_initialized_3dd20dd8);
  if Address = nil then
    raise EArgumentException.Create(CozyText_Api_Pointer_Cannot_bind_a_missing_API_address_8254a66b);
  if (Arena = nil) or StorageSealed or Slot.FBound or (Arena^.Count >= MaxApiSlots) then
    raise EInvalidOpException.Create(CozyText_Api_Pointer_API_storage_is_unavailable_sealed_or_already_bou_4cc0b8de);
  SavedError := ActiveCodec^.ReadError();
  try
    FillChar(OwnerInfo, SizeOf(OwnerInfo), 0); FillChar(TargetInfo, SizeOf(TargetInfo), 0);
    if (Arena^.Query(@Slot, @OwnerInfo, SizeOf(OwnerInfo)) <> SizeOf(OwnerInfo)) or
      (Arena^.Query(Address, @TargetInfo, SizeOf(TargetInfo)) <> SizeOf(TargetInfo)) or
      (OwnerInfo.State <> $1000) or (TargetInfo.State <> $1000) or
      (OwnerInfo.Kind <> $1000000) or (TargetInfo.Kind <> $1000000) then
      raise EInvalidOpException.Create(CozyText_Api_Pointer_OWN_POINTER_REGISTRATION_INVALID_627e18b1);
    Encoded := ActiveCodec^.Encode(Address);
    Index := Arena^.Count;
    Arena^.Entries[Index].Owner := @Slot;
    Arena^.Entries[Index].Encoded := Encoded;
    Arena^.Entries[Index].Original := Address;
    Arena^.Entries[Index].OwnerBase := OwnerInfo.AllocationBase;
    Arena^.Entries[Index].TargetBase := TargetInfo.AllocationBase;
    RegisteredOwners[Index] := @Slot;
    Inc(Arena^.Count);
    Slot.FIndex := Index + 1;
    Slot.FBound := True;
  finally
    ActiveCodec^.WriteError(SavedError);
  end;
end;

function DecodeApiPointer(const [ref] Slot: TEncodedApiPointer): Pointer;
var SavedError: Cardinal; Encoded: Pointer;
begin
  Encoded := SlotValue(Slot);
  SavedError := ActiveCodec^.ReadError();
  try
    Result := ActiveCodec^.Decode(Encoded);
  finally
    ActiveCodec^.WriteError(SavedError);
  end;
  if Result = nil then
    raise EInvalidOpException.Create(CozyText_Api_Pointer_A_decoded_API_pointer_is_missing_a103484c);
end;

function ApiPointerStorageIsSealed: Boolean;
var Info: TPageInformation; SavedError: Cardinal; Size: NativeUInt;
begin
  Result := False;
  if not StorageSealed or (Arena = nil) then Exit;
  SavedError := ActiveCodec^.ReadError();
  try
    FillChar(Info, SizeOf(Info), 0);
    Size := Arena^.Query(Arena, @Info, SizeOf(Info));
    Result := (Size = SizeOf(Info)) and (Info.AllocationBase = Arena) and
      (Info.BaseAddress = Arena) and (Info.RegionSize >= ArenaBytes) and
      (Info.State = $1000) and (Info.Protect = PageReadOnly) and
      (Arena^.Count > 0) and (Arena^.Count <= MaxApiSlots);
  finally
    ActiveCodec^.WriteError(SavedError);
  end;
end;

procedure SealApiPointerStorage;
var Previous, SavedError: Cardinal;
begin
  if (Arena = nil) or (Arena^.Count = 0) then
    raise EInvalidOpException.Create(CozyText_Api_Pointer_API_storage_is_not_initialized_d67187ff);
  if StorageSealed then
  begin
    if not ApiPointerStorageIsSealed then
      raise EInvalidOpException.Create(CozyText_Api_Pointer_API_storage_protection_changed_876ad6c5);
    Exit;
  end;
  SavedError := ActiveCodec^.ReadError();
  try
    Previous := 0;
    if not Arena^.Protect(Arena, ArenaBytes, PageReadOnly, Previous) then
      raise EInvalidOpException.Create(CozyText_Api_Pointer_Cannot_seal_API_pointer_storage_ff429f19);
    StorageSealed := True;
    if not ApiPointerStorageIsSealed then
      raise EInvalidOpException.Create(CozyText_Api_Pointer_Cannot_verify_sealed_API_pointer_storage_113288a7);
  finally
    ActiveCodec^.WriteError(SavedError);
  end;
end;

function ApiPointerStorageCount: Cardinal;
begin
  if Arena = nil then Result := 0 else Result := Arena^.Count;
end;

function ApiPointerTargetsMatch(const Expected: array of Pointer): Boolean;
var
  Used: array of Boolean;
  I, J: Integer;
  Target: Pointer;
  Slot: ^TEncodedApiPointer;
  Found: Boolean;
begin
  Result := False;
  if not ApiPointerStorageIsSealed or (Length(Expected) <> Integer(Arena^.Count)) then Exit;
  SetLength(Used, Length(Expected));
  for I := 0 to Integer(Arena^.Count) - 1 do
  begin
    Slot := Arena^.Entries[I].Owner;
    if (Slot = nil) or not Slot^.FBound or (Slot^.FIndex <> Cardinal(I + 1)) then Exit;
    Target := DecodeApiPointer(Slot^);
    Found := False;
    for J := 0 to High(Expected) do
      if not Used[J] and (Expected[J] <> nil) and (Expected[J] = Target) then
      begin Used[J] := True; Found := True; Break; end;
    if not Found then Exit;
  end;
  Result := True;
end;

function CaptureApiPointerGraph(out Slots, Depth: Cardinal): TBytes;
var Nodes: TCozyPointerNodes; Edges: TCozyPointerEdges;
  I: Integer; Slot: ^TEncodedApiPointer; Entry: TApiEntry;
  Info: TPageInformation; Target: Pointer; SavedError: Cardinal;
  procedure Require(Value: Boolean);
  begin if not Value then raise EInvalidOpException.Create(CozyText_Api_Pointer_OWN_POINTER_GRAPH_CHANGED_8a6c236d); end;
  procedure Readable(Address, Allocation: Pointer; Bytes: NativeUInt; Executable: Boolean);
  var Offset: NativeUInt; Protection: Cardinal;
  begin
    Require(Address <> nil);
    FillChar(Info, SizeOf(Info), 0);
    Require(Arena^.Query(Address, @Info, SizeOf(Info)) = SizeOf(Info));
    Require((Info.State = $1000) and (Info.Kind = $1000000) and
      (Info.AllocationBase = Allocation) and ((Info.Protect and $101) = 0));
    Require(NativeUInt(Address) >= NativeUInt(Info.BaseAddress));
    Offset := NativeUInt(Address)-NativeUInt(Info.BaseAddress);
    Require((Offset <= Info.RegionSize) and (Bytes <= Info.RegionSize-Offset));
    Protection := Info.Protect and $FF;
    if Executable then Require((Protection = $10) or (Protection = $20) or (Protection = $40) or (Protection = $80))
    else Require((Protection = $02) or (Protection = $04) or (Protection = $08) or (Protection = $20) or (Protection = $40) or (Protection = $80));
  end;
begin
  Result := nil; Slots := 0; Depth := 0;
  Require(ApiPointerStorageIsSealed);
  SavedError := ActiveCodec^.ReadError();
  try
    Slots := Arena^.Count;
    for I := 0 to Integer(Slots)-1 do begin
      Entry := Arena^.Entries[I];
      { Check the separately registered identity BEFORE querying/dereferencing.
        Registration is initialization-only; targets and owners are pinned image
        lifetime. No user object may be freed/replaced under this snapshot. }
      Require((Entry.Owner <> nil) and (Entry.Owner = RegisteredOwners[I]));
      Readable(Entry.Owner, Entry.OwnerBase, SizeOf(TEncodedApiPointer), False);
      Slot := Entry.Owner;
      Require(Slot^.FBound and (Slot^.FIndex = Cardinal(I+1)));
      Target := DecodeApiPointer(Slot^);
      Require(Target = Entry.Original);
      Readable(Target, Entry.TargetBase, 1, True);
    end;
    Require(ApiPointerStorageIsSealed and (Slots = Arena^.Count));
    CozyApiGraphShape(Slots, Nodes, Edges);
    Result := CozyPointerGraphBytes(Nodes, Edges, Depth);
  finally ActiveCodec^.WriteError(SavedError); end;
end;

{$IFDEF COZY_POINTER_GRAPH_PROBE}
function ProbeApiPointerGraphRejects(Fault: Cardinal): Boolean;
var OldEntry: TApiEntry; OldCount, OldIndex, Previous, Slots, Depth: Cardinal;
  Slot: ^TEncodedApiPointer; Bytes: TBytes;
begin
  Result := False;
  if not ApiPointerStorageIsSealed or (Fault < 1) or (Fault > 5) then Exit;
  OldEntry := Arena^.Entries[0]; OldCount := Arena^.Count;
  Slot := OldEntry.Owner; OldIndex := Slot^.FIndex;
  if not Arena^.Protect(Arena,ArenaBytes,PageReadWrite,Previous) then Exit;
  try
    case Fault of
      1: Arena^.Count := 0;
      2: Arena^.Entries[0].Owner := Pointer(NativeUInt(1));
      3: Arena^.Entries[0].Original := nil;
      4: Arena^.Entries[0].Encoded := ActiveCodec^.Encode(@ProbeApiPointerGraphRejects);
      5: Slot^.FIndex := 0;
    end;
    if not Arena^.Protect(Arena,ArenaBytes,PageReadOnly,Previous) then
      raise EInvalidOpException.Create(CozyText_Api_Pointer_PROBE_PROTECTION_FAILED_017c3de1);
    try Bytes := CaptureApiPointerGraph(Slots,Depth);
    except on E: EInvalidOpException do Result := True; end;
  finally
    if not Arena^.Protect(Arena,ArenaBytes,PageReadWrite,Previous) then
      raise EInvalidOpException.Create(CozyText_Api_Pointer_PROBE_RESTORE_FAILED_2d94ec39);
    Arena^.Entries[0] := OldEntry; Arena^.Count := OldCount; Slot^.FIndex := OldIndex;
    if not Arena^.Protect(Arena,ArenaBytes,PageReadOnly,Previous) then
      raise EInvalidOpException.Create(CozyText_Api_Pointer_PROBE_RESTORE_FAILED_2d94ec39);
    if Length(Bytes)>0 then FillChar(Bytes[0],Length(Bytes),0);
  end;
end;
{$ENDIF}

initialization

finalization
  { This EXE-owned 64-KiB read-only arena and codec deliberately survive RTL
    unit finalization. A cancelled IO/DNS callback may still be returning and
    decoding a pointer during process teardown. Windows reclaims the pages at
    process exit, together with the pinned API modules. Do not use this unit
    in an unloadable runtime package. Mutable sessions/keys use call gates and
    are drained and freed normally; this is only process-lifetime API metadata. }
end.
