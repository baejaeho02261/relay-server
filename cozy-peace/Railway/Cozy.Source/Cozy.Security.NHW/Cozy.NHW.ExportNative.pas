unit Cozy.NHW.ExportNative;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  Cozy.NHW.ExportRules;

// Read only the current process's mapped PE *metadata*. The supplied bases
// must be modules the loader already has mapped. Never load a DLL merely to
// inspect it, never dereference a pointer belonging to a different process.
function CaptureExportSnapshot(const Bases: array of NativeUInt;
  out Snapshot: TExportSnapshot): Boolean;

{$IFDEF NHW_NATIVE10N_TESTS}
function TestExportNative10N(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  System.SysUtils,
  System.Generics.Collections, System.Generics.Defaults,
  Cozy.NHW.PERules,
  Cozy.NHW.WinPointers,
  Cozy.NHW.AllocationNative,
  Cozy.NHW.Export.ImageReader, Cozy.NHW.Export.DelayReader;

const
  MAX_EXPORT_FUNCTIONS = 16384;
  MAX_EXPORT_NAMES = 16384;
  MAX_FORWARDER_LENGTH = 240;

type
  TExportDirectory = packed record
    Characteristics: Cardinal;
    TimeStamp: Cardinal;
    Major: Word;
    Minor: Word;
    NameRVA: Cardinal;
    OrdinalBase: Cardinal;
    CountFunctions: Cardinal;
    CountNames: Cardinal;
    EAT: Cardinal;
    NamePointers: Cardinal;
    NameOrdinals: Cardinal;
  end;

  TModuleExportState = record
    TableHash: UInt64;
    ForwarderHash: UInt64;
    ApiSetHash: UInt64;
    TargetHash: UInt64;
    ResolverHash: UInt64;
    Forwarders: Cardinal;
    ApiSets: Cardinal;
    TargetSamples: Cardinal;
    ValidTable: Boolean;
    ValidForwarders: Boolean;
    ValidTargets: Boolean;
    ValidResolution: Boolean;
  end;

{$IFDEF NHW_NATIVE10N_TESTS}
type
  TModuleReader10N = function(Base: NativeUInt; out State: TModuleExportState): Boolean;
  TDelayReader10N = function(out Feature: TPEFeature; out Slots: Cardinal): Boolean;
var
  ModuleReader10N: TModuleReader10N = nil;
  DelayReader10N: TDelayReader10N = nil;
{$ENDIF}

function ImportantFunction(const Name: AnsiString): Boolean;
begin
  Result := (Name = 'NtQuerySystemInformation') or
    (Name = 'NtOpenProcess') or (Name = 'NtClose') or
    (Name = 'NtQueryVirtualMemory') or
    (Name = 'NtQueryInformationThread') or
    (Name = 'GetProcAddress') or (Name = 'GetModuleHandleW') or
    (Name = 'GetCurrentProcessId') or (Name = 'Sleep') or
    (Name = 'VirtualProtect') or (Name = 'VirtualQuery') or
    (Name = 'CreateThread') or (Name = 'CreateRemoteThread') or
    (Name = 'LoadLibraryW');
end;

function ReadModuleExports(Base: NativeUInt;
  out State: TModuleExportState): Boolean;
var
  Image: TImageInfo;
  Dir: TExportDirectory;
  A, FnAddress: NativeUInt;
  NameRVA: Cardinal;
  OrdIndex: Word;
  I, J: Cardinal;
  ExportRVA: Cardinal;
  S: AnsiString;
  IsForwarder, KnownFunction, AnySample: Boolean;
  Resolved: Pointer;
  CountNamedSamples: Cardinal;
  GoodRVAs, TargetExecutable: Boolean;
  TargetRegion: TVirtualRegion;
  EatAddress, NameAddress, OrdAddress: NativeUInt;
  EATEntries, NameEntries: PCardinal;
  OrdEntries: PWord;
begin
  State := Default(TModuleExportState);
  Result := False;
  NameEntries := nil;
  OrdEntries := nil;
  if not ReadImageInfo(Base, Image) then Exit;
  // A readable module with NO exports is a valid, explicit member of the
  // snapshot, not an unreadable module to silently omit from the hash.
  Result := True;
  State.TableHash := ExportHash(HASH_SEED, UInt64(Base));
  State.ForwarderHash := HASH_SEED;
  State.ApiSetHash := HASH_SEED;
  State.TargetHash := HASH_SEED;
  State.ResolverHash := HASH_SEED;
  State.ValidTable := False;
  GoodRVAs := True;
  State.ValidForwarders := True;
  State.ValidTargets := True;
  State.ValidResolution := True;
  if (Image.ExportRVA = 0) and (Image.ExportSize = 0) then
  begin
    State.ValidTable := True;
    Exit;
  end;
  if (Image.ExportRVA = 0) or (Image.ExportSize = 0) then Exit;
  if not MapAddress(Image, Image.ExportRVA, SizeOf(TExportDirectory), A) then Exit;
  if not SafeRead(A, Dir, SizeOf(Dir)) then Exit(False);
  if not WithinImage(Image, Image.ExportRVA, Image.ExportSize) or
     (Dir.CountFunctions = 0) or
     (Dir.CountFunctions > MAX_EXPORT_FUNCTIONS) or
     (Dir.CountNames > MAX_EXPORT_NAMES) or
     (Dir.CountNames > Dir.CountFunctions) or
     not WithinImage(Image, Dir.EAT, Dir.CountFunctions * 4) then Exit;
  if Dir.CountNames <> 0 then
    if not WithinImage(Image, Dir.NamePointers, Dir.CountNames * 4) or
       not WithinImage(Image, Dir.NameOrdinals, Dir.CountNames * 2) then Exit;
  // Validate the *full* table spans once; no per-element NT query.
  if not MapAddress(Image, Dir.EAT, Dir.CountFunctions * 4, EatAddress) then Exit;
  if not ReadableLocal(EatAddress, Dir.CountFunctions * 4) then Exit(False);
  EATEntries := Pointer(EatAddress);
  if Dir.CountNames <> 0 then
  begin
    if not MapAddress(Image, Dir.NamePointers, Dir.CountNames * 4, NameAddress) or
       not MapAddress(Image, Dir.NameOrdinals, Dir.CountNames * 2, OrdAddress) then Exit;
    if not ReadableLocal(NameAddress, Dir.CountNames * 4) or
       not ReadableLocal(OrdAddress, Dir.CountNames * 2) then Exit(False);
    NameEntries := Pointer(NameAddress);
    OrdEntries := Pointer(OrdAddress);
  end;
  State.TableHash := ExportHash(State.TableHash, UInt64(Base));
  State.TableHash := ExportHash(State.TableHash, Dir.CountFunctions);
  State.TableHash := ExportHash(State.TableHash, Dir.CountNames);
  State.TableHash := ExportHash(State.TableHash, Dir.OrdinalBase);
  try
  for I := 0 to Dir.CountFunctions - 1 do
  begin
    ExportRVA := PCardinal(NativeUInt(EATEntries) + NativeUInt(I) * 4)^;
    State.TableHash := ExportHash(State.TableHash, ExportRVA);
    if ExportRVA = 0 then Continue;
    IsForwarder := (ExportRVA >= Image.ExportRVA) and
      (ExportRVA - Image.ExportRVA < Image.ExportSize);
    if IsForwarder then
    begin
      Inc(State.Forwarders);
      if not ReadAsciiRVA(Image, ExportRVA, MAX_FORWARDER_LENGTH, S) then
        Exit(False); // Incomplete string read cannot form an aggregate digest.
      State.ForwarderHash := HashText(State.ForwarderHash, S);
      if not IsValidForwarder(S) then State.ValidForwarders := False;
      if IsApiSetContract(S) then
      begin
        Inc(State.ApiSets);
        State.ApiSetHash := HashText(State.ApiSetHash, S);
      end;
    end
    else if not WithinImage(Image, ExportRVA, 1) then
      GoodRVAs := False;
  end;
  CountNamedSamples := 0;
  AnySample := False;
  if Dir.CountNames > 0 then
  for J := 0 to Dir.CountNames - 1 do
  begin
    NameRVA := PCardinal(NativeUInt(NameEntries) + NativeUInt(J) * 4)^;
    OrdIndex := PWord(NativeUInt(OrdEntries) + NativeUInt(J) * 2)^;
    if OrdIndex >= Dir.CountFunctions then Exit;
    // Named exports may legitimately be data. Only explicitly selected
    // function names are checked for executable image ownership.
    if not ReadAsciiRVA(Image, NameRVA, 160, S) then Exit(False);
    State.TableHash := HashText(State.TableHash, S);
    State.TableHash := ExportHash(State.TableHash, OrdIndex);
    KnownFunction := ImportantFunction(S);
    if not KnownFunction then Continue;
    Inc(CountNamedSamples);
    AnySample := True;
    ExportRVA := PCardinal(NativeUInt(EATEntries) + NativeUInt(OrdIndex) * 4)^;
    if ExportRVA = 0 then
    begin
      State.ValidResolution := False;
      Continue;
    end;
    IsForwarder := (ExportRVA >= Image.ExportRVA) and
      (ExportRVA - Image.ExportRVA < Image.ExportSize);
    // Resolving an external forwarder may cause loader side effects. The
    // forwarder is therefore checked as metadata above, not invoked here.
    // Direct EAT functions can be compared with GetProcAddress safely.
    if IsForwarder then Continue;
    Resolved := WinExport(HMODULE(Base), S);
    if Resolved = nil then
    begin
      // This selected direct export was part of the expected sample set.
      // Omitting it would change the aggregate merely because a query failed.
      Exit(False);
    end;
    State.ResolverHash := HashText(State.ResolverHash, S);
    State.ResolverHash := ExportHash(State.ResolverHash, UInt64(NativeUInt(Resolved)));
    if not QueryVirtualRegion(WinCurrentProcess, NativeUInt(Resolved),
      TargetRegion) then Exit(False);
    TargetExecutable := (TargetRegion.RegionType = ALLOC_MEM_IMAGE) and
      RegionIsExecutable(TargetRegion);
    if not TargetExecutable then State.ValidTargets := False;
    if not IsForwarder then
    begin
      if not MapAddress(Image, ExportRVA, 1, FnAddress) then
        State.ValidResolution := False
      else if NativeUInt(Resolved) <> FnAddress then
        State.ValidResolution := False;
    end;
    State.TargetHash := HashText(State.TargetHash, S);
    State.TargetHash := ExportHash(State.TargetHash, UInt64(OrdIndex));
    State.TargetHash := ExportHash(State.TargetHash,
      UInt64(Ord(TargetExecutable)));
  end;
  State.TableHash := ExportHash(State.TableHash, State.Forwarders);
  State.ForwarderHash := ExportHash(State.ForwarderHash, State.Forwarders);
  State.ApiSetHash := ExportHash(State.ApiSetHash, State.ApiSets);
  State.TargetHash := ExportHash(State.TargetHash, CountNamedSamples);
  State.ResolverHash := ExportHash(State.ResolverHash, CountNamedSamples);
  // Avoid classifying data exports as executable functions. Invalid RVAs
  // still indicate an EAT metadata error, not attribution of a writer.
  State.ValidTable := GoodRVAs;
  if not AnySample then
  begin
    State.ValidTargets := True;
    State.ValidResolution := True;
  end;
  except
    Result := False;  // Memory changed mid-snapshot: treat as unavailable.
  end;
end;

function CaptureExportSnapshot(const Bases: array of NativeUInt;
  out Snapshot: TExportSnapshot): Boolean;
var
  I: Integer;
  M: TModuleExportState;
  Work: TExportSnapshot;
  Modules: Cardinal;
  ModuleOK, DelayOK: Boolean;
begin
  Snapshot := Default(TExportSnapshot);
  Work := Default(TExportSnapshot);
  Result := False;
  Work.Table.Digest := HASH_SEED;
  Work.Forwarder.Digest := HASH_SEED;
  Work.ApiSet.Digest := HASH_SEED;
  Work.Target.Digest := HASH_SEED;
  Work.Resolution.Digest := HASH_SEED;
  Work.Table.Valid := True;
  Work.Forwarder.Valid := True;
  Work.ApiSet.Valid := True;
  Work.Target.Valid := True;
  Work.Resolution.Valid := True;
  Modules := 0;
  for I := Low(Bases) to High(Bases) do
  begin
    // Zero is the caller's explicit "not selected" sentinel, not a read failure.
    if Bases[I] = 0 then Continue;
    M := Default(TModuleExportState);
    {$IFDEF NHW_NATIVE10N_TESTS}
    if Assigned(ModuleReader10N) then
      ModuleOK := ModuleReader10N(Bases[I], M)
    else
    {$ENDIF}
      ModuleOK := ReadModuleExports(Bases[I], M);
    if not ModuleOK then Exit; // publish none of this partial capture
    Inc(Modules);
    Work.Table.Digest := ExportHash(ExportHash(Work.Table.Digest, Bases[I]), M.TableHash);
    Work.Forwarder.Digest := ExportHash(ExportHash(Work.Forwarder.Digest, Bases[I]), M.ForwarderHash);
    Work.ApiSet.Digest := ExportHash(ExportHash(Work.ApiSet.Digest, Bases[I]), M.ApiSetHash);
    Work.Target.Digest := ExportHash(ExportHash(Work.Target.Digest, Bases[I]), M.TargetHash);
    Work.Resolution.Digest := ExportHash(ExportHash(Work.Resolution.Digest, Bases[I]), M.ResolverHash);
    Work.Table.Valid := Work.Table.Valid and M.ValidTable;
    Work.Forwarder.Valid := Work.Forwarder.Valid and M.ValidForwarders;
    Work.ApiSet.Valid := Work.ApiSet.Valid and M.ValidForwarders;
    Work.Target.Valid := Work.Target.Valid and M.ValidTargets;
    Work.Resolution.Valid := Work.Resolution.Valid and M.ValidResolution;
  end;
  if Modules > 0 then
  begin
    Work.Table.Available := True;
    Work.Forwarder.Available := True;
    Work.ApiSet.Available := True;
    Work.Target.Available := True;
    Work.Resolution.Available := True;
  end;
  {$IFDEF NHW_NATIVE10N_TESTS}
  if Assigned(DelayReader10N) then
    DelayOK := DelayReader10N(Work.DelayImport, Work.ResolvedDelaySlots)
  else
  {$ENDIF}
    DelayOK := CaptureDelayImports(Work.DelayImport, Work.ResolvedDelaySlots,
      Work.DelaySlots);
  if not DelayOK or not Work.DelayImport.Available then
  begin
    Work.DelayImport := Default(TPEFeature);
    Work.ResolvedDelaySlots := 0;
    Work.DelaySlots := Default(TDelaySlotSnapshot);
  end;
  Result := (Modules > 0) or Work.DelayImport.Available;
  if Result then Snapshot := Work;
end;

{$IFDEF NHW_NATIVE10N_TESTS}
{$I Cozy.NHW.Native10N.ExportNative.inc}
{$ENDIF}

end.
