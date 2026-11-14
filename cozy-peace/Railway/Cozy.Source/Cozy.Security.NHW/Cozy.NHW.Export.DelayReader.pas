unit Cozy.NHW.Export.DelayReader;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows, Cozy.NHW.ExportRules, Cozy.NHW.PERules;

const
  MAX_DELAY_DESCRIPTORS = 64;
  MAX_DELAY_SLOTS = 4096;

type
  TDelayDescriptor = packed record
    Attributes: Cardinal;
    DllName: Cardinal;
    ModuleHandleSlot: Cardinal;
    ImportAddressTable: Cardinal;
    ImportNameTable: Cardinal;
    BoundImportTable: Cardinal;
    UnloadImportTable: Cardinal;
    Timestamp: Cardinal;
  end;

function CaptureDelayImports(out Feature: TPEFeature;
  out ResolvedSlots: Cardinal; out Detail: TDelaySlotSnapshot): Boolean;

implementation

uses
  System.SysUtils, System.Generics.Collections, System.Generics.Defaults, Cozy.NHW.Export.ImageReader;

function CaptureDelayImports(out Feature: TPEFeature;
  out ResolvedSlots: Cardinal; out Detail: TDelaySlotSnapshot): Boolean;
var
  Image: TImageInfo;
  Desc, DescAgain: TDelayDescriptor;
  DescCopies: array[0..MAX_DELAY_DESCRIPTORS-1] of TDelayDescriptor;
  A, DAddress, UAddress: NativeUInt;
  I, J, NumDesc, Total, DescriptorsRead, Resolved: Cardinal;
  TargetVA, AgainVA, UnloadVA: UInt64;
  S: AnsiString;
  IsLocal, Terminated, DescriptorsEnded: Boolean;
  Hash, LayoutHash: UInt64;
  Items: TDelaySlotObservations;
  Slot: TDelaySlotObservation;
  N: Integer;
begin
  Feature := Default(TPEFeature);
  ResolvedSlots := 0;
  Detail := Default(TDelaySlotSnapshot);
  Result := False;
  if not ReadImageInfo(NativeUInt(HInstance), Image) then Exit;
  if (Image.DelayRVA = 0) and (Image.DelaySize = 0) then
  begin
    Feature.Available := True;
    Feature.Valid := True;
    Feature.Digest := ExportHash(HASH_SEED, 0);
    Detail.ImageBase := Image.Base;
    Detail.LayoutDigest := ExportHash(HASH_SEED, 0);
    Detail.Complete := True;
    Exit(True);
  end;
  // Unknown/malformed/unstable tables remain unavailable. No partial slot list
  // or count escapes, and this routine never invokes the delay-load helper.
  if (Image.DelaySize < SizeOf(TDelayDescriptor)) or
     not WithinImage(Image, Image.DelayRVA, Image.DelaySize) then Exit;
  NumDesc := Image.DelaySize div SizeOf(TDelayDescriptor);
  if (NumDesc = 0) or (NumDesc > MAX_DELAY_DESCRIPTORS) then Exit;
  SetLength(Items, MAX_DELAY_SLOTS);
  Hash := HASH_SEED;
  LayoutHash := ExportHash(HASH_SEED, Image.DelayRVA);
  Total := 0; Resolved := 0; DescriptorsRead := 0;
  DescriptorsEnded := False;
  for I := 0 to NumDesc - 1 do
  begin
    if not MapAddress(Image,
      Image.DelayRVA + I * Cardinal(SizeOf(TDelayDescriptor)),
      SizeOf(TDelayDescriptor), DAddress) then Exit;
    if not SafeRead(DAddress, Desc, SizeOf(Desc)) then Exit;
    DescCopies[I] := Desc;
    Inc(DescriptorsRead);
    if (Desc.Attributes = 0) and (Desc.DllName = 0) and
       (Desc.ModuleHandleSlot = 0) and (Desc.ImportAddressTable = 0) and
       (Desc.ImportNameTable = 0) and (Desc.BoundImportTable = 0) and
       (Desc.UnloadImportTable = 0) and (Desc.Timestamp = 0) then
    begin
      DescriptorsEnded := True;
      Break;
    end;
    if (Desc.Attributes <> 1) or (Desc.ImportAddressTable = 0) then Exit;
    if not ReadAsciiRVA(Image, Desc.DllName, 160, S) then Exit;
    Hash := HashText(Hash, S);
    LayoutHash := HashText(LayoutHash, S);
    LayoutHash := ExportHash(LayoutHash, Desc.ImportAddressTable);
    LayoutHash := ExportHash(LayoutHash, Desc.ImportNameTable);
    LayoutHash := ExportHash(LayoutHash, Desc.UnloadImportTable);
    LayoutHash := ExportHash(LayoutHash, Desc.ModuleHandleSlot);
    Terminated := False;
    for J := 0 to MAX_DELAY_SLOTS - 1 do
    begin
      if not WithinImage(Image, Desc.ImportAddressTable, 8) or
         (J > (Image.Size - Desc.ImportAddressTable - 8) div 8) then Exit;
      if not MapAddress(Image, Desc.ImportAddressTable + J * 8, 8, A) then Exit;
      if not ReadU64(A, TargetVA) then Exit;
      if TargetVA = 0 then
      begin
        Terminated := True;
        Break;
      end;
      if Total >= MAX_DELAY_SLOTS then Exit;
      Slot := Default(TDelaySlotObservation);
      Slot.SlotAddress := A;
      Slot.TargetAddress := NativeUInt(TargetVA);
      IsLocal := (TargetVA >= UInt64(Image.Base)) and
        (TargetVA - UInt64(Image.Base) < UInt64(Image.Size));
      Slot.Resolved := not IsLocal;
      if not IsLocal then
      begin
        if not ExecutableMappedImage(NativeUInt(TargetVA)) then Exit;
        Inc(Resolved);
        Hash := ExportHash(Hash, UInt64(I));
        Hash := ExportHash(Hash, UInt64(J));
        Hash := ExportHash(Hash, TargetVA);
      end;
      if Desc.UnloadImportTable <> 0 then
      begin
        if not WithinImage(Image, Desc.UnloadImportTable, 8) or
           (J > (Image.Size - Desc.UnloadImportTable - 8) div 8) then Exit;
        if not MapAddress(Image, Desc.UnloadImportTable + J * 8, 8, UAddress) or
           not ReadU64(UAddress, UnloadVA) then Exit;
        if (UnloadVA < UInt64(Image.Base)) or
           (UnloadVA - UInt64(Image.Base) >= UInt64(Image.Size)) then Exit;
        Slot.UnloadTarget := NativeUInt(UnloadVA);
      end;
      Items[Integer(Total)] := Slot;
      Inc(Total);
    end;
    if not Terminated then Exit;
    // A concurrent helper resolution/unload is retried on a future sweep.
    for N := 0 to Integer(J) do
    begin
      if not MapAddress(Image, Desc.ImportAddressTable + Cardinal(N) * 8, 8, A) or
         not ReadU64(A, AgainVA) then Exit;
      if Cardinal(N) = J then
      begin if AgainVA <> 0 then Exit; end
      else if AgainVA <> UInt64(Items[Integer(Total - J) + N].TargetAddress) then Exit;
    end;
  end;
  if not DescriptorsEnded then Exit;
  // Recheck descriptors (including the terminator) before publishing a view.
  for I := 0 to DescriptorsRead - 1 do
  begin
    if not MapAddress(Image, Image.DelayRVA + I * Cardinal(SizeOf(Desc)),
      SizeOf(Desc), DAddress) or not SafeRead(DAddress, DescAgain, SizeOf(DescAgain)) then Exit;
    if not CompareMem(@DescCopies[I], @DescAgain, SizeOf(DescAgain)) then Exit;
  end;
  SetLength(Items, Integer(Total));
  TArray.Sort<TDelaySlotObservation>(Items,
    TComparer<TDelaySlotObservation>.Construct(
      function(const L, R: TDelaySlotObservation): Integer
      begin
        if L.SlotAddress < R.SlotAddress then Result := -1
        else if L.SlotAddress > R.SlotAddress then Result := 1
        else Result := 0;
      end));
  for N := 0 to Length(Items) - 1 do
  begin
    if N > 0 then
      if Items[N-1].SlotAddress = Items[N].SlotAddress then Exit;
    if not ReadU64(Items[N].SlotAddress, AgainVA) or
       (AgainVA <> UInt64(Items[N].TargetAddress)) then Exit;
    LayoutHash := ExportHash(LayoutHash, UInt64(Items[N].SlotAddress));
    LayoutHash := ExportHash(LayoutHash, UInt64(Items[N].UnloadTarget));
  end;
  Detail.ImageBase := Image.Base;
  Detail.LayoutDigest := ExportHash(LayoutHash, UInt64(Total));
  Detail.Slots := Items;
  Detail.Complete := True;
  Feature.Available := True;
  Feature.Valid := True;
  Feature.Digest := ExportHash(Hash, Resolved);
  ResolvedSlots := Resolved;
  Result := True;
end;

end.
