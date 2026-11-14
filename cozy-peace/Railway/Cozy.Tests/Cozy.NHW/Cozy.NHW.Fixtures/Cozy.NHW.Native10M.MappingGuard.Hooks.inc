var
  Mapping10MBackingCalls, Mapping10MPageCalls: Integer;
  Mapping10MFail, Mapping10MChanged: Boolean;
function MappingNativeAvailable: Boolean;
begin Result := True; end;
function QueryMappingBacking(ProcessHandle: THandle; Address: NativeUInt;
  out DevicePath: string): Boolean;
begin
  Inc(Mapping10MBackingCalls);
  DevicePath := '';
  Result := not Mapping10MFail;
  if Result then
    if Mapping10MChanged then DevicePath := 'changed' else DevicePath := 'original';
end;
function QueryMappingWorkingSet(ProcessHandle: THandle;
  var Items: array of TMappingWorkingSetItem; Count: Integer): Boolean;
var I: Integer;
begin
  Inc(Mapping10MPageCalls, Count);
  Result := not Mapping10MFail;
  for I := 0 to Count - 1 do
    if Result then Items[I].Attributes := NativeUInt(1) or (NativeUInt(1) shl 15)
    else Items[I].Attributes := 0;
end;
