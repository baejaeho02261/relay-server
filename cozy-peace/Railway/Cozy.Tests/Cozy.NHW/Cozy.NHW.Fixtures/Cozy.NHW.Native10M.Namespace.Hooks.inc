var Namespace10MMode: Integer; Namespace10MDacl: UInt64;
    Namespace10MEntry: TNamespaceEntry;
function EnumerateNamespace(const NativeDirectory: string; Entries: TNamespaceEntries): Boolean;
begin
  Entries.Clear;
  if Namespace10MMode <> 4 then Entries.Add('NHW.TEST', Namespace10MEntry);
  Result := Namespace10MMode <> 1;
end;
function QueryNamespaceDacl(const NativeDirectory: string; out Signature: UInt64): Boolean;
begin
  if Namespace10MMode = 2 then raise EOutOfMemory.Create('injected after namespace collection');
  Signature := Namespace10MDacl; Result := Namespace10MMode <> 3;
end;
