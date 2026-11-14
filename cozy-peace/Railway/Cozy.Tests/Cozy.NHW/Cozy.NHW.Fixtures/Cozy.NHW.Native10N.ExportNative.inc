var ExportFailBase10N: NativeUInt; ExportCalls10N: Integer;
function ExportModuleMock10N(Base: NativeUInt; out State: TModuleExportState): Boolean;
begin
  Inc(ExportCalls10N); State := Default(TModuleExportState);
  Result := Base <> ExportFailBase10N;
  State.TableHash := UInt64(Base); State.ForwarderHash := 3; State.ApiSetHash := 4;
  State.TargetHash := 5; State.ResolverHash := 6;
  State.ValidTable := True; State.ValidForwarders := True;
  State.ValidTargets := True; State.ValidResolution := True;
end;
function ExportDelayMock10N(out Feature: TPEFeature; out Slots: Cardinal): Boolean;
begin Feature := Default(TPEFeature); Slots := 0; Result := False; end;
function TestExportNative10N(out Failure: string; out Checks: Integer): Boolean;
var S, Complete: TExportSnapshot; B: array[0..2] of NativeUInt;
    Empty: TArray<NativeUInt>; M: TModuleExportState; Data: TBytes; Base: NativeUInt;
  procedure Check(Value: Boolean; const Text: string);
  begin
    Inc(Checks);
    if not Value then raise Exception.Create(Text);
  end;
begin
  Result := False; Failure := ''; Checks := 0;
  Empty := nil; Data := nil;
  try
    try
      ModuleReader10N := ExportModuleMock10N; DelayReader10N := ExportDelayMock10N;
      B[0] := $10000; B[1] := $20000; B[2] := 0;
      ExportFailBase10N := B[1]; ExportCalls10N := 0;
      Check(not CaptureExportSnapshot(B, S), 'required image read failure fails aggregate');
      Check(ExportCalls10N = 2, 'both selected images attempted until failure');
      Check(not S.Table.Available and not S.Target.Available and (S.Table.Digest = 0), 'no partial successful digest published');
      ExportFailBase10N := 0; ExportCalls10N := 0;
      Check(CaptureExportSnapshot(B, Complete), 'complete selection captured');
      Check(Complete.Table.Available and Complete.Table.Valid, 'complete table available');
      Check(ExportCalls10N = 2, 'zero sentinel not treated as missing required module');
      Check(not Complete.DelayImport.Available and (Complete.ResolvedDelaySlots = 0), 'optional failed delay query unavailable');
      B[1] := $30000; Check(CaptureExportSnapshot(B, S), 'changed complete image selection captured');
      Check(S.Table.Digest <> Complete.Table.Digest, 'module identities are included in aggregate');
      Empty := nil; Check(not CaptureExportSnapshot(Empty, S), 'empty selection and absent delay is unavailable');
      ModuleReader10N := nil;
      SetLength(Data, 4096); FillChar(Data[0], Length(Data), 0); Base := NativeUInt(@Data[0]);
      PWord(Pointer(Base))^ := $5A4D; PCardinal(Pointer(Base+$3C))^ := $80;
      PCardinal(Pointer(Base+$80))^ := $4550; PWord(Pointer(Base+$84))^ := $8664;
      PWord(Pointer(Base+$94))^ := $F0; PWord(Pointer(Base+$98))^ := $20B;
      PCardinal(Pointer(Base+$98+56))^ := 4096; PCardinal(Pointer(Base+$98+108))^ := 16;
      Check(ReadModuleExports(Base, M), 'readable image with no exports is an explicit success');
      Check(M.ValidTable and M.ValidTargets, 'normal export absence is valid');
      PCardinal(Pointer(Base+$98+112))^ := $200;
      Check(ReadModuleExports(Base, M) and not M.ValidTable, 'one-sided export directory is malformed, not absent');
      Check(not ReadModuleExports(1, M), 'invalid/unreadable base is not a successful empty image');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    ModuleReader10N := nil; DelayReader10N := nil;
  end;
end;
