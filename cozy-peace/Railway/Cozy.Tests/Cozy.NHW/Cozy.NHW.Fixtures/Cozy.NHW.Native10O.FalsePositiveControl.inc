function TestFalsePositiveControl10O(out Failure: string; out Checks: Integer): Boolean;
var
  G: TNewSignalSuppressor;
  Raw, Saved, Visible, Legacy: TDetectionKinds;
  K: TDetectionKind;
  procedure Check(Value: Boolean; const Text: string);
  begin
    Inc(Checks);
    if not Value then raise Exception.Create(Text);
  end;

begin
  Result := False; Failure := ''; Checks := 0;
  G := nil;
  try
    try
      G := TNewSignalSuppressor.Create;
      Raw := [dkProcess, dkImportRedirect, dkTLSCallbackIntegrity, dkUnwindStructural,
        dkExecutableLifecycle, dkSectionBacking, dkThreadStackOrigin]; Saved := Raw;
      Visible := G.FilterForOutput(Raw, False, 1000);
      Check((Visible = Raw) and (Raw = Saved), 'first output preserves input');
      Visible := G.FilterForOutput(Raw, False, 1001);
      Check(Visible = [dkProcess], 'repeated six labels suppressed only in output copy');
      Check(Raw = Saved, 'internal evidence remains complete after suppression');
      Visible := G.FilterForOutput(Raw, False, 60999);
      Check(Visible = [dkProcess], 'cooldown boundary not early');
      Visible := G.FilterForOutput(Raw, False, 61000);
      Check(Visible = Raw, 'cooldown boundary allows labels');
      G.Reset;
      Visible := G.FilterForOutput(Raw, True, 1000);
      Check(Visible = [dkProcess], 'baseline filters only new labels');
      Check(Raw = Saved, 'baseline cannot erase internal signals');
      Visible := G.FilterForOutput(Raw, False, 1001);
      Check(Visible = Raw, 'baseline does not consume first report');
      Visible := G.FilterForOutput(Raw, False, 999);
      Check(Visible = Raw, 'backwards tick does not indefinitely suppress');
      Legacy := [];
      for K := Low(TDetectionKind) to High(TDetectionKind) do
        if not IsV60Signal(K) then Include(Legacy, K);
      Visible := G.FilterForOutput(Legacy, True, 1000);
      Check(Visible = Legacy, 'all other signal categories preserved even in baseline');
      Check(G.FilterForOutput([], False, 1001) = [], 'empty observations remain empty');
      Check(ShouldSuppressNewSignal(True, 1, 2, 60000), 'legacy helper preserved');
      Check(not ShouldSuppressNewSignal(True, 2, 1, 60000), 'legacy helper handles reversal');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    G.Free;
  end;
end;
