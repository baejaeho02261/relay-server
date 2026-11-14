function TestCaptureRules10O(out Failure: string; out Checks: Integer): Boolean;
var
  D: string;
  Signals: TCaptureSignals;
  procedure Check(Value: Boolean; const Text: string);
  begin
    Inc(Checks);
    if not Value then raise Exception.Create(Text);
  end;

begin
  Result := False; Failure := ''; Checks := 0;

  try
    try
      D := 'D:\CustomOS\System32';
      Check(CapturePktMonAtDirectory('pktmon.exe', D + '\pktmon.exe', D), 'exact configured OS directory');
      Check(CapturePktMonAtDirectory('PKTMON.EXE', 'd:/customos/system32/PKTMON.EXE', D), 'case and slash normalization');
      Check(CapturePktMonAtDirectory('pktmon.exe', '\\?\' + D + '\pktmon.exe', D), 'explicit extended DOS path');
      Check(CapturePktMonAtDirectory('pktmon.exe', '\??\' + D + '\pktmon.exe', D), 'explicit NT DOS prefix');
      Check(not CapturePktMonAtDirectory('pktmon.exe', 'C:\bait\Windows\System32\pktmon.exe', D), 'suffix impostor rejected');
      Check(not CapturePktMonAtDirectory('pktmon.exe', 'C:\Windows\System32\pktmon.exe', D), 'wrong Windows installation rejected');
      Check(not CapturePktMonAtDirectory('pktmon.exe', D + '\sub\pktmon.exe', D), 'subdirectory rejected');
      Check(not CapturePktMonAtDirectory('pktmon.exe', D + '\pktmon.exe.bak', D), 'suffix extension rejected');
      Check(not CapturePktMonAtDirectory('pktmon.exe', D + '\pktmon.exe:stream', D), 'alternate stream rejected');
      Check(not CapturePktMonAtDirectory('pktmon.exe', D + '\.\pktmon.exe', D), 'dot path not implicitly trusted');
      Check(not CapturePktMonAtDirectory('pktmon.exe', 'System32\pktmon.exe', D), 'relative path rejected');
      Check(not CapturePktMonAtDirectory('pktmon.exe', D + '\pktmon.exe' + #0 + '.evil', D), 'embedded null rejected');
      Check(not CapturePktMonAtDirectory('other.exe', D + '\pktmon.exe', D), 'basename must also match');
      Check(not CapturePktMonAtDirectory('pktmon.exe', D + '\pktmon.exe', ''), 'missing system directory not trusted');
      Check(CaptureSystemDirectory(D), 'Windows system directory API available');
      Check(IsMicrosoftPktMon('pktmon.exe', IncludeTrailingPathDelimiter(D) + 'pktmon.exe'), 'live API path match without file IO');
      Signals := ClassifyCapture('wireshark.exe', 'C:\test\wireshark.exe', [], [], False);
      Check(Signals = [], 'name alone remains insufficient');
      Signals := ClassifyCapture('other.exe', 'C:\test\other.exe', [cfPcap], [cfPcap], False);
      Check((csLibrary in Signals) and (csDriver in Signals) and (csCorrelation in Signals), 'existing corroborated classification unchanged');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    // No owned resources.
  end;
end;
