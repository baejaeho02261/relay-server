// Included only by NHW.AdvancedPrivacyRegressionV100 with the AA test define.
// Executes the REAL allocation/cleanup path; not a mock reconstruction.
function TestPrivacyConstructionAA(out Failure: string; out Checks: Integer): Boolean;
var
  Boundary: Integer;
  Detail: string;
  Completed, Raised: Boolean;
  ExpectedMask: Cardinal;
  procedure Check(Value: Boolean; const Why: string);
  begin
    Inc(Checks);
    if not Value then raise Exception.Create(Why);
  end;
begin
  Result := False;
  Failure := '';
  Checks := 0;
  if PrivacyProbeActive then
  begin Failure := 'privacy fixture is already active'; Exit; end;
  try
    try
      for Boundary := 1 to 9 do
      begin
        PrivacyProbeActive := True;
        PrivacyProbeFailAt := Boundary;
        PrivacyProbeAttempts := 0;
        PrivacyProbeCreatedMask := 0;
        PrivacyProbeReleasedMask := 0;
        PrivacyProbeDoubleRelease := False;
        Raised := False;
        Completed := False;
        Detail := '';
        try
          Completed := ValidatePrivacyV100(Detail);
        except
          on E: EPrivacyConstructionProbe do Raised := True;
        end;
        ExpectedMask := (Cardinal(1) shl (Boundary - 1)) - 1;
        Check(Raised, 'construction exception must propagate');
        Check(not Completed, 'interrupted suite cannot complete');
        Check(Detail = '', 'construction exception is not a rule-test failure');
        Check(PrivacyProbeAttempts = Boundary, 'no construction after failure');
        Check(PrivacyProbeCreatedMask = ExpectedMask, 'created resources match boundary');
        Check(PrivacyProbeReleasedMask = ExpectedMask, 'all acquired resources released');
        Check(not PrivacyProbeDoubleRelease, 'no double cleanup');
        PrivacyProbeActive := False;
      end;
      Result := True;
    except
      on E: Exception do Failure := E.ClassName + ': ' + E.Message;
    end;
  finally
    PrivacyProbeActive := False;
    PrivacyProbeFailAt := 0;
    PrivacyProbeAttempts := 0;
    PrivacyProbeCreatedMask := 0;
    PrivacyProbeReleasedMask := 0;
    PrivacyProbeDoubleRelease := False;
  end;
end;
