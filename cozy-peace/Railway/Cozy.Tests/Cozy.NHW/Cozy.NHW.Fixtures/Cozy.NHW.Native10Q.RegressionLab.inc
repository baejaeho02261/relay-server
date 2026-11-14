function TestRegressionLab10Q(out Failure: string; out Checks: Integer): Boolean;
begin
  Result := ValidateSectionIdentityRegression(Failure, Checks);
end;
