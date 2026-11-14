function TestAdvancedRegressionV8010Q(out Failure: string; out Checks: Integer): Boolean;
begin
  Result := ValidateV80StateSequences(Failure, Checks);
end;
