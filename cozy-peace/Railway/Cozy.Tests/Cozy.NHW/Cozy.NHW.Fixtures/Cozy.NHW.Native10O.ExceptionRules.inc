function TestExceptionRules10O(out Failure: string; out Checks: Integer): Boolean;
var
  Bytes: Cardinal;
  procedure Check(Value: Boolean; const Text: string);
  begin
    Inc(Checks);
    if not Value then raise Exception.Create(Text);
  end;

begin
  Result := False; Failure := ''; Checks := 0;

  try
    try
      Check(ExceptionUnwindHeaderValid(1, 0, $1000, $1004, Bytes) and (Bytes = 4), 'zero-code header');
      Check(ExceptionUnwindHeaderValid(1, 3, $1000, $100C, Bytes) and (Bytes = 12), 'odd code count aligned');
      Check(ExceptionUnwindHeaderValid(9, 3, $1000, $1010, Bytes) and (Bytes = 16), 'EHANDLER RVA trailer');
      Check(ExceptionUnwindHeaderValid(17, 3, $1000, $1010, Bytes) and (Bytes = 16), 'UHANDLER RVA trailer');
      Check(ExceptionUnwindHeaderValid(25, 3, $1000, $1010, Bytes) and (Bytes = 16), 'combined handler flags use one RVA');
      Check(ExceptionUnwindHeaderValid(33, 3, $1000, $1018, Bytes) and (Bytes = 24), 'CHAININFO triple RVA trailer');
      Check(not ExceptionUnwindHeaderValid(9, 3, $1000, $100F, Bytes) and (Bytes = 0), 'handler truncation rejected');
      Check(not ExceptionUnwindHeaderValid(33, 3, $1000, $1017, Bytes) and (Bytes = 0), 'chain truncation rejected');
      Check(not ExceptionUnwindHeaderValid(41, 0, $1000, $2000, Bytes), 'EH plus CHAIN rejected');
      Check(not ExceptionUnwindHeaderValid(49, 0, $1000, $2000, Bytes), 'UH plus CHAIN rejected');
      Check(not ExceptionUnwindHeaderValid(57, 0, $1000, $2000, Bytes), 'both handlers plus CHAIN rejected');
      Check(not ExceptionUnwindHeaderValid(0, 0, $1000, $2000, Bytes), 'zero version rejected');
      Check(not ExceptionUnwindHeaderValid(4, 0, $1000, $2000, Bytes), 'unknown version policy unchanged');
      Check(ExceptionUnwindHeaderValid(2, 0, $1000, $1004, Bytes), 'existing v2 support retained');
      Check(ExceptionUnwindHeaderValid(3, 0, $1000, $1004, Bytes), 'existing v3 support retained');
      Check(not ExceptionUnwindHeaderValid(1, 0, $1001, $2000, Bytes), 'misaligned unwind RVA rejected');
      Check(not ExceptionUnwindHeaderValid(1, 0, $2000, $1000, Bytes), 'RVA beyond image rejected without underflow');
      Check(ExceptionUnwindHeaderValid(33, 255, $1000, $1210, Bytes) and (Bytes = 528), 'maximum code count bounded');
      Check(not ExceptionUnwindHeaderValid(1, 0, $FFFFFFFC, High(Cardinal), Bytes), 'end-of-address-range bounded');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    // No owned resources.
  end;
end;
