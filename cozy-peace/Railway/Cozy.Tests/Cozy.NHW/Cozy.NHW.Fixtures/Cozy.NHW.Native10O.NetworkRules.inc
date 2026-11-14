type
  T10OFaultStrings = class(TStrings)
  protected
    function Get(Index: Integer): string; override;
    function GetCount: Integer; override;
  public
    procedure Clear; override;
    procedure Delete(Index: Integer); override;
    procedure Insert(Index: Integer; const S: string); override;
  end;
function T10OFaultStrings.Get(Index: Integer): string;
begin
  if Index = 1 then raise EOutOfMemory.Create('injected source read failure');
  Result := 'partial';
end;
function T10OFaultStrings.GetCount: Integer;
begin Result := 3; end;
procedure T10OFaultStrings.Clear;
begin end;
procedure T10OFaultStrings.Delete(Index: Integer);
begin raise Exception.Create('unused'); end;
procedure T10OFaultStrings.Insert(Index: Integer; const S: string);
begin raise Exception.Create('unused'); end;

function TestNetworkRules10O(out Failure: string; out Checks: Integer): Boolean;
var
  G: TChangeGate;
  A, B: TStringList;
  Broken: T10OFaultStrings;
  OldAccepted: TStringList;
  Raised: Boolean;
  procedure Check(Value: Boolean; const Text: string);
  begin
    Inc(Checks);
    if not Value then raise Exception.Create(Text);
  end;

begin
  Result := False; Failure := ''; Checks := 0;
  G := nil; A := nil; B := nil; Broken := nil;
  try
    try
      G := TChangeGate.Create; A := TStringList.Create; B := TStringList.Create;
      Broken := T10OFaultStrings.Create;
      A.Add('a'); B.Add('b');
      Check(not G.Observe(A), 'first complete baseline');
      Check(G.FHasBaseline and (G.FAccepted[0] = 'a'), 'baseline accepted');
      Check(not G.Observe(B) and (G.FCandidateHits = 1), 'first changed candidate');
      OldAccepted := G.FAccepted; Raised := False;
      try G.Observe(Broken); except on X: EOutOfMemory do Raised := True; end;
      Check(Raised, 'injected partial copy failed');
      Check((G.FAccepted = OldAccepted) and (G.FAccepted.Count = 1) and
        (G.FAccepted[0] = 'a'), 'allocation failure leaves accepted pointer and keys intact');
      Check((G.FCandidateHits = 0) and (G.FCandidate.Count = 0), 'failed copy breaks pending sequence');
      Check(not G.Observe(B), 'first new success after gap is not confirmed');
      Check(G.Observe(B), 'second complete success confirms');
      Check((G.FAccepted[0] = 'b') and (G.FAccepted <> OldAccepted), 'accepted snapshot replaced by swap');
      Check(not G.Observe(B), 'accepted snapshot is stable');
      Check(not G.Observe(A), 'new change begins');
      Check(not G.Observe(nil), 'nil observation not accepted');
      Check((G.FAccepted[0] = 'b') and (G.FCandidateHits = 0), 'nil preserves baseline and clears candidate');
      Check(not G.Observe(A), 'gap requires first observation again');
      Check(G.Observe(A), 'fresh pair can be accepted');
      G.Reset; Check(not G.FHasBaseline, 'reset clears baseline');
      B.Clear; Check(not G.Observe(B) and G.FHasBaseline, 'empty complete snapshot is valid');
      Check(not G.Observe(B), 'empty unchanged snapshot stable');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    Broken.Free; B.Free; A.Free; G.Free;
  end;
end;
