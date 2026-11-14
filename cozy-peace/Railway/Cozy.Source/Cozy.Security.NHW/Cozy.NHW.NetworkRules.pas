unit Cozy.NHW.NetworkRules;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  System.SysUtils,
  System.Classes;

type
  // A complete snapshot must be stable in two successive observations before
  // it replaces the accepted snapshot. Incomplete probes must not call Observe.
  TChangeGate = class
  private
    FAccepted: TStringList;
    FCandidate: TStringList;
    FCandidateHits: Integer;
    FHasBaseline: Boolean;
    class function SameKeys(A, B: TStrings): Boolean; static;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    function Observe(Current: TStrings): Boolean;
  end;

{$IFDEF NHW_NATIVE10O_TESTS}
function TestNetworkRules10O(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

class function TChangeGate.SameKeys(A, B: TStrings): Boolean;
var I: Integer;
begin
  if A.Count <> B.Count then Exit(False);
  for I := 0 to A.Count - 1 do
    if A[I] <> B[I] then Exit(False);
  Result := True;
end;

constructor TChangeGate.Create;
begin
  inherited Create;
  FAccepted := TStringList.Create;
  FCandidate := TStringList.Create;
  Reset;
end;

destructor TChangeGate.Destroy;
begin
  FCandidate.Free;
  FAccepted.Free;
  inherited Destroy;
end;

procedure TChangeGate.Reset;
begin
  FAccepted.Clear;
  FCandidate.Clear;
  FHasBaseline := False;
  FCandidateHits := 0;
end;

procedure BreakChangeCandidate(Gate: TChangeGate);
begin
  Gate.FCandidate.Clear;
  Gate.FCandidateHits := 0;
end;

procedure SwapChangeList(var A, B: TStringList);
var T: TStringList;
begin
  T := A;
  A := B;
  B := T;
end;

function ApplyCompleteChangeSnapshot(Gate: TChangeGate;
  var NextKeys: TStringList): Boolean;
begin
  Result := False;
  if not Gate.FHasBaseline then
  begin
    SwapChangeList(Gate.FAccepted, NextKeys);
    Gate.FHasBaseline := True;
    Exit;
  end;
  if TChangeGate.SameKeys(NextKeys, Gate.FAccepted) then
  begin
    BreakChangeCandidate(Gate);
    Exit;
  end;
  if (Gate.FCandidateHits > 0) and
     TChangeGate.SameKeys(NextKeys, Gate.FCandidate) then
  begin
    // Two complete matching observations. Never mutate FAccepted
    // until construction and comparisons have all succeeded.
    SwapChangeList(Gate.FAccepted, NextKeys);
    BreakChangeCandidate(Gate);
    Exit(True);
  end;
  SwapChangeList(Gate.FCandidate, NextKeys);
  Gate.FCandidateHits := 1;
end;

function TChangeGate.Observe(Current: TStrings): Boolean;
var NextKeys: TStringList;
begin
  Result := False;
  NextKeys := nil;
  try
    try
      if Current = nil then
      begin
        BreakChangeCandidate(Self);
        Exit;
      end;
      // Copy first: source getters/Assign may raise (including allocation
      // failure). Only fully built snapshots may become accepted/candidate.
      NextKeys := TStringList.Create;
      NextKeys.Assign(Current);
      Result := ApplyCompleteChangeSnapshot(Self, NextKeys);
    except
      // Failed observations break a pending sequence, not the baseline.
      BreakChangeCandidate(Self);
      raise;
    end;
  finally
    NextKeys.Free;
  end;
end;

{$IFDEF NHW_NATIVE10O_TESTS}
  {$I Cozy.NHW.Native10O.NetworkRules.inc}
{$ENDIF}

end.
