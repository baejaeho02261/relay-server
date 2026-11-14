unit Cozy.NHW.FastEventRing;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

{$IFDEF NHW_NATIVE10Q_TESTS}{$Q+}{$R+}{$ENDIF}

interface

uses
  Winapi.Windows,
  System.SyncObjs,
  System.Generics.Collections,
  Cozy.NHW.ETWTypes;

const
  NHW_FAST_RING_CAPACITY = 1024;

type
  TFastKernelSample = record
    Event: TKernelEvent;
    ArrivalQpc: Int64;  // callback arrival QPC, not generation timestamp
    Serial: Cardinal;   // per-consumer monotonic sequence, wraps naturally
  end;

  TFastKernelSampleList = TList<TFastKernelSample>;

  // Wait-free SPSC ring: exactly one ETW ProcessTrace callback thread writes,
  // exactly one main monitoring thread reads. No strings, heap allocation,
  // API calls, disk writes or blocking locks in Push / Pop.
  // It is NOT safe to use as a general multi-producer queue.
  TFastEventRing = class
  private
    FSlots: array[0..NHW_FAST_RING_CAPACITY - 1] of TFastKernelSample;
    FReadPos: LongInt;
    FWritePos: LongInt;
    FDropped: Int64;  // 0..High(Cardinal), atomically read; never wraps
    FLossPending: Integer;
    FSerial: Cardinal;
  public
    constructor Create;
    destructor Destroy; override;
    function Push(const E: TKernelEvent; Qpc: Int64): Boolean;
    function Pop(out Sample: TFastKernelSample): Boolean;
    function Pending: Integer;
    function DroppedTotal: Cardinal;
    function ConsumeLoss: Boolean; // only the designated consumer calls this
  end;

{$IFDEF NHW_NATIVE10Q_TESTS}
function TestFastEventRing10Q(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

{$IFDEF NHW_NATIVE10Q_TESTS}
uses System.SysUtils;
{$ENDIF}

constructor TFastEventRing.Create;
begin
  inherited Create;
  FReadPos := 0;
  FWritePos := 0;
  FDropped := 0;
  FLossPending := 0;
  FSerial := 0;
end;

destructor TFastEventRing.Destroy;
begin
  { The owning ETW monitor joins its sole producer before freeing this ring. }
  FillChar(FSlots, SizeOf(FSlots), 0);
  FReadPos := 0; FWritePos := 0; FDropped := 0;
  FLossPending := 0; FSerial := 0;
  inherited Destroy;
end;

function TFastEventRing.Push(const E: TKernelEvent; Qpc: Int64): Boolean;
var
  CurrentPos, NextPos: LongInt;
  Loss: Int64;
begin
  CurrentPos := FWritePos; // single producer owns FWritePos
  NextPos := (CurrentPos + 1) and (NHW_FAST_RING_CAPACITY - 1);
  if NextPos = TInterlocked.CompareExchange(FReadPos, 0, 0) then
  begin
    Loss := TInterlocked.CompareExchange(FDropped, Int64(0), Int64(0));
    if Loss < Int64(High(Cardinal)) then
      TInterlocked.Exchange(FDropped, Loss + 1);
    TInterlocked.Exchange(FLossPending, 1);
    Exit(False);
  end;
  // Explicit protocol wrap remains defined under {$Q+} and {$R+}.
  if FSerial = High(Cardinal) then FSerial := 0
  else Inc(FSerial);
  FSlots[CurrentPos].Event := E;
  FSlots[CurrentPos].ArrivalQpc := Qpc;
  FSlots[CurrentPos].Serial := FSerial;
  // Publish completed POD record with a release/full-fence exchange.
  TInterlocked.Exchange(FWritePos, NextPos);
  Result := True;
end;

function TFastEventRing.Pop(out Sample: TFastKernelSample): Boolean;
var
  CurrentPos: LongInt;
begin
  Sample := Default(TFastKernelSample);
  CurrentPos := FReadPos; // single consumer owns FReadPos
  Result := CurrentPos <> TInterlocked.CompareExchange(FWritePos, 0, 0);
  if not Result then Exit;
  Sample := FSlots[CurrentPos];
  { Clear the consumed PID/thread evidence before releasing this slot to the
    single producer. Clearing after FReadPos publication would be a race. }
  FillChar(FSlots[CurrentPos], SizeOf(TFastKernelSample), 0);
  TInterlocked.Exchange(FReadPos,
    (CurrentPos + 1) and (NHW_FAST_RING_CAPACITY - 1));
end;

function TFastEventRing.Pending: Integer;
var
  ReadPos, WritePos: LongInt;
begin
  ReadPos := TInterlocked.CompareExchange(FReadPos, 0, 0);
  WritePos := TInterlocked.CompareExchange(FWritePos, 0, 0);
  Result := (WritePos - ReadPos) and (NHW_FAST_RING_CAPACITY - 1);
end;

function TFastEventRing.DroppedTotal: Cardinal;
begin
  Result := Cardinal(TInterlocked.CompareExchange(FDropped, Int64(0), Int64(0)));
end;

function TFastEventRing.ConsumeLoss: Boolean;
begin
  Result := TInterlocked.Exchange(FLossPending, 0) <> 0;
end;

{$IFDEF NHW_NATIVE10Q_TESTS}
{$I Cozy.NHW.Native10Q.FastEventRing.inc}
{$ENDIF}

end.
