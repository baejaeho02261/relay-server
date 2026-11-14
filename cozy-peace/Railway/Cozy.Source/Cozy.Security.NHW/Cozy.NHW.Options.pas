unit Cozy.NHW.Options;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Cozy.NHW.Types;

// Fixed automatic startup configuration; no command-line parsing.
procedure ConfigureDefaultMonitoring(out Opt: TOptions);

implementation

uses
  Winapi.Windows, Cozy.NHW.WinPointers;

procedure ConfigureDefaultMonitoring(out Opt: TOptions);
begin
  Opt := Default(TOptions);
  Opt.TargetPID := WinCurrentProcessId;
  Opt.IntervalMS := 500;
  Opt.MissThreshold := 2;
  Opt.BaselineScans := 3;
  Opt.SummaryMS := 5000;
  // Query-only and read-only handles are common for Windows services, AV,
  // diagnostics and accessibility tooling. Keep collecting lower levels
  // internally, but direct Process/Thread Detect requires the high-impact
  // class: VM_WRITE/VM_OPERATION/CREATE_THREAD or SET_CONTEXT equivalents.
  Opt.MinLevel := 3;
  Opt.ThreadMinLevel := 3;
  Opt.ThreadWatch := True;  // Monitor process AND thread handles.
  Opt.Watch := True;        // Continuous monitoring until Ctrl+C.
  Opt.ReportHandleCount := False; // Avoid notification on count-only changes.
end;

end.
