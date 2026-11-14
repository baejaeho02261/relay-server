unit Cozy.NHW.ETWTypes;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  System.Generics.Collections;

type
  TKernelEventKind = (keThreadStart, keThreadEnd,
    keProcessStart, keProcessEnd, keFileIO, keRegistryActivity,
    keImageLoad, keImageUnload);

  TKernelEvent = record
    Kind: TKernelEventKind;
    PID: Cardinal;
    ThreadID: Cardinal;
    ParentPID: Cardinal;
    Tick: UInt64;
  end;

  TKernelEventList = TList<TKernelEvent>;

implementation

end.
