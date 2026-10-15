using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

namespace GameCi {
// Out-of-context accessibility events observe only the already job-verified O.
// No injection, process suspension, window command or synthetic input is used.
public sealed class OverlayLeaseObserver : IDisposable {
    delegate void EventProc(IntPtr hook,uint kind,IntPtr window,int objectId,int childId,uint eventThread,uint eventTime);
    delegate bool EnumProc(IntPtr window,IntPtr state);
    [StructLayout(LayoutKind.Sequential)] struct POINT { public int x,y; }
    [StructLayout(LayoutKind.Sequential)] struct MSG { public IntPtr window;public uint message;public UIntPtr wParam;public IntPtr lParam;public uint time;public POINT point;public uint privateValue; }
    [DllImport("user32.dll",SetLastError=true)] static extern IntPtr SetWinEventHook(uint first,uint last,IntPtr module,EventProc callback,uint pid,uint thread,uint flags);
    [DllImport("user32.dll")] static extern bool UnhookWinEvent(IntPtr hook);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr window,out uint pid);
    [DllImport("user32.dll")] static extern IntPtr GetAncestor(IntPtr window,uint flags);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr window);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc callback,IntPtr state);
    [DllImport("user32.dll",SetLastError=true)] static extern int GetMessageW(out MSG message,IntPtr window,uint first,uint last);
    [DllImport("user32.dll")] static extern bool PeekMessageW(out MSG message,IntPtr window,uint first,uint last,uint remove);
    [DllImport("user32.dll",SetLastError=true)] static extern bool PostThreadMessageW(uint thread,uint message,UIntPtr wParam,IntPtr lParam);
    [DllImport("kernel32.dll")] static extern uint GetCurrentThreadId();
    [DllImport("kernel32.dll")] static extern ulong GetTickCount64();
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")] static extern uint GetProcessId(IntPtr process);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool DuplicateHandle(IntPtr sourceProcess,IntPtr source,IntPtr targetProcess,out IntPtr target,uint access,bool inherit,uint options);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr handle,uint milliseconds);
    readonly object gate=new object();readonly uint pid;readonly HashSet<IntPtr> seen=new HashSet<IntPtr>();
    readonly ManualResetEventSlim ready=new ManualResetEventSlim(false);readonly Thread thread;readonly EventProc callback;
    IntPtr process;uint threadId;Exception error;bool disposed;long visibleAt,hiddenAt;ulong visibleTick,hiddenTick;bool hiddenAlive,reappeared;IntPtr observedWindow;
    public OverlayLeaseObserver(uint processId,IntPtr heldProcess) {
        if(processId==0||GetProcessId(heldProcess)!=processId)throw new ArgumentException("LEASE_OBSERVER_PROCESS_MISMATCH");
        pid=processId;
        if(!DuplicateHandle(GetCurrentProcess(),heldProcess,GetCurrentProcess(),out process,0,false,2))throw new Win32Exception();
        callback=Observe;thread=new Thread(Loop);thread.IsBackground=true;thread.Name="Owned overlay lease observation";thread.Start();
        if(!ready.Wait(5000)){Dispose();throw new InvalidOperationException("LEASE_OBSERVER_START_TIMEOUT");}
        if(error!=null){var cause=error;Dispose();throw new InvalidOperationException("LEASE_OBSERVER_START_FAILED",cause);}
    }
    bool OwnWindow(IntPtr window){uint owner;return window!=IntPtr.Zero&&GetWindowThreadProcessId(window,out owner)!=0&&owner==pid&&GetAncestor(window,2)==window;}
    void Visible(IntPtr window){lock(gate){seen.Add(window);if(hiddenAt!=0)reappeared=true;if(visibleAt==0){observedWindow=window;visibleAt=DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();visibleTick=GetTickCount64();}}}
    void Observe(IntPtr hook,uint kind,IntPtr window,int objectId,int childId,uint eventThread,uint eventTime){
        try{
            if(objectId!=0||childId!=0)return;
            bool known;lock(gate){known=window==observedWindow&&visibleAt!=0;}
            // The hook itself filters the exact PID. A queued event for our
            // already-bound HWND remains meaningful after its destruction.
            if(!known&&!OwnWindow(window))return;
            if(kind==0x8002){
                lock(gate){if(hiddenAt!=0){reappeared=true;return;}}
                if(IsWindowVisible(window))Visible(window);return;
            }
            if(kind==0x8003){lock(gate){if(window==observedWindow&&seen.Contains(window)&&hiddenAt==0){
                // Use the OS event generation tick, not delayed callback time.
                // Reconstruct its DWORD wrap within this short owned run.
                ulong now=GetTickCount64();uint age=unchecked((uint)now-eventTime);
                if(age>10000||now<age)throw new InvalidOperationException("LEASE_OBSERVER_EVENT_TOO_OLD");
                hiddenAt=DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();hiddenTick=now-age;hiddenAlive=WaitForSingleObject(process,0)==0x102;
            }}}
        }catch(Exception e){lock(gate){error=e;}}
    }
    void Loop(){IntPtr hook=IntPtr.Zero;try{
        threadId=GetCurrentThreadId();MSG message;PeekMessageW(out message,IntPtr.Zero,0,0,0);
        hook=SetWinEventHook(0x8002,0x8003,IntPtr.Zero,callback,pid,0,0);
        if(hook==IntPtr.Zero)throw new Win32Exception();
        EnumWindows((window,state)=>{if(OwnWindow(window)&&IsWindowVisible(window))Visible(window);return true;},IntPtr.Zero);ready.Set();
        int code;while((code=GetMessageW(out message,IntPtr.Zero,0,0))>0){}if(code<0)throw new Win32Exception();
        // The caller stops only after the observed process has exited. Pump
        // already queued out-of-context events before unhook/final snapshot.
        for(int i=0;i<20;i++){for(int j=0;j<256&&PeekMessageW(out message,IntPtr.Zero,0,0,1);j++){}Thread.Sleep(1);}
    }catch(Exception e){lock(gate){error=e;}ready.Set();}finally{if(hook!=IntPtr.Zero&&!UnhookWinEvent(hook))lock(gate){error=new InvalidOperationException("LEASE_OBSERVER_UNHOOK_FAILED");}}}
    public long VisibleAt {get{lock(gate){return visibleAt;}}}
    public long HiddenAt {get{lock(gate){return hiddenAt;}}}
    public ulong VisibleTick {get{lock(gate){return visibleTick;}}}
    public ulong HiddenTick {get{lock(gate){return hiddenTick;}}}
    public static ulong CurrentTick {get{return GetTickCount64();}}
    public long WindowHandle {get{lock(gate){return observedWindow.ToInt64();}}}
    public bool HiddenWhileAlive {get{lock(gate){return hiddenAlive;}}}
    public bool Reappeared {get{lock(gate){return reappeared;}}}
    public bool Failed {get{lock(gate){return error!=null;}}}
    public void Dispose(){if(disposed)return;disposed=true;
        bool stopped=!thread.IsAlive;
        if(!stopped){PostThreadMessageW(threadId,0x12,UIntPtr.Zero,IntPtr.Zero);stopped=thread.Join(5000);}
        if(!stopped)throw new InvalidOperationException("LEASE_OBSERVER_STOP_TIMEOUT");
        if(process!=IntPtr.Zero){CloseHandle(process);process=IntPtr.Zero;}ready.Dispose();
    }
}
}
