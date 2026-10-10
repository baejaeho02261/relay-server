// CI-only process ownership and ordinary console/window test control.
// Not linked into A/B/O. No foreign-process memory access or injected code.
using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using System.Diagnostics;
using System.Threading;
namespace GameCi {
public sealed class WindowsJob : IDisposable {
    IntPtr job, process; public uint RootId {get; private set;}
    [StructLayout(LayoutKind.Sequential)] struct SA { public int size; public IntPtr descriptor; [MarshalAs(UnmanagedType.Bool)] public bool inherit; }
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct SI { public int cb; public IntPtr reserved,desktop,title; public uint x,y,xsize,ysize,xchars,ychars,fill,flags; public ushort show,reserved2; public IntPtr reservedPtr,input,output,error; }
    [StructLayout(LayoutKind.Sequential)] struct SIX {public SI startup; public IntPtr attributes;}
    [StructLayout(LayoutKind.Sequential)] struct PI {public IntPtr process,thread; public uint pid,tid;}
    [StructLayout(LayoutKind.Sequential)] struct BASIC {public long processTime,jobTime; public uint flags; public UIntPtr minWorking,maxWorking; public uint activeLimit; public UIntPtr affinity; public uint priority,scheduling;}
    [StructLayout(LayoutKind.Sequential)] struct IO {public ulong rOps,wOps,oOps,rBytes,wBytes,oBytes;}
    [StructLayout(LayoutKind.Sequential)] struct LIMIT {public BASIC basic;public IO io;public UIntPtr processMemory,jobMemory,peakProcessMemory,peakJobMemory;}
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateJobObjectW(IntPtr a,string n);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetInformationJobObject(IntPtr j,int c,ref LIMIT l,int n);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr j,int c,IntPtr b,int n,IntPtr ret);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr j,IntPtr p);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool IsProcessInJob(IntPtr p,IntPtr j,out bool member);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateJobObject(IntPtr j,uint code);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateProcess(IntPtr p,uint code);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint ResumeThread(IntPtr t);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(IntPtr h,uint ms);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr p,out uint code);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool InitializeProcThreadAttributeList(IntPtr p,int count,int flags,ref IntPtr size);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool UpdateProcThreadAttribute(IntPtr p,uint flags,IntPtr attr,IntPtr value,IntPtr size,IntPtr old,IntPtr ret);
    [DllImport("kernel32.dll")] static extern void DeleteProcThreadAttributeList(IntPtr p);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateFileW(string n,uint a,uint share,ref SA sa,uint create,uint flags,IntPtr template);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcessW(string app,StringBuilder command,IntPtr p,IntPtr t,bool inherit,uint flags,IntPtr env,string cwd,ref SIX si,out PI pi);
    static Exception Error(string stage) {return new Win32Exception(Marshal.GetLastWin32Error(),stage);}
    static string Quote(string text) { var b=new StringBuilder("\"");int slashes=0;foreach(char c in text){if(c=='\\'){slashes++;continue;}if(c=='"'){b.Append('\\',slashes*2+1);b.Append(c);}else{b.Append('\\',slashes);b.Append(c);}slashes=0;}b.Append('\\',slashes*2);return b.Append('"').ToString(); }
    public static WindowsJob Start(string exe,string[] args,string cwd,IDictionary environment,string log) {
        if(IntPtr.Size!=8)throw new InvalidOperationException("CI_X64_REQUIRED");
        var result=new WindowsJob();IntPtr attr=IntPtr.Zero,list=IntPtr.Zero,env=IntPtr.Zero,output=IntPtr.Zero,input=IntPtr.Zero;PI pi=new PI();bool initialized=false;
        try {
            result.job=CreateJobObjectW(IntPtr.Zero,null);if(result.job==IntPtr.Zero)throw Error("CI_JOB_CREATE");
            var limit=new LIMIT();limit.basic.flags=0x2208;limit.basic.activeLimit=64;limit.jobMemory=new UIntPtr(8UL*1024*1024*1024);
            if(!SetInformationJobObject(result.job,9,ref limit,Marshal.SizeOf(typeof(LIMIT))))throw Error("CI_JOB_LIMIT");
            var sa=new SA{size=Marshal.SizeOf(typeof(SA)),inherit=true};
            output=CreateFileW(log,0x40000000,1,ref sa,1,0x80,IntPtr.Zero);if(output==new IntPtr(-1))throw Error("CI_LOG_CREATE");
            input=CreateFileW("NUL",0x80000000,3,ref sa,3,0x80,IntPtr.Zero);if(input==new IntPtr(-1))throw Error("CI_INPUT_CREATE");
            IntPtr size=IntPtr.Zero;InitializeProcThreadAttributeList(IntPtr.Zero,1,0,ref size);if(size==IntPtr.Zero)throw Error("CI_HANDLE_LIST_SIZE");
            attr=Marshal.AllocHGlobal(size);if(!InitializeProcThreadAttributeList(attr,1,0,ref size))throw Error("CI_HANDLE_LIST_INIT");initialized=true;
            list=Marshal.AllocHGlobal(16);Marshal.WriteIntPtr(list,output);Marshal.WriteIntPtr(list,8,input);
            if(!UpdateProcThreadAttribute(attr,0,new IntPtr(0x20002),list,new IntPtr(16),IntPtr.Zero,IntPtr.Zero))throw Error("CI_HANDLE_LIST_SET");
            var vars=new SortedDictionary<string,string>(StringComparer.OrdinalIgnoreCase);foreach(DictionaryEntry pair in environment)vars[(string)pair.Key]=(string)pair.Value;
            var block=new StringBuilder();foreach(var pair in vars){if(pair.Key.IndexOf('=')>=0||pair.Key.IndexOf('\0')>=0||pair.Value.IndexOf('\0')>=0)throw new ArgumentException("CI_ENV_INVALID");block.Append(pair.Key).Append('=').Append(pair.Value).Append('\0');}block.Append('\0');env=Marshal.StringToHGlobalUni(block.ToString());
            var si=new SIX();si.startup.cb=Marshal.SizeOf(typeof(SIX));si.startup.flags=0x100;si.startup.input=input;si.startup.output=output;si.startup.error=output;si.attributes=attr;
            var command=new StringBuilder(Quote(exe));foreach(var arg in args)command.Append(' ').Append(Quote(arg));
            if(!CreateProcessW(exe,command,IntPtr.Zero,IntPtr.Zero,true,0x80404,env,cwd,ref si,out pi))throw Error("CI_PROCESS_CREATE");
            result.process=pi.process;result.RootId=pi.pid;
            if(!AssignProcessToJobObject(result.job,pi.process))throw Error("CI_JOB_ASSIGN");
            if(ResumeThread(pi.thread)==0xffffffff)throw Error("CI_PROCESS_RESUME");return result;
        } catch {if(pi.process!=IntPtr.Zero)TerminateProcess(pi.process,1);result.Dispose();throw;}
        finally {if(pi.thread!=IntPtr.Zero)CloseHandle(pi.thread);if(initialized)DeleteProcThreadAttributeList(attr);if(attr!=IntPtr.Zero)Marshal.FreeHGlobal(attr);if(list!=IntPtr.Zero)Marshal.FreeHGlobal(list);if(env!=IntPtr.Zero)Marshal.FreeHGlobal(env);if(output!=IntPtr.Zero&&output!=new IntPtr(-1))CloseHandle(output);if(input!=IntPtr.Zero&&input!=new IntPtr(-1))CloseHandle(input);}
    }
    public bool HasExited {get {return WaitForSingleObject(process,0)==0;}}
    public uint ExitCode {get {uint code;if(!HasExited||!GetExitCodeProcess(process,out code))throw Error("CI_PROCESS_STATUS");return code;}}
    public uint[] ProcessIds() {IntPtr b=Marshal.AllocHGlobal(8192);try{if(!QueryInformationJobObject(job,3,b,8192,IntPtr.Zero))throw Error("CI_JOB_QUERY");int n=Marshal.ReadInt32(b,4);if(n<0||n>1023)throw new InvalidOperationException("CI_JOB_COUNT");var result=new uint[n];for(int i=0;i<n;i++)result[i]=(uint)Marshal.ReadIntPtr(b,8+i*8).ToInt64();return result;}finally{Marshal.FreeHGlobal(b);}}
    public bool OwnsProcess(IntPtr handle){bool member;return job!=IntPtr.Zero&&IsProcessInJob(handle,job,out member)&&member;}
    public void Dispose(){bool timeout=false;try{if(job!=IntPtr.Zero){TerminateJobObject(job,1);var clock=Stopwatch.StartNew();while(ProcessIds().Length!=0&&clock.ElapsedMilliseconds<5000)Thread.Sleep(20);timeout=ProcessIds().Length!=0;}}finally{if(job!=IntPtr.Zero){CloseHandle(job);job=IntPtr.Zero;}if(process!=IntPtr.Zero){CloseHandle(process);process=IntPtr.Zero;}}if(timeout)throw new InvalidOperationException("CI_JOB_CLEANUP_TIMEOUT");}
}
public static class DesktopControl {
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool FreeConsole();
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool AttachConsole(uint pid);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateFileW(string n,uint access,uint share,IntPtr sa,uint create,uint flags,IntPtr t);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr h);
    [StructLayout(LayoutKind.Explicit,Size=20)] struct INPUT { [FieldOffset(0)]public ushort type;[FieldOffset(4)]public int down;[FieldOffset(8)]public ushort repeat;[FieldOffset(10)]public ushort key;[FieldOffset(12)]public ushort scan;[FieldOffset(14)]public ushort character;[FieldOffset(16)]public uint state; }
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool WriteConsoleInputW(IntPtr h,INPUT[] input,uint count,out uint written);
    [StructLayout(LayoutKind.Sequential)] struct COORD {public short x,y;}
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetConsoleMode(IntPtr h,out uint mode);
    [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool QueryFullProcessImageNameW(IntPtr p,uint flags,StringBuilder b,ref int size);
    delegate bool EnumProc(IntPtr h,IntPtr p);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc callback,IntPtr p);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h,out uint pid);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll",SetLastError=true)] static extern IntPtr SendMessageTimeoutW(IntPtr h,uint msg,IntPtr w,IntPtr l,uint flags,uint timeout,out IntPtr result);
    public static string ImagePath(uint pid){var h=OpenProcess(0x1000,false,pid);if(h==IntPtr.Zero)return "";try{int n=32768;var b=new StringBuilder(n);return QueryFullProcessImageNameW(h,0,b,ref n)?b.ToString():"";}finally{CloseHandle(h);}}
    public static bool SubmitLicense(uint pid,string key){if(!System.Text.RegularExpressions.Regex.IsMatch(key,"^[A-F0-9]{64}$"))throw new ArgumentException("CI_KEY_FORMAT");FreeConsole();if(!AttachConsole(pid))return false;IntPtr input=IntPtr.Zero,output=IntPtr.Zero;try{input=CreateFileW("CONIN$",0xc0000000,3,IntPtr.Zero,3,0,IntPtr.Zero);output=CreateFileW("CONOUT$",0x80000000,3,IntPtr.Zero,3,0,IntPtr.Zero);if(input==new IntPtr(-1)||output==new IntPtr(-1))return false;uint inputMode,outputMode;if(!GetConsoleMode(input,out inputMode)||!GetConsoleMode(output,out outputMode))return false;string text=key+"\r";var events=new INPUT[text.Length];for(int i=0;i<text.Length;i++)events[i]=new INPUT{type=1,down=1,repeat=1,key=(ushort)(text[i]=='\r'?13:text[i]),character=text[i]};uint written;if(!WriteConsoleInputW(input,events,(uint)events.Length,out written)||written!=events.Length)throw new InvalidOperationException("CI_CONSOLE_WRITE");return true;}finally{if(input!=IntPtr.Zero&&input!=new IntPtr(-1))CloseHandle(input);if(output!=IntPtr.Zero&&output!=new IntPtr(-1))CloseHandle(output);FreeConsole();}}
    public static bool Window(uint pid,bool close){bool found=false;EnumWindows((h,p)=>{uint owner;GetWindowThreadProcessId(h,out owner);if(owner!=pid||!IsWindowVisible(h))return true;found=true;if(close){IntPtr ignored;SendMessageTimeoutW(h,0x10,IntPtr.Zero,IntPtr.Zero,2,2000,out ignored);}return !found;},IntPtr.Zero);return found;}
}
}
