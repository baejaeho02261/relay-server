param(
 [Parameter(Mandatory=$true)][string]$ManifestPath,
 [string]$ResourcePath,
 [string]$ImagePath
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
try {
 if (-not $ResourcePath -and -not $ImagePath) { throw 'OVERLAY_MANIFEST_INPUT_REQUIRED' }
 $expected=[IO.File]::ReadAllBytes([IO.Path]::GetFullPath($ManifestPath))
 if($expected.Length -eq 0 -or $expected.Length -gt 65536){throw 'OVERLAY_MANIFEST_SIZE'}
 $xml=New-Object System.Xml.XmlDocument
 $xml.XmlResolver=$null
 $settings=New-Object System.Xml.XmlReaderSettings
 $settings.DtdProcessing=[System.Xml.DtdProcessing]::Prohibit
 $settings.XmlResolver=$null
 $settings.MaxCharactersInDocument=65536
 $text=([Text.UTF8Encoding]::new($false,$true)).GetString($expected)
 $text=$text.TrimStart([char]0xfeff)
 $reader=[System.Xml.XmlReader]::Create([IO.StringReader]::new($text),$settings)
 try{$xml.Load($reader)}finally{$reader.Dispose()}
 $dpi=$xml.SelectSingleNode("//*[local-name()='dpiAwareness' and namespace-uri()='http://schemas.microsoft.com/SMI/2016/WindowsSettings']")
 if($null -eq $dpi -or $dpi.InnerText.Trim() -ne 'PerMonitorV2, PerMonitor'){throw 'OVERLAY_MANIFEST_DPI_REQUIRED'}
 Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
public static class GameOverlayManifestAudit {
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
 static extern IntPtr LoadLibraryExW(string path, IntPtr file, uint flags);
 [DllImport("kernel32.dll", SetLastError=true)]
 static extern IntPtr FindResourceW(IntPtr module, IntPtr name, IntPtr type);
 [DllImport("kernel32.dll", SetLastError=true)]
 static extern uint SizeofResource(IntPtr module, IntPtr resource);
 [DllImport("kernel32.dll", SetLastError=true)]
 static extern IntPtr LoadResource(IntPtr module, IntPtr resource);
 [DllImport("kernel32.dll")]
 static extern IntPtr LockResource(IntPtr resource);
 [DllImport("kernel32.dll")]
 static extern bool FreeLibrary(IntPtr module);
 static ushort Word(byte[] bytes, ref int at, int end) {
  if(at < 0 || at > end-2) throw new InvalidDataException("RESOURCE_HEADER_BOUNDS");
  ushort value=BitConverter.ToUInt16(bytes,at);at+=2;return value;
 }
 static int Identifier(byte[] bytes, ref int at, int end) {
  ushort first=Word(bytes,ref at,end);
  if(first==65535) return Word(bytes,ref at,end);
  while(first!=0) first=Word(bytes,ref at,end);
  return -1;
 }
 public static byte[] FromRes(string path) {
  byte[] bytes=File.ReadAllBytes(path),found=null;
  int at=0;
  while(at<bytes.Length) {
   if(at>bytes.Length-8) throw new InvalidDataException("RESOURCE_TRUNCATED");
   uint size=BitConverter.ToUInt32(bytes,at),header=BitConverter.ToUInt32(bytes,at+4);
   long end=(long)at+header+size;
   if(header<32 || (header&3)!=0 || end>bytes.Length) throw new InvalidDataException("RESOURCE_BOUNDS");
   int cursor=at+8,headerEnd=at+(int)header;
   int type=Identifier(bytes,ref cursor,headerEnd),name=Identifier(bytes,ref cursor,headerEnd);
   if(type==24 && name==1) {
    if(found!=null || size>65536) throw new InvalidDataException("RESOURCE_MANIFEST_COUNT");
    found=new byte[(int)size];Buffer.BlockCopy(bytes,headerEnd,found,0,(int)size);
   }
   at=checked((int)((end+3)&~3L));
  }
  if(found==null) throw new InvalidDataException("RESOURCE_MANIFEST_MISSING");
  return found;
 }
 public static byte[] FromExe(string path) {
  // Resource-only image mapping: never load imports or execute the entry point.
  IntPtr module=LoadLibraryExW(path,IntPtr.Zero,0x22);
  if(module==IntPtr.Zero) throw new InvalidDataException("IMAGE_RESOURCE_MAP_FAILED");
  try {
   IntPtr resource=FindResourceW(module,new IntPtr(1),new IntPtr(24));
   if(resource==IntPtr.Zero) throw new InvalidDataException("IMAGE_MANIFEST_MISSING");
   uint size=SizeofResource(module,resource);
   if(size==0 || size>65536) throw new InvalidDataException("IMAGE_MANIFEST_SIZE");
   IntPtr data=LockResource(LoadResource(module,resource));
   if(data==IntPtr.Zero) throw new InvalidDataException("IMAGE_MANIFEST_READ_FAILED");
   byte[] bytes=new byte[(int)size];Marshal.Copy(data,bytes,0,(int)size);return bytes;
  } finally { FreeLibrary(module); }
 }
 public static bool Equal(byte[] first,byte[] second) {
  if(first.Length!=second.Length) return false;
  for(int i=0;i<first.Length;i++) if(first[i]!=second[i]) return false;
  return true;
 }
}
'@
 if($ResourcePath){
  $actual=[GameOverlayManifestAudit]::FromRes([IO.Path]::GetFullPath($ResourcePath))
  if(-not [GameOverlayManifestAudit]::Equal($expected,$actual)){throw 'OVERLAY_RES_MANIFEST_STALE'}
  Write-Output 'OVERLAY_RES_MANIFEST_OK PerMonitorV2'
 }
 if($ImagePath){
  $actual=[GameOverlayManifestAudit]::FromExe([IO.Path]::GetFullPath($ImagePath))
  if(-not [GameOverlayManifestAudit]::Equal($expected,$actual)){throw 'OVERLAY_EXE_MANIFEST_STALE'}
  Write-Output 'OVERLAY_EXE_MANIFEST_OK PerMonitorV2'
 }
 exit 0
} catch { Write-Error $_; exit 1 }
