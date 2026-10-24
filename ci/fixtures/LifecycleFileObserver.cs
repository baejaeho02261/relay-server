using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace GameCi {

// A value snapshot: a later Status() call cannot change previously recorded evidence.
public sealed class LifecycleFileSnapshot {
    public string Mode { get; private set; }
    public string Identity { get; private set; }
    public string Sha512 { get; private set; }
    public bool HashMatched { get; private set; }
    public bool FilePresentBefore { get; private set; }
    public bool HeldSameIdentity { get; private set; }
    public bool InitialPathMatched { get; private set; }
    public bool HeldPathMatches { get; private set; }
    public int HeldPathError { get; private set; }
    public bool DeletePending { get; private set; }
    public int HandleError { get; private set; }
    public bool PathAbsent { get; private set; }
    public bool PathIdentityMatched { get; private set; }
    public int PathError { get; private set; }
    public bool Disposed { get; private set; }
    public bool AbsentAfterRelease { get; private set; }
    internal LifecycleFileSnapshot(string mode, string identity, string sha512,
        bool heldSameIdentity, bool heldPathMatches, int heldPathError, bool deletePending, int handleError,
        bool pathAbsent, bool pathIdentityMatched, int pathError, bool disposed) {
        Mode = mode; Identity = identity; Sha512 = sha512;
        HashMatched = true; FilePresentBefore = true;
        InitialPathMatched = true;
        HeldSameIdentity = heldSameIdentity; HeldPathMatches = heldPathMatches;
        HeldPathError = heldPathError;
        DeletePending = deletePending; HandleError = handleError;
        PathAbsent = pathAbsent; PathIdentityMatched = pathIdentityMatched;
        PathError = pathError; Disposed = disposed;
        AbsentAfterRelease = disposed && pathAbsent;
    }
}

// The harness MUST first verify that its held, job-owned B process has exited.
// This observer reads only that exact B image. It never requests DELETE access,
// changes a disposition, deletes a path, closes another process's handles, or
// treats a queued deletion / ACCESS_DENIED as proof of absence.
public sealed class LifecycleFileObserver : IDisposable {
    const uint GENERIC_READ = 0x80000000;
    const uint FILE_READ_ATTRIBUTES = 0x80;
    const uint FILE_SHARE_READ = 1;
    const uint FILE_SHARE_WRITE = 2;
    const uint FILE_SHARE_DELETE = 4;
    const uint OPEN_EXISTING = 3;
    const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    const uint FILE_ATTRIBUTE_DIRECTORY = 0x10;
    const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x400;
    const uint INVALID_FILE_ATTRIBUTES = 0xffffffff;
    const int ERROR_FILE_NOT_FOUND = 2;
    const int ERROR_INVALID_DATA = 13;
    const int ERROR_INVALID_HANDLE = 6;
    const ulong MAX_IMAGE_BYTES = 1024UL * 1024UL * 1024UL;

    [StructLayout(LayoutKind.Sequential)] struct NativeFileTime {
        public uint Low, High;
    }
    [StructLayout(LayoutKind.Sequential)] struct ByHandleFileInformation {
        public uint Attributes;
        public NativeFileTime CreationTime, LastAccessTime, LastWriteTime;
        public uint VolumeSerialNumber, FileSizeHigh, FileSizeLow;
        public uint NumberOfLinks, FileIndexHigh, FileIndexLow;
    }
    // FILE_STANDARD_INFO uses one-byte BOOLEANs, not Win32 four-byte BOOLs.
    [StructLayout(LayoutKind.Sequential, Pack = 8)] struct FileStandardInformation {
        public long AllocationSize, EndOfFile;
        public uint NumberOfLinks;
        public byte DeletePending, Directory;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    static extern SafeFileHandle CreateFileW(string path, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool GetFileInformationByHandle(SafeFileHandle file, out ByHandleFileInformation info);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int infoClass,
        out FileStandardInformation info, uint size);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, StringBuilder path,
        uint capacity, uint flags);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    static extern uint GetLongPathNameW(string path, StringBuilder expanded, uint capacity);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    static extern uint GetFileAttributesW(string path);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool SetFilePointerEx(SafeFileHandle file, long distance, out long position, uint method);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool ReadFile(SafeFileHandle file, byte[] buffer, uint bytesToRead,
        out uint bytesRead, IntPtr overlapped);

    readonly object gate = new object();
    readonly List<SafeFileHandle> ancestors = new List<SafeFileHandle>();
    readonly Dictionary<string, string> ancestorIdentities =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    readonly string imagePath;
    readonly string mode;
    readonly string identity;
    readonly string sha512;
    SafeFileHandle held;
    bool disposed;
    bool absentAfterRelease;

    public LifecycleFileObserver(string path, string expectedSha512, string mode, string ownedRoot) {
        if (Environment.OSVersion.Platform != PlatformID.Win32NT)
            throw new PlatformNotSupportedException("LIFECYCLE_OBSERVER_WINDOWS_REQUIRED");
        if (mode != "REFUSED" && mode != "SCHEDULED")
            throw new ArgumentException("LIFECYCLE_OBSERVER_MODE_INVALID", "mode");
        ValidateHash(expectedSha512);
        this.mode = mode;
        imagePath = NormalizeLocalPath(path);
        string root = NormalizeLocalPath(ownedRoot);
        if (root.Length <= 3 || !imagePath.StartsWith(root + "\\", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("LIFECYCLE_OBSERVER_OUTSIDE_OWNED_ROOT");
        if (Marshal.SizeOf(typeof(ByHandleFileInformation)) != 52 ||
            Marshal.SizeOf(typeof(FileStandardInformation)) != 24)
            throw new InvalidOperationException("LIFECYCLE_OBSERVER_ABI_MISMATCH");
        try {
            // Pin each existing directory from the volume root down. No WRITE
            // or DELETE sharing allows an ancestor to become a reparse point or
            // be renamed while the image name is being checked and observed.
            PinAncestors(System.IO.Path.GetDirectoryName(imagePath));
            uint share = FILE_SHARE_READ;
            if (mode == "SCHEDULED") share |= FILE_SHARE_DELETE;
            held = CreateFileW(Extended(imagePath), GENERIC_READ, share, IntPtr.Zero,
                OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
            if (held.IsInvalid) throw NativeFailure("LIFECYCLE_OBSERVER_OPEN_FAILED");
            ByHandleFileInformation before;
            if (!GetFileInformationByHandle(held, out before))
                throw NativeFailure("LIFECYCLE_OBSERVER_FILE_INFO_FAILED");
            ValidateImage(before);
            if (!FinalPathEquals(held, imagePath))
                throw new InvalidOperationException("LIFECYCLE_OBSERVER_FINAL_PATH_MISMATCH");
            FileStandardInformation standard;
            if (!GetFileInformationByHandleEx(held, 1, out standard, 24))
                throw NativeFailure("LIFECYCLE_OBSERVER_STANDARD_INFO_FAILED");
            if (standard.DeletePending != 0 || standard.Directory != 0 || standard.NumberOfLinks != 1)
                throw new InvalidOperationException("LIFECYCLE_OBSERVER_INITIAL_STATE_INVALID");
            identity = FileIdentity(before);
            sha512 = HashHeld(held, FileSize(before));
            if (!String.Equals(sha512, expectedSha512, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("LIFECYCLE_OBSERVER_HASH_MISMATCH");
            ByHandleFileInformation after;
            if (!GetFileInformationByHandle(held, out after))
                throw NativeFailure("LIFECYCLE_OBSERVER_RECHECK_FAILED");
            ValidateImage(after);
            if (FileIdentity(after) != identity || FileSize(after) != FileSize(before) ||
                after.LastWriteTime.High != before.LastWriteTime.High ||
                after.LastWriteTime.Low != before.LastWriteTime.Low || !FinalPathEquals(held, imagePath))
                throw new InvalidOperationException("LIFECYCLE_OBSERVER_IMAGE_CHANGED");
        } catch {
            CloseHandles();
            disposed = true;
            throw;
        }
    }

    public string Mode { get { return mode; } }
    public string Identity { get { return identity; } }
    public string Sha512 { get { return sha512; } }
    public bool FilePresentBefore { get { return true; } }
    public bool InitialPathMatched { get { return true; } }
    public bool Disposed { get { lock (gate) { return disposed; } } }
    public bool AbsentAfterRelease { get { lock (gate) { return absentAfterRelease; } } }

    // Expansion is read-only and grants no ownership or authorization. The
    // caller creates/owns its private directory before invoking this helper.
    public static string CanonicalDirectory(string existingPath) {
        if (Environment.OSVersion.Platform != PlatformID.Win32NT)
            throw new PlatformNotSupportedException("LIFECYCLE_OBSERVER_WINDOWS_REQUIRED");
        string directory = NormalizeLocalPath(existingPath);
        List<SafeFileHandle> pins = new List<SafeFileHandle>();
        Dictionary<string, string> identities = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try {
            PinDirectoryChain(directory, pins, identities);
            return directory;
        } finally {
            for (int i = pins.Count - 1; i >= 0; i--) pins[i].Dispose();
        }
    }

    public LifecycleFileSnapshot Status() {
        lock (gate) {
            bool same = false, finalPathMatches = false, pending = false;
            int handleError = 0, heldPathError = 0;
            if (!disposed) {
                ByHandleFileInformation info;
                if (held == null || held.IsInvalid || held.IsClosed) handleError = ERROR_INVALID_HANDLE;
                else if (!GetFileInformationByHandle(held, out info)) handleError = Marshal.GetLastWin32Error();
                else {
                    same = FileIdentity(info) == identity && info.NumberOfLinks <= 1 &&
                        (info.Attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0;
                    if (!same) handleError = ERROR_INVALID_DATA;
                    try { finalPathMatches = FinalPathEquals(held, imagePath); }
                    catch (Win32Exception e) { heldPathError = e.NativeErrorCode; }
                    catch (InvalidOperationException) { heldPathError = ERROR_INVALID_DATA; }
                    FileStandardInformation standard;
                    if (!GetFileInformationByHandleEx(held, 1, out standard, 24))
                        handleError = Marshal.GetLastWin32Error();
                    else {
                        pending = standard.DeletePending != 0;
                        if (standard.Directory != 0 || standard.NumberOfLinks > 1 ||
                            (standard.NumberOfLinks == 0 && !pending)) {
                            same = false; handleError = ERROR_INVALID_DATA;
                        }
                    }
                }
            }
            bool absent, pathIdentity;
            int pathError;
            if (disposed) ObserveReleasedPath(out absent, out pathIdentity, out pathError);
            else ObservePath(true, out absent, out pathIdentity, out pathError);
            if (disposed) absentAfterRelease = absent;
            return new LifecycleFileSnapshot(mode, identity, sha512, same, finalPathMatches,
                heldPathError, pending, handleError, absent, pathIdentity, pathError, disposed);
        }
    }

    public void Dispose() {
        lock (gate) {
            if (disposed) return;
            // Release the image first. This may let the product's previously
            // accepted deletion complete; the observer never requests it.
            if (held != null) { held.Dispose(); held = null; }
            bool absent, pathIdentity;
            int pathError;
            ObservePath(false, out absent, out pathIdentity, out pathError);
            absentAfterRelease = absent;
            CloseHandles();
            disposed = true;
        }
        GC.SuppressFinalize(this);
    }

    void ObservePath(bool verifyIdentity, out bool absent, out bool pathIdentity, out int error) {
        absent = false; pathIdentity = false; error = 0;
        uint attributes = GetFileAttributesW(Extended(imagePath));
        if (attributes == INVALID_FILE_ATTRIBUTES) {
            error = Marshal.GetLastWin32Error();
            absent = error == ERROR_FILE_NOT_FOUND;
            return;
        }
        if ((attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
            error = ERROR_INVALID_DATA; return;
        }
        // After release only sample the name's absence. Never reopen a deleted
        // image or report identity proof after the original held handle closed.
        if (!verifyIdentity) return;
        using (SafeFileHandle current = CreateFileW(Extended(imagePath), FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, IntPtr.Zero,
            OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero)) {
            if (current.IsInvalid) { error = Marshal.GetLastWin32Error(); return; }
            ByHandleFileInformation info;
            if (!GetFileInformationByHandle(current, out info)) { error = Marshal.GetLastWin32Error(); return; }
            pathIdentity = FileIdentity(info) == identity && info.NumberOfLinks == 1 &&
                (info.Attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0;
            if (!pathIdentity) error = ERROR_INVALID_DATA;
        }
    }

    void ObserveReleasedPath(out bool absent, out bool pathIdentity, out int error) {
        absent = false; pathIdentity = false; error = 0;
        try {
            // Disposal closed all original handles. A subsequent bounded poll
            // pins and rechecks directories only, so a replaced ancestor cannot
            // redirect a name query outside the original owned tree. The image
            // itself is never reopened after the observation handle is released.
            PinAncestors(System.IO.Path.GetDirectoryName(imagePath));
            ObservePath(false, out absent, out pathIdentity, out error);
        } catch (Win32Exception e) {
            error = e.NativeErrorCode;
        } catch (InvalidOperationException) {
            error = ERROR_INVALID_DATA;
        } finally {
            CloseHandles();
        }
    }

    void PinAncestors(string directory) {
        PinDirectoryChain(directory, ancestors, ancestorIdentities);
    }

    static void PinDirectoryChain(string directory, List<SafeFileHandle> pins,
        Dictionary<string, string> identities) {
        List<string> paths = new List<string>();
        string current = directory;
        while (!String.IsNullOrEmpty(current)) {
            paths.Add(current);
            string parent = System.IO.Path.GetDirectoryName(current);
            if (String.Equals(parent, current, StringComparison.OrdinalIgnoreCase)) break;
            current = parent;
        }
        paths.Reverse();
        foreach (string path in paths) {
            SafeFileHandle handle = CreateFileW(Extended(path), FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ, IntPtr.Zero, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
            if (handle.IsInvalid) { int error = Marshal.GetLastWin32Error(); handle.Dispose();
                throw new Win32Exception(error, "LIFECYCLE_OBSERVER_ANCESTOR_OPEN_FAILED"); }
            pins.Add(handle);
            ByHandleFileInformation info;
            if (!GetFileInformationByHandle(handle, out info))
                throw NativeFailure("LIFECYCLE_OBSERVER_ANCESTOR_INFO_FAILED");
            if ((info.Attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
                (info.Attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 || !FinalPathEquals(handle, path))
                throw new InvalidOperationException("LIFECYCLE_OBSERVER_ANCESTOR_UNSAFE");
            string originalIdentity;
            if (identities.TryGetValue(path, out originalIdentity)) {
                if (originalIdentity != FileIdentity(info))
                    throw new InvalidOperationException("LIFECYCLE_OBSERVER_ANCESTOR_REPLACED");
            } else identities.Add(path, FileIdentity(info));
        }
    }

    void CloseHandles() {
        if (held != null) { held.Dispose(); held = null; }
        for (int i = ancestors.Count - 1; i >= 0; i--) ancestors[i].Dispose();
        ancestors.Clear();
    }

    static void ValidateHash(string value) {
        if (value == null || value.Length != 128) throw new ArgumentException("LIFECYCLE_OBSERVER_SHA512_INVALID");
        foreach (char c in value)
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                throw new ArgumentException("LIFECYCLE_OBSERVER_SHA512_INVALID");
    }

    static string NormalizeLocalPath(string value) {
        // Owned test runs use local drive paths. Device paths, UNC shares, ADS,
        // aliases with dot segments / trailing spaces and DOS devices are not
        // accepted as an alternate way of reaching an image outside the root.
        if (String.IsNullOrEmpty(value) || value.Length < 3 || value.IndexOf('\0') >= 0 ||
            !Char.IsLetter(value[0]) || value[1] != ':' || (value[2] != '\\' && value[2] != '/'))
            throw new ArgumentException("LIFECYCLE_OBSERVER_LOCAL_ABSOLUTE_PATH_REQUIRED");
        string normalized = value.Replace('/', '\\');
        if (normalized.IndexOf(':', 2) >= 0) throw new ArgumentException("LIFECYCLE_OBSERVER_STREAM_PATH_REJECTED");
        string[] parts = normalized.Substring(3).Split('\\');
        for (int i = 0; i < parts.Length; i++) {
            string part = parts[i];
            if (part.Length == 0) {
                if (i == parts.Length - 1) continue;
                throw new ArgumentException("LIFECYCLE_OBSERVER_EMPTY_PATH_COMPONENT");
            }
            if (part == "." || part == ".." || part.EndsWith(".", StringComparison.Ordinal) ||
                part.EndsWith(" ", StringComparison.Ordinal) || part.IndexOfAny(System.IO.Path.GetInvalidFileNameChars()) >= 0)
                throw new ArgumentException("LIFECYCLE_OBSERVER_PATH_ALIAS_REJECTED");
            string name = part.Split('.')[0].ToUpperInvariant();
            if (name == "CON" || name == "PRN" || name == "AUX" || name == "NUL" ||
                name == "CONIN$" || name == "CONOUT$" ||
                (name.Length == 4 && (name.StartsWith("COM", StringComparison.Ordinal) ||
                name.StartsWith("LPT", StringComparison.Ordinal)) && name[3] >= '1' && name[3] <= '9'))
                throw new ArgumentException("LIFECYCLE_OBSERVER_DEVICE_PATH_REJECTED");
        }
        string full = System.IO.Path.GetFullPath(normalized);
        if (full.Length > 3) full = full.TrimEnd('\\');
        // TEMP commonly contains ADMINI~1 even when the final handle path is
        // Administrator. Expand the existing DOS aliases before boundary and
        // pinned-handle checks, without resolving or accepting reparse points.
        StringBuilder expanded = new StringBuilder(512);
        uint count = GetLongPathNameW(Extended(full), expanded, (uint)expanded.Capacity);
        if (count == 0) throw NativeFailure("LIFECYCLE_OBSERVER_LONG_PATH_FAILED");
        if (count >= expanded.Capacity) {
            if (count > 32767) throw new InvalidOperationException("LIFECYCLE_OBSERVER_PATH_TOO_LONG");
            expanded = new StringBuilder(checked((int)count + 1));
            count = GetLongPathNameW(Extended(full), expanded, (uint)expanded.Capacity);
            if (count == 0) throw NativeFailure("LIFECYCLE_OBSERVER_LONG_PATH_FAILED");
            if (count >= expanded.Capacity) throw new InvalidOperationException("LIFECYCLE_OBSERVER_PATH_CHANGED");
        }
        string result = expanded.ToString();
        if (!result.StartsWith("\\\\?\\", StringComparison.Ordinal))
            throw new InvalidOperationException("LIFECYCLE_OBSERVER_LOCAL_PATH_REQUIRED");
        result = result.Substring(4);
        if (result.Length > 3) result = result.TrimEnd('\\');
        return result;
    }

    static string Extended(string path) { return "\\\\?\\" + path; }

    static bool FinalPathEquals(SafeFileHandle file, string expected) {
        StringBuilder buffer = new StringBuilder(512);
        uint count = GetFinalPathNameByHandleW(file, buffer, (uint)buffer.Capacity, 0);
        if (count == 0) throw NativeFailure("LIFECYCLE_OBSERVER_FINAL_PATH_FAILED");
        if (count >= buffer.Capacity) {
            if (count > 32767) throw new InvalidOperationException("LIFECYCLE_OBSERVER_FINAL_PATH_TOO_LONG");
            buffer = new StringBuilder(checked((int)count + 1));
            count = GetFinalPathNameByHandleW(file, buffer, (uint)buffer.Capacity, 0);
            if (count == 0) throw NativeFailure("LIFECYCLE_OBSERVER_FINAL_PATH_FAILED");
            if (count >= buffer.Capacity) throw new InvalidOperationException("LIFECYCLE_OBSERVER_FINAL_PATH_CHANGED");
        }
        string actual = buffer.ToString();
        if (!actual.StartsWith("\\\\?\\", StringComparison.Ordinal)) return false;
        actual = actual.Substring(4);
        if (actual.Length > 3) actual = actual.TrimEnd('\\');
        return String.Equals(actual, expected, StringComparison.OrdinalIgnoreCase);
    }

    static void ValidateImage(ByHandleFileInformation info) {
        ulong size = FileSize(info);
        if ((info.Attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) != 0 ||
            info.NumberOfLinks != 1 || size == 0 || size > MAX_IMAGE_BYTES)
            throw new InvalidOperationException("LIFECYCLE_OBSERVER_IMAGE_UNSAFE");
    }
    static ulong FileSize(ByHandleFileInformation info) {
        return ((ulong)info.FileSizeHigh << 32) | info.FileSizeLow;
    }
    static string FileIdentity(ByHandleFileInformation info) {
        return info.VolumeSerialNumber.ToString("x8", CultureInfo.InvariantCulture) + ":" +
            info.FileIndexHigh.ToString("x8", CultureInfo.InvariantCulture) +
            info.FileIndexLow.ToString("x8", CultureInfo.InvariantCulture);
    }
    static string HashHeld(SafeFileHandle file, ulong expectedSize) {
        long position;
        if (!SetFilePointerEx(file, 0, out position, 0) || position != 0)
            throw NativeFailure("LIFECYCLE_OBSERVER_SEEK_FAILED");
        byte[] buffer = new byte[128 * 1024];
        try {
            using (SHA512 algorithm = SHA512.Create()) {
                ulong total = 0;
                while (true) {
                    uint read;
                    if (!ReadFile(file, buffer, (uint)buffer.Length, out read, IntPtr.Zero))
                        throw NativeFailure("LIFECYCLE_OBSERVER_READ_FAILED");
                    if (read == 0) break;
                    total += read;
                    if (total > expectedSize) throw new InvalidOperationException("LIFECYCLE_OBSERVER_IMAGE_SIZE_CHANGED");
                    algorithm.TransformBlock(buffer, 0, checked((int)read), buffer, 0);
                }
                if (total != expectedSize) throw new InvalidOperationException("LIFECYCLE_OBSERVER_IMAGE_SIZE_CHANGED");
                algorithm.TransformFinalBlock(new byte[0], 0, 0);
                StringBuilder digest = new StringBuilder(128);
                foreach (byte b in algorithm.Hash) digest.Append(b.ToString("x2", CultureInfo.InvariantCulture));
                return digest.ToString();
            }
        } finally {
            Array.Clear(buffer, 0, buffer.Length);
        }
    }
    static Win32Exception NativeFailure(string message) {
        return new Win32Exception(Marshal.GetLastWin32Error(), message);
    }
}
}
