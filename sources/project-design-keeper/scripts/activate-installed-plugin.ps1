#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PackageRoot,

    [Parameter(Mandatory = $true)]
    [string]$InstallRoot,

    [Parameter(Mandatory = $true)]
    [string]$SmokeProject
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not ("KeeperActivationNative" -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

public sealed class KeeperActivationIdentityException : InvalidOperationException
{
    public KeeperActivationIdentityException(string message) : base(message) { }
    public KeeperActivationIdentityException(string message, Exception innerException) : base(message, innerException) { }
}

public sealed class KeeperActivationCandidateException : InvalidOperationException
{
    public KeeperActivationCandidateException(string message) : base(message) { }
    public KeeperActivationCandidateException(string message, Exception innerException) : base(message, innerException) { }
}

public sealed class KeeperActivationPackageShapeException : InvalidOperationException
{
    public KeeperActivationPackageShapeException(string message) : base(message) { }
    public KeeperActivationPackageShapeException(string message, Exception innerException) : base(message, innerException) { }
}

public sealed class KeeperActivationDeadlineException : TimeoutException
{
    public KeeperActivationDeadlineException(string message) : base(message) { }
}

public sealed class KeeperActivationOwnedProcessResult
{
    public int ExitCode { get; internal set; }
    public string Output { get; internal set; }
    public bool TimedOut { get; internal set; }
    public bool OutputLimitExceeded { get; internal set; }
    public int RootPid { get; internal set; }
}

public sealed class KeeperActivationKernelHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    private KeeperActivationKernelHandle() : base(true) { }
    internal KeeperActivationKernelHandle(IntPtr value) : base(true) { SetHandle(value); }
    protected override bool ReleaseHandle() { return CloseHandle(handle); }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
}

public sealed class KeeperActivationFileEvidence
{
    public byte[] Bytes { get; private set; }
    public string Identity { get; private set; }
    public long Length { get; private set; }
    public string Sha256 { get; private set; }

    public KeeperActivationFileEvidence(byte[] bytes, string identity, long length, string sha256)
    {
        Bytes = bytes;
        Identity = identity;
        Length = length;
        Sha256 = sha256;
    }
}

public sealed class KeeperActivationDeleteLease : IDisposable
{
    internal SafeFileHandle Handle { get; private set; }
    internal bool DeleteRequested { get; set; }
    public bool IsDirectory { get; private set; }

    internal KeeperActivationDeleteLease(SafeFileHandle handle, bool isDirectory)
    {
        Handle = handle;
        IsDirectory = isDirectory;
    }

    public void Dispose()
    {
        if (Handle != null)
        {
            Handle.Dispose();
            Handle = null;
        }
    }
}

public static class KeeperActivationNative
{
    [StructLayout(LayoutKind.Sequential)]
    private struct BY_HANDLE_FILE_INFORMATION
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle handle,
        out BY_HANDLE_FILE_INFORMATION information);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string path,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateDirectoryW(string path, IntPtr securityAttributes);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadFile(
        SafeFileHandle handle,
        [Out] byte[] buffer,
        uint bytesToRead,
        out uint bytesRead,
        IntPtr overlapped);

    [StructLayout(LayoutKind.Sequential)]
    private struct FILE_DISPOSITION_INFO
    {
        [MarshalAs(UnmanagedType.Bool)]
        public bool DeleteFile;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetFileInformationByHandle(
        SafeFileHandle handle,
        int fileInformationClass,
        ref FILE_DISPOSITION_INFO fileInformation,
        uint bufferSize);

    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        [MarshalAs(UnmanagedType.Bool)] public bool bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_ACCOUNTING_INFORMATION
    {
        public long TotalUserTime;
        public long TotalKernelTime;
        public long ThisPeriodTotalUserTime;
        public long ThisPeriodTotalKernelTime;
        public uint TotalPageFaultCount;
        public uint TotalProcesses;
        public uint ActiveProcesses;
        public uint TotalTerminatedProcesses;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern KeeperActivationKernelHandle CreateJobObjectW(IntPtr securityAttributes, string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(
        KeeperActivationKernelHandle job,
        int informationClass,
        ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION information,
        uint informationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(
        KeeperActivationKernelHandle job,
        KeeperActivationKernelHandle process);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateJobObject(KeeperActivationKernelHandle job, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool QueryInformationJobObject(
        KeeperActivationKernelHandle job,
        int informationClass,
        out JOBOBJECT_BASIC_ACCOUNTING_INFORMATION information,
        uint informationLength,
        IntPtr returnLength);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcessW(
        string applicationName,
        StringBuilder commandLine,
        IntPtr processAttributes,
        IntPtr threadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandles,
        uint creationFlags,
        IntPtr environment,
        string currentDirectory,
        ref STARTUPINFO startupInformation,
        out PROCESS_INFORMATION processInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CreatePipe(
        out SafeFileHandle readPipe,
        out SafeFileHandle writePipe,
        ref SECURITY_ATTRIBUTES pipeAttributes,
        uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetHandleInformation(SafeFileHandle handle, uint mask, uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(KeeperActivationKernelHandle thread);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(KeeperActivationKernelHandle handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(KeeperActivationKernelHandle process, out uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(KeeperActivationKernelHandle process, uint exitCode);

    private sealed class BoundedOutputBudget
    {
        private readonly object gate = new object();
        private readonly long maximum;
        private long observed;
        private bool exceeded;

        internal BoundedOutputBudget(long maximumBytes)
        {
            if (maximumBytes < 1 || maximumBytes > 16L * 1024 * 1024)
            {
                throw new ArgumentOutOfRangeException("maximumBytes");
            }
            maximum = maximumBytes;
        }

        internal int Reserve(int count)
        {
            lock (gate)
            {
                long before = observed;
                observed = observed > Int64.MaxValue - count ? Int64.MaxValue : observed + count;
                if (observed > maximum) exceeded = true;
                long room = Math.Max(0L, maximum - before);
                return (int)Math.Min((long)count, room);
            }
        }

        internal bool Exceeded
        {
            get { lock (gate) { return exceeded; } }
        }

        internal long Maximum { get { return maximum; } }
    }

    private static void DrainBoundedPipe(
        SafeFileHandle handle,
        BoundedOutputBudget budget,
        MemoryStream destination)
    {
        using (handle)
        using (FileStream stream = new FileStream(handle, FileAccess.Read, 16 * 1024, false))
        {
            byte[] buffer = new byte[16 * 1024];
            for (;;)
            {
                int read = stream.Read(buffer, 0, buffer.Length);
                if (read == 0) return;
                int keep = budget.Reserve(read);
                if (keep > 0) destination.Write(buffer, 0, keep);
            }
        }
    }

    private static uint GetOwnedJobActiveProcesses(KeeperActivationKernelHandle job)
    {
        const int JobObjectBasicAccountingInformation = 1;
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION information;
        if (!QueryInformationJobObject(
            job,
            JobObjectBasicAccountingInformation,
            out information,
            (uint)Marshal.SizeOf(typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION)),
            IntPtr.Zero))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to query owned installed-smoke process tree");
        }
        return information.ActiveProcesses;
    }

    private static bool HasOwnedRootExited(KeeperActivationKernelHandle process)
    {
        const uint WaitObject0 = 0;
        const uint WaitTimeout = 258;
        uint result = WaitForSingleObject(process, 0);
        if (result == WaitObject0) return true;
        if (result == WaitTimeout) return false;
        throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to wait for owned installed-smoke root process");
    }

    private static bool IsOwnedProcessTreeEmpty(
        KeeperActivationKernelHandle job,
        KeeperActivationKernelHandle process)
    {
        bool rootExited = HasOwnedRootExited(process);
        uint activeProcesses = GetOwnedJobActiveProcesses(job);
        return rootExited && activeProcesses == 0;
    }

    private static void ConfirmOwnedProcessTreeEmpty(
        KeeperActivationKernelHandle job,
        KeeperActivationKernelHandle process,
        Task stdoutTask,
        Task stderrTask,
        int milliseconds,
        string label)
    {
        Stopwatch clock = Stopwatch.StartNew();
        for (;;)
        {
            if (IsOwnedProcessTreeEmpty(job, process))
            {
                int remaining = Math.Max(1, milliseconds - (int)Math.Min((long)milliseconds, clock.ElapsedMilliseconds));
                if (!Task.WaitAll(new Task[] { stdoutTask, stderrTask }, remaining))
                {
                    throw new TimeoutException(label + " pipes did not reach EOF after ActiveProcesses=0");
                }
                return;
            }
            long remainingMilliseconds = milliseconds - clock.ElapsedMilliseconds;
            if (remainingMilliseconds <= 0)
            {
                throw new TimeoutException(label + " did not reach ActiveProcesses=0");
            }
            Thread.Sleep((int)Math.Min(25L, remainingMilliseconds));
        }
    }

    public static KeeperActivationOwnedProcessResult RunBoundedOwnedProcess(
        string executable,
        string arguments,
        int waitMilliseconds,
        int confirmationMilliseconds,
        long maximumOutputBytes)
    {
        const int JobObjectExtendedLimitInformation = 9;
        const uint JobObjectLimitKillOnJobClose = 0x00002000;
        const uint CreateSuspended = 0x00000004;
        const uint CreateNoWindow = 0x08000000;
        const uint StartfUseStdHandles = 0x00000100;
        const uint HandleFlagInherit = 0x00000001;
        const uint StillActive = 259;
        if (String.IsNullOrWhiteSpace(executable) || executable.IndexOf('"') >= 0)
        {
            throw new ArgumentException("Owned installed-smoke executable path is invalid", "executable");
        }
        if (waitMilliseconds < 1 || confirmationMilliseconds < 1)
        {
            throw new ArgumentOutOfRangeException("waitMilliseconds");
        }

        KeeperActivationKernelHandle job = null;
        KeeperActivationKernelHandle process = null;
        KeeperActivationKernelHandle thread = null;
        SafeFileHandle stdoutRead = null;
        SafeFileHandle stdoutWrite = null;
        SafeFileHandle stderrRead = null;
        SafeFileHandle stderrWrite = null;
        SafeFileHandle stdinRead = null;
        SafeFileHandle stdinWrite = null;
        Task stdoutTask = null;
        Task stderrTask = null;
        bool processCreated = false;
        bool assigned = false;
        try
        {
            job = CreateJobObjectW(IntPtr.Zero, null);
            if (job == null || job.IsInvalid)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to create owned installed-smoke job object");
            }
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION jobLimits = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            jobLimits.BasicLimitInformation.LimitFlags = JobObjectLimitKillOnJobClose;
            if (!SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                ref jobLimits,
                (uint)Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION))))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to configure owned installed-smoke job object");
            }

            SECURITY_ATTRIBUTES pipeAttributes = new SECURITY_ATTRIBUTES();
            pipeAttributes.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
            pipeAttributes.bInheritHandle = true;
            if (!CreatePipe(out stdoutRead, out stdoutWrite, ref pipeAttributes, 0) ||
                !CreatePipe(out stderrRead, out stderrWrite, ref pipeAttributes, 0) ||
                !CreatePipe(out stdinRead, out stdinWrite, ref pipeAttributes, 0))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to create owned installed-smoke standard-I/O pipes");
            }
            if (!SetHandleInformation(stdoutRead, HandleFlagInherit, 0) ||
                !SetHandleInformation(stderrRead, HandleFlagInherit, 0) ||
                !SetHandleInformation(stdinWrite, HandleFlagInherit, 0))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to isolate owned installed-smoke pipe handles");
            }

            STARTUPINFO startup = new STARTUPINFO();
            startup.cb = Marshal.SizeOf(typeof(STARTUPINFO));
            startup.dwFlags = StartfUseStdHandles;
            startup.hStdInput = stdinRead.DangerousGetHandle();
            startup.hStdOutput = stdoutWrite.DangerousGetHandle();
            startup.hStdError = stderrWrite.DangerousGetHandle();
            PROCESS_INFORMATION created;
            StringBuilder commandLine = new StringBuilder("\"" + executable + "\" " + arguments);
            if (!CreateProcessW(
                executable,
                commandLine,
                IntPtr.Zero,
                IntPtr.Zero,
                true,
                CreateSuspended | CreateNoWindow,
                IntPtr.Zero,
                null,
                ref startup,
                out created))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to create suspended owned installed-smoke process");
            }
            processCreated = true;
            process = new KeeperActivationKernelHandle(created.hProcess);
            thread = new KeeperActivationKernelHandle(created.hThread);
            int rootPid = unchecked((int)created.dwProcessId);
            stdoutWrite.Dispose(); stdoutWrite = null;
            stderrWrite.Dispose(); stderrWrite = null;
            stdinRead.Dispose(); stdinRead = null;
            stdinWrite.Dispose(); stdinWrite = null;

            if (!AssignProcessToJobObject(job, process))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to assign suspended installed-smoke process to its owned job");
            }
            assigned = true;
            BoundedOutputBudget outputBudget = new BoundedOutputBudget(maximumOutputBytes);
            MemoryStream stdout = new MemoryStream();
            MemoryStream stderr = new MemoryStream();
            SafeFileHandle capturedStdout = stdoutRead; stdoutRead = null;
            SafeFileHandle capturedStderr = stderrRead; stderrRead = null;
            stdoutTask = Task.Factory.StartNew(
                delegate { DrainBoundedPipe(capturedStdout, outputBudget, stdout); },
                CancellationToken.None,
                TaskCreationOptions.LongRunning,
                TaskScheduler.Default);
            stderrTask = Task.Factory.StartNew(
                delegate { DrainBoundedPipe(capturedStderr, outputBudget, stderr); },
                CancellationToken.None,
                TaskCreationOptions.LongRunning,
                TaskScheduler.Default);
            if (ResumeThread(thread) == UInt32.MaxValue)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to resume owned installed-smoke process inside its job");
            }
            thread.Dispose(); thread = null;

            Stopwatch waitClock = Stopwatch.StartNew();
            bool timedOut = false;
            bool outputExceeded = false;
            for (;;)
            {
                if (outputBudget.Exceeded) { outputExceeded = true; break; }
                if (IsOwnedProcessTreeEmpty(job, process)) break;
                long remainingMilliseconds = waitMilliseconds - waitClock.ElapsedMilliseconds;
                if (remainingMilliseconds <= 0) { timedOut = true; break; }
                Thread.Sleep((int)Math.Min(25L, remainingMilliseconds));
            }
            if (timedOut || outputExceeded)
            {
                string reason = timedOut ? "the activation deadline" : "the bounded output limit";
                if (!TerminateJobObject(job, 0xC000013A))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to terminate owned installed-smoke process tree after " + reason);
                }
                ConfirmOwnedProcessTreeEmpty(
                    job, process, stdoutTask, stderrTask, confirmationMilliseconds,
                    "Owned installed-smoke process tree termination");
            }
            else
            {
                int remaining = Math.Max(1, waitMilliseconds - (int)Math.Min((long)waitMilliseconds, waitClock.ElapsedMilliseconds));
                if (!Task.WaitAll(new Task[] { stdoutTask, stderrTask }, remaining))
                {
                    timedOut = true;
                    if (!TerminateJobObject(job, 0xC000013A))
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to terminate owned installed-smoke process tree after pipe deadline");
                    }
                    ConfirmOwnedProcessTreeEmpty(
                        job, process, stdoutTask, stderrTask, confirmationMilliseconds,
                        "Owned installed-smoke process tree pipe termination");
                }
            }
            uint nativeExitCode;
            if (!GetExitCodeProcess(process, out nativeExitCode) || nativeExitCode == StillActive)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to confirm owned installed-smoke root exit code");
            }
            string stdoutText = Encoding.UTF8.GetString(stdout.ToArray());
            string stderrText = Encoding.UTF8.GetString(stderr.ToArray());
            string output = String.Join(Environment.NewLine, new string[] { stdoutText, stderrText }).TrimEnd();
            if (outputBudget.Exceeded)
            {
                output += Environment.NewLine + "[installed smoke output truncated at " + outputBudget.Maximum + " bytes]";
            }
            stdout.Dispose();
            stderr.Dispose();
            return new KeeperActivationOwnedProcessResult
            {
                RootPid = rootPid,
                ExitCode = unchecked((int)nativeExitCode),
                Output = output,
                TimedOut = timedOut,
                OutputLimitExceeded = outputExceeded
            };
        }
        catch
        {
            if (processCreated && process != null && !process.IsInvalid && !HasOwnedRootExited(process))
            {
                if (assigned && job != null && !job.IsInvalid) TerminateJobObject(job, 0xC000013A);
                else TerminateProcess(process, 0xC000013A);
                WaitForSingleObject(process, 5000);
            }
            throw;
        }
        finally
        {
            if (stdoutRead != null) stdoutRead.Dispose();
            if (stdoutWrite != null) stdoutWrite.Dispose();
            if (stderrRead != null) stderrRead.Dispose();
            if (stderrWrite != null) stderrWrite.Dispose();
            if (stdinRead != null) stdinRead.Dispose();
            if (stdinWrite != null) stdinWrite.Dispose();
            if (thread != null) thread.Dispose();
            if (process != null) process.Dispose();
            if (job != null) job.Dispose();
        }
    }

    private static string FileIdentity(BY_HANDLE_FILE_INFORMATION information)
    {
        return string.Format(
            CultureInfo.InvariantCulture,
            "{0:x8}:{1:x8}:{2:x8}",
            information.VolumeSerialNumber,
            information.FileIndexHigh,
            information.FileIndexLow);
    }

    private static long FileLength(BY_HANDLE_FILE_INFORMATION information)
    {
        return ((long)information.FileSizeHigh << 32) | information.FileSizeLow;
    }

    private static bool SameFileEvidence(BY_HANDLE_FILE_INFORMATION left, BY_HANDLE_FILE_INFORMATION right)
    {
        return left.VolumeSerialNumber == right.VolumeSerialNumber &&
            left.FileIndexHigh == right.FileIndexHigh &&
            left.FileIndexLow == right.FileIndexLow &&
            left.NumberOfLinks == right.NumberOfLinks &&
            FileLength(left) == FileLength(right) &&
            left.FileAttributes == right.FileAttributes &&
            left.LastWriteTime.dwHighDateTime == right.LastWriteTime.dwHighDateTime &&
            left.LastWriteTime.dwLowDateTime == right.LastWriteTime.dwLowDateTime;
    }

    private static SafeFileHandle OpenFileEvidenceHandle(string path)
    {
        const uint GENERIC_READ = 0x80000000;
        const uint FILE_SHARE_READ = 0x00000001;
        const uint OPEN_EXISTING = 3;
        const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
        SafeFileHandle handle = CreateFileW(
            path,
            GENERIC_READ,
            FILE_SHARE_READ,
            IntPtr.Zero,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to open package file without following reparse points");
        }
        return handle;
    }

    public static SafeFileHandle OpenDirectoryMutationLease(string path)
    {
        const uint FILE_READ_ATTRIBUTES = 0x00000080;
        const uint DELETE = 0x00010000;
        const uint FILE_SHARE_READ = 0x00000001;
        const uint FILE_SHARE_WRITE = 0x00000002;
        const uint OPEN_EXISTING = 3;
        const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
        const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        const uint FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
        const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;
        SafeFileHandle handle = CreateFileW(
            path,
            FILE_READ_ATTRIBUTES | DELETE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            IntPtr.Zero,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to acquire staging directory mutation lease");
        }
        BY_HANDLE_FILE_INFORMATION information;
        if (!GetFileInformationByHandle(handle, out information) ||
            (information.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
            (information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            if (error != 0) throw new Win32Exception(error, "Unable to identify staging directory mutation lease");
            throw new InvalidOperationException("Staging directory mutation lease must identify a non-reparse directory");
        }
        return handle;
    }

    public static void CreateDirectoryExclusive(string path)
    {
        if (!CreateDirectoryW(path, IntPtr.Zero))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to acquire exclusive activation test-control directory");
        }
    }

    public static string[] EnumerateImmediateChildrenBounded(string path, int maximumEntries, int timeoutMilliseconds)
    {
        if (maximumEntries < 0) throw new ArgumentOutOfRangeException("maximumEntries");
        if (timeoutMilliseconds <= 0) throw new ArgumentOutOfRangeException("timeoutMilliseconds");
        Task<string[]> task = Task.Factory.StartNew(delegate
        {
            System.Collections.Generic.List<string> entries = new System.Collections.Generic.List<string>();
            foreach (string entry in Directory.EnumerateFileSystemEntries(path))
            {
                if (entries.Count >= maximumEntries)
                {
                    throw new KeeperActivationPackageShapeException("Directory inventory exceeds its bounded entry limit");
                }
                entries.Add(entry);
            }
            return entries.ToArray();
        });
        try
        {
            if (!task.Wait(timeoutMilliseconds))
            {
                throw new TimeoutException("Directory inventory exceeded its bounded operation timeout");
            }
        }
        catch (AggregateException error)
        {
            AggregateException flattened = error.Flatten();
            if (flattened.InnerExceptions.Count == 1)
            {
                ExceptionDispatchInfo.Capture(flattened.InnerExceptions[0]).Throw();
            }
            throw;
        }
        return task.GetAwaiter().GetResult();
    }

    public static KeeperActivationFileEvidence ReadBoundedSingleLinkFile(string path, long maximumBytes)
    {
        const uint FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
        const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;
        if (maximumBytes < 0 || maximumBytes > Int32.MaxValue)
        {
            throw new ArgumentOutOfRangeException("maximumBytes");
        }
        BY_HANDLE_FILE_INFORMATION before;
        byte[] bytes;
        using (SafeFileHandle handle = OpenFileEvidenceHandle(path))
        {
            if (!GetFileInformationByHandle(handle, out before))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to identify package file");
            }
            long length = FileLength(before);
            if ((before.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0)
            {
                throw new KeeperActivationPackageShapeException("Package file must be a non-reparse regular file");
            }
            if (before.NumberOfLinks != 1)
            {
                throw new KeeperActivationPackageShapeException("Package file must have exactly one hard link");
            }
            if (length < 0 || length > maximumBytes)
            {
                throw new KeeperActivationPackageShapeException(string.Format(
                    CultureInfo.InvariantCulture,
                    "Package file size {0} exceeds the per-file limit of {1} bytes",
                    length,
                    maximumBytes));
            }
            bytes = new byte[(int)length];
            using (FileStream stream = new FileStream(handle, FileAccess.Read))
            {
                int offset = 0;
                while (offset < bytes.Length)
                {
                    int read = stream.Read(bytes, offset, Math.Min(64 * 1024, bytes.Length - offset));
                    if (read <= 0) throw new KeeperActivationIdentityException("Package file ended during bounded read");
                    offset += read;
                }
                if (stream.ReadByte() != -1) throw new KeeperActivationIdentityException("Package file grew during bounded read");
                BY_HANDLE_FILE_INFORMATION after;
                if (!GetFileInformationByHandle(stream.SafeFileHandle, out after) || !SameFileEvidence(before, after))
                {
                    throw new KeeperActivationIdentityException("Package file identity changed during bounded read");
                }
            }
        }
        using (SafeFileHandle finalHandle = OpenFileEvidenceHandle(path))
        {
            BY_HANDLE_FILE_INFORMATION finalInformation;
            if (!GetFileInformationByHandle(finalHandle, out finalInformation) || !SameFileEvidence(before, finalInformation))
            {
                throw new KeeperActivationIdentityException("Package file pathname identity changed after bounded read");
            }
        }
        string digest;
        using (SHA256 sha = SHA256.Create())
        {
            digest = BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant();
        }
        return new KeeperActivationFileEvidence(bytes, FileIdentity(before), bytes.LongLength, digest);
    }

    private static SafeFileHandle OpenDeleteLeaseHandle(string path, bool directory)
    {
        const uint GENERIC_READ = 0x80000000;
        const uint FILE_READ_ATTRIBUTES = 0x00000080;
        const uint DELETE = 0x00010000;
        const uint FILE_SHARE_READ = 0x00000001;
        const uint FILE_SHARE_WRITE = 0x00000002;
        const uint OPEN_EXISTING = 3;
        const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
        const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        SafeFileHandle handle = CreateFileW(
            path,
            (directory ? FILE_READ_ATTRIBUTES : GENERIC_READ) | DELETE,
            directory ? FILE_SHARE_READ | FILE_SHARE_WRITE : FILE_SHARE_READ,
            IntPtr.Zero,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | (directory ? FILE_FLAG_BACKUP_SEMANTICS : 0),
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to acquire authenticated cleanup delete lease");
        }
        return handle;
    }

    public static KeeperActivationDeleteLease OpenVerifiedFileDeleteLease(
        string path,
        long maximumBytes,
        string expectedIdentity,
        long expectedLength,
        string expectedSha256)
    {
        const uint FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
        const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;
        if (maximumBytes < 0 || maximumBytes > Int32.MaxValue) throw new ArgumentOutOfRangeException("maximumBytes");
        SafeFileHandle handle = OpenDeleteLeaseHandle(path, false);
        try
        {
            BY_HANDLE_FILE_INFORMATION before;
            if (!GetFileInformationByHandle(handle, out before))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to identify cleanup file delete lease");
            }
            long length = FileLength(before);
            if ((before.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 || before.NumberOfLinks != 1)
            {
                throw new InvalidOperationException("Cleanup file delete lease must identify a single-link non-reparse regular file");
            }
            if (length < 0 || length > maximumBytes || length != expectedLength ||
                !String.Equals(FileIdentity(before), expectedIdentity, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Cleanup file identity or bounded length changed before delete-lease acquisition");
            }
            byte[] bytes = new byte[(int)length];
            int offset = 0;
            while (offset < bytes.Length)
            {
                byte[] chunk = new byte[Math.Min(64 * 1024, bytes.Length - offset)];
                uint read;
                if (!ReadFile(handle, chunk, (uint)chunk.Length, out read, IntPtr.Zero))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to read cleanup file delete lease");
                }
                if (read == 0) throw new EndOfStreamException("Cleanup file ended during delete-lease authentication");
                Buffer.BlockCopy(chunk, 0, bytes, offset, (int)read);
                offset += (int)read;
            }
            byte[] overflow = new byte[1];
            uint overflowRead;
            if (!ReadFile(handle, overflow, 1, out overflowRead, IntPtr.Zero))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to authenticate cleanup file EOF");
            }
            if (overflowRead != 0) throw new InvalidOperationException("Cleanup file grew during delete-lease authentication");
            BY_HANDLE_FILE_INFORMATION after;
            if (!GetFileInformationByHandle(handle, out after) || !SameFileEvidence(before, after))
            {
                throw new InvalidOperationException("Cleanup file changed during delete-lease authentication");
            }
            string digest;
            using (SHA256 sha = SHA256.Create())
            {
                digest = BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant();
            }
            if (!String.Equals(digest, expectedSha256, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Cleanup file digest changed before delete-lease acquisition");
            }
            return new KeeperActivationDeleteLease(handle, false);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    public static KeeperActivationDeleteLease OpenVerifiedDirectoryDeleteLease(string path, string expectedIdentity)
    {
        const uint FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
        const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;
        SafeFileHandle handle = OpenDeleteLeaseHandle(path, true);
        try
        {
            BY_HANDLE_FILE_INFORMATION information;
            if (!GetFileInformationByHandle(handle, out information))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to identify cleanup directory delete lease");
            }
            if ((information.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
                (information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
                !String.Equals(FileIdentity(information), expectedIdentity, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Cleanup directory identity changed before delete-lease acquisition");
            }
            return new KeeperActivationDeleteLease(handle, true);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    public static void DeleteVerifiedLease(KeeperActivationDeleteLease lease)
    {
        if (lease == null || lease.Handle == null || lease.Handle.IsInvalid || lease.Handle.IsClosed || lease.DeleteRequested)
        {
            throw new InvalidOperationException("Cleanup delete lease is invalid or already consumed");
        }
        const int FileDispositionInfo = 4;
        FILE_DISPOSITION_INFO disposition = new FILE_DISPOSITION_INFO { DeleteFile = true };
        if (!SetFileInformationByHandle(
            lease.Handle,
            FileDispositionInfo,
            ref disposition,
            (uint)Marshal.SizeOf(typeof(FILE_DISPOSITION_INFO))))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to delete authenticated cleanup handle");
        }
        lease.DeleteRequested = true;
    }

    [DllImport("shell32.dll", SetLastError = true)]
    private static extern IntPtr CommandLineToArgvW(
        [MarshalAs(UnmanagedType.LPWStr)] string commandLine,
        out int argumentCount);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr memory);

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2_0;
        public IntPtr Reserved2_1;
        public IntPtr UniqueProcessId;
        public IntPtr Reserved3;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool IsWow64Process(IntPtr process, out bool wow64Process);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(
        IntPtr process,
        IntPtr baseAddress,
        [Out] byte[] buffer,
        IntPtr size,
        out IntPtr bytesRead);

    [DllImport("ntdll.dll", EntryPoint = "NtQueryInformationProcess")]
    private static extern int NtQueryInformationProcessBasic(
        IntPtr process,
        int informationClass,
        out PROCESS_BASIC_INFORMATION information,
        int informationLength,
        out int returnLength);

    [DllImport("ntdll.dll", EntryPoint = "NtQueryInformationProcess")]
    private static extern int NtQueryInformationProcessPointer(
        IntPtr process,
        int informationClass,
        out IntPtr information,
        int informationLength,
        out int returnLength);

    public static uint GetLinkCount(string path)
    {
        using (FileStream stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete))
        {
            BY_HANDLE_FILE_INFORMATION information;
            if (!GetFileInformationByHandle(stream.SafeFileHandle, out information))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            return information.NumberOfLinks;
        }
    }

    public static string GetDirectoryIdentity(string path)
    {
        const uint FILE_READ_ATTRIBUTES = 0x0080;
        const uint FILE_SHARE_READ = 0x00000001;
        const uint FILE_SHARE_WRITE = 0x00000002;
        const uint FILE_SHARE_DELETE = 0x00000004;
        const uint OPEN_EXISTING = 3;
        const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
        const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        const uint FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
        const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;

        using (SafeFileHandle handle = CreateFileW(
            path,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            IntPtr.Zero,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            IntPtr.Zero))
        {
            if (handle.IsInvalid)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to open directory without following reparse points");
            }
            BY_HANDLE_FILE_INFORMATION information;
            if (!GetFileInformationByHandle(handle, out information))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to identify directory");
            }
            if ((information.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
                (information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
            {
                throw new InvalidOperationException("Path must identify a non-reparse directory");
            }
            return string.Format(
                CultureInfo.InvariantCulture,
                "{0:x8}:{1:x8}:{2:x8}",
                information.VolumeSerialNumber,
                information.FileIndexHigh,
                information.FileIndexLow);
        }
    }

    public static string[] ParseCommandLine(string commandLine)
    {
        int count;
        IntPtr pointer = CommandLineToArgvW(commandLine, out count);
        if (pointer == IntPtr.Zero)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        try
        {
            string[] arguments = new string[count];
            for (int index = 0; index < count; index++)
            {
                arguments[index] = Marshal.PtrToStringUni(Marshal.ReadIntPtr(pointer, index * IntPtr.Size));
            }
            return arguments;
        }
        finally
        {
            LocalFree(pointer);
        }
    }

    private static byte[] ReadRemoteBytes(IntPtr process, ulong address, int count)
    {
        byte[] bytes = new byte[count];
        IntPtr read;
        if (!ReadProcessMemory(process, new IntPtr(unchecked((long)address)), bytes, new IntPtr(count), out read) ||
            read.ToInt64() != count)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to read the target process parameters");
        }
        return bytes;
    }

    private static ulong ReadRemotePointer(IntPtr process, ulong address, int pointerSize)
    {
        byte[] bytes = ReadRemoteBytes(process, address, pointerSize);
        return pointerSize == 8 ? BitConverter.ToUInt64(bytes, 0) : BitConverter.ToUInt32(bytes, 0);
    }

    public static string GetProcessCurrentDirectory(long processId)
    {
        const uint PROCESS_VM_READ = 0x0010;
        const uint PROCESS_QUERY_INFORMATION = 0x0400;
        IntPtr process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, checked((int)processId));
        if (process == IntPtr.Zero)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to open the target process");
        }
        try
        {
            bool wow64;
            if (!IsWow64Process(process, out wow64))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to determine target process bitness");
            }
            if (!Environment.Is64BitProcess && Environment.Is64BitOperatingSystem && !wow64)
            {
                throw new NotSupportedException("A 32-bit activation host cannot inspect a 64-bit Node process");
            }

            int pointerSize = wow64 ? 4 : IntPtr.Size;
            ulong pebAddress;
            int returned;
            if (wow64 && Environment.Is64BitProcess)
            {
                IntPtr wow64Peb;
                int status = NtQueryInformationProcessPointer(process, 26, out wow64Peb, IntPtr.Size, out returned);
                if (status != 0 || wow64Peb == IntPtr.Zero)
                {
                    throw new InvalidOperationException("Unable to query the target WOW64 process environment block");
                }
                pebAddress = unchecked((ulong)wow64Peb.ToInt64());
            }
            else
            {
                PROCESS_BASIC_INFORMATION basic;
                int status = NtQueryInformationProcessBasic(
                    process,
                    0,
                    out basic,
                    Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)),
                    out returned);
                if (status != 0 || basic.PebBaseAddress == IntPtr.Zero)
                {
                    throw new InvalidOperationException("Unable to query the target process environment block");
                }
                pebAddress = unchecked((ulong)basic.PebBaseAddress.ToInt64());
            }

            ulong processParameters = ReadRemotePointer(process, pebAddress + (pointerSize == 8 ? 0x20UL : 0x10UL), pointerSize);
            if (processParameters == 0) throw new InvalidOperationException("Target process parameters are unavailable");
            ulong currentDirectory = processParameters + (pointerSize == 8 ? 0x38UL : 0x24UL);
            ushort byteLength = BitConverter.ToUInt16(ReadRemoteBytes(process, currentDirectory, 2), 0);
            if ((byteLength & 1) != 0 || byteLength > 32766)
            {
                throw new InvalidOperationException("Target process current directory has an invalid length");
            }
            ulong buffer = ReadRemotePointer(process, currentDirectory + (pointerSize == 8 ? 8UL : 4UL), pointerSize);
            if (byteLength == 0 || buffer == 0) throw new InvalidOperationException("Target process current directory is unavailable");
            return Encoding.Unicode.GetString(ReadRemoteBytes(process, buffer, byteLength));
        }
        finally
        {
            CloseHandle(process);
        }
    }
}
"@
}

$ExactPackageFiles = @(
    ".codex-plugin/plugin.json",
    ".mcp.json",
    "dist/index.js",
    "package.json",
    "skills/distill-project-design/agents/openai.yaml",
    "skills/distill-project-design/assets/knowledge-pack/architecture.md.template",
    "skills/distill-project-design/assets/knowledge-pack/archive-index.md.template",
    "skills/distill-project-design/assets/knowledge-pack/conventions.md.template",
    "skills/distill-project-design/assets/knowledge-pack/decisions.md.template",
    "skills/distill-project-design/assets/knowledge-pack/evidence-map.md.template",
    "skills/distill-project-design/assets/knowledge-pack/index.md.template",
    "skills/distill-project-design/assets/knowledge-pack/intent.md.template",
    "skills/distill-project-design/assets/knowledge-pack/manifest.json",
    "skills/distill-project-design/assets/knowledge-pack/module.md.template",
    "skills/distill-project-design/assets/knowledge-pack/open-questions.md.template",
    "skills/distill-project-design/assets/knowledge-pack/principles.md.template",
    "skills/distill-project-design/assets/knowledge-pack/tuning.md.template",
    "skills/distill-project-design/assets/knowledge-pack/verification.md.template",
    "skills/distill-project-design/assets/project-design-context/agents/openai.yaml",
    "skills/distill-project-design/assets/project-design-context/SKILL.md",
    "skills/distill-project-design/references/document-contract.md",
    "skills/distill-project-design/references/knowledge-model.md",
    "skills/distill-project-design/references/mcp-tools.md",
    "skills/distill-project-design/references/workflow.md",
    "skills/distill-project-design/SKILL.md"
) | Sort-Object -CaseSensitive
$PackageMaximumFileBytes = 16 * 1024 * 1024
$PackageMaximumJsonBytes = 256 * 1024
$PackageMaximumTotalBytes = 64 * 1024 * 1024
$InstallParentMaximumEntries = 1024
$ProcessFixtureMaximumBytes = 256 * 1024
$ActivationMaximumProcessRecords = 4096
$ActivationDirectoryOperationTimeoutMs = 5000
$script:ActivationClock = [Diagnostics.Stopwatch]::StartNew()
$script:ActivationDeadlineAtMs = [long]120000
$script:ActivationRecoveryMode = $false
$script:ActivationForwardDeadlineExpired = $false
$script:ActivationExpireAtNextDeadlineCheck = $false
$script:ActivationSmokeTimeoutOverrideMs = $null

function Assert-ActivationDeadline {
    param([string]$Phase)
    if ($script:ActivationExpireAtNextDeadlineCheck) {
        $script:ActivationExpireAtNextDeadlineCheck = $false
        $script:ActivationDeadlineAtMs = $script:ActivationClock.ElapsedMilliseconds
    }
    if ($script:ActivationClock.ElapsedMilliseconds -ge $script:ActivationDeadlineAtMs) {
        if (-not $script:ActivationRecoveryMode) { $script:ActivationForwardDeadlineExpired = $true }
        throw ([KeeperActivationDeadlineException]::new(
            "Activation operation deadline exceeded during $Phase"))
    }
}

function Test-ActivationExceptionType {
    param([Exception]$Exception, [Type]$ExpectedType)
    $current = $Exception
    for ($depth = 0; $depth -lt 16 -and $null -ne $current; $depth += 1) {
        if ($ExpectedType.IsAssignableFrom($current.GetType())) { return $true }
        $current = $current.InnerException
    }
    return $false
}

function Get-ActivationExceptionDetail {
    param([Exception]$Exception)
    $current = $Exception
    for ($depth = 0; $depth -lt 16 -and $null -ne $current.InnerException; $depth += 1) {
        $current = $current.InnerException
    }
    return $current.Message
}

function Test-ActivationDeadlineException {
    param([Exception]$Exception)
    return Test-ActivationExceptionType $Exception ([KeeperActivationDeadlineException])
}

function Test-ActivationPackageShapeException {
    param([Exception]$Exception)
    return Test-ActivationExceptionType $Exception ([KeeperActivationPackageShapeException])
}

function Get-ActivationOperationTimeoutMs {
    param([string]$Phase, [int]$MaximumMilliseconds = $ActivationDirectoryOperationTimeoutMs)
    Assert-ActivationDeadline $Phase
    $remaining = $script:ActivationDeadlineAtMs - $script:ActivationClock.ElapsedMilliseconds
    if ($remaining -le 0) {
        if (-not $script:ActivationRecoveryMode) { $script:ActivationForwardDeadlineExpired = $true }
        throw ([KeeperActivationDeadlineException]::new(
            "Activation operation deadline exceeded during $Phase"))
    }
    return [int][Math]::Max(1, [Math]::Min([long]$MaximumMilliseconds, $remaining))
}

function Test-SamePath {
    param([string]$Left, [string]$Right)
    return [string]::Equals(
        [IO.Path]::GetFullPath($Left).TrimEnd([char[]]@('\', '/')),
        [IO.Path]::GetFullPath($Right).TrimEnd([char[]]@('\', '/')),
        [StringComparison]::OrdinalIgnoreCase)
}

function Assert-FullyQualifiedPath {
    param([string]$Label, [string]$Path)
    if (-not [string]::IsNullOrWhiteSpace($Path) -and
        ($Path.StartsWith('\\?\', [StringComparison]::Ordinal) -or
         $Path.StartsWith('\\.\', [StringComparison]::Ordinal))) {
        throw "$Label uses an unsupported Win32 device namespace"
    }
    if ([string]::IsNullOrWhiteSpace($Path) -or
        -not ($Path -match '^(?:[A-Za-z]:[\\/]|\\\\[^\\/]+[\\/][^\\/]+)')) {
        throw "$Label must be an absolute fully qualified path"
    }
}

function Assert-NoReparsePathComponents {
    param([string]$Label, [string]$Path)
    $root = [IO.Path]::GetPathRoot($Path)
    $current = $root
    $remainder = $Path.Substring($root.Length)
    foreach ($component in $remainder.Split([char[]]@('\', '/'), [StringSplitOptions]::RemoveEmptyEntries)) {
        $current = [IO.Path]::Combine($current, $component)
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Label contains a reparse point or symbolic link: $current"
            }
        }
    }
}

function Get-ValidatedDirectory {
    param([string]$Label, [string]$Path)
    Assert-FullyQualifiedPath $Label $Path
    $full = [IO.Path]::GetFullPath($Path).TrimEnd([char[]]@('\', '/'))
    Assert-NoReparsePathComponents $Label $full
    $item = Get-Item -LiteralPath $full -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label must not be a reparse point or symbolic link"
    }
    if (-not $item.PSIsContainer) {
        throw "$Label must be a directory"
    }
    return $full
}

function Get-VerifiedDirectoryIdentity {
    param([string]$Label, [string]$Path)
    try {
        $validated = Get-ValidatedDirectory $Label $Path
        return [KeeperActivationNative]::GetDirectoryIdentity($validated)
    }
    catch {
        if ($_.Exception -is [KeeperActivationIdentityException]) { throw }
        throw ([KeeperActivationIdentityException]::new(
            "$Label identity could not be verified; preserving all ambiguous paths. $($_.Exception.Message)",
            $_.Exception))
    }
}

function Assert-VerifiedDirectoryIdentity {
    param([string]$Label, [string]$Path, [string]$ExpectedIdentity)
    if ([string]::IsNullOrWhiteSpace($ExpectedIdentity)) {
        throw ([KeeperActivationIdentityException]::new(
            "$Label identity was never captured; preserving all ambiguous paths"))
    }
    $actualIdentity = Get-VerifiedDirectoryIdentity $Label $Path
    if ($actualIdentity -cne $ExpectedIdentity) {
        throw ([KeeperActivationIdentityException]::new(
            "$Label directory identity changed; preserving all ambiguous paths"))
    }
}

function Assert-VerifiedRenameReady {
    param(
        [string]$SourceLabel,
        [string]$Source,
        [string]$ExpectedSourceIdentity,
        [string]$DestinationLabel,
        [string]$Destination,
        [string]$InstallParent,
        [string]$ExpectedParentIdentity
    )
    [void](Assert-DirectChild $SourceLabel $InstallParent $Source)
    [void](Assert-DirectChild $DestinationLabel $InstallParent $Destination)
    if (Test-Path -LiteralPath $Destination) {
        throw ([KeeperActivationIdentityException]::new(
            "$DestinationLabel unexpectedly exists before rename; preserving all ambiguous paths"))
    }
    Assert-VerifiedDirectoryIdentity $SourceLabel $Source $ExpectedSourceIdentity
    Assert-VerifiedDirectoryIdentity 'Install parent' $InstallParent $ExpectedParentIdentity
}

function Assert-VerifiedRenameResult {
    param(
        [string]$SourceLabel,
        [string]$Source,
        [string]$DestinationLabel,
        [string]$Destination,
        [string]$ExpectedMovedIdentity,
        [string]$InstallParent,
        [string]$ExpectedParentIdentity
    )
    Assert-VerifiedDirectoryIdentity $DestinationLabel $Destination $ExpectedMovedIdentity
    Assert-VerifiedDirectoryIdentity 'Install parent' $InstallParent $ExpectedParentIdentity
    if (Test-Path -LiteralPath $Source) {
        throw ([KeeperActivationIdentityException]::new(
            "$SourceLabel was replaced while its directory was renamed; preserving all ambiguous paths"))
    }
}

function Assert-DirectChild {
    param([string]$Label, [string]$Parent, [string]$Candidate)
    $fullParent = [IO.Path]::GetFullPath($Parent).TrimEnd([char[]]@('\', '/'))
    $fullCandidate = [IO.Path]::GetFullPath($Candidate).TrimEnd([char[]]@('\', '/'))
    $candidateParent = [IO.Path]::GetDirectoryName($fullCandidate).TrimEnd([char[]]@('\', '/'))
    if (-not (Test-SamePath $fullParent $candidateParent)) {
        throw "$Label escaped its expected parent: $fullCandidate"
    }
    return $fullCandidate
}

function Get-ExpectedDirectories {
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($file in $ExactPackageFiles) {
        $directory = [IO.Path]::GetDirectoryName($file).Replace('\', '/')
        while (-not [string]::IsNullOrEmpty($directory)) {
            [void]$set.Add($directory)
            $directory = [IO.Path]::GetDirectoryName($directory)
            if ($null -ne $directory) { $directory = $directory.Replace('\', '/') }
        }
    }
    return @($set) | Sort-Object -CaseSensitive
}

function Get-RelativePackagePath {
    param([string]$Root, [string]$Path)
    $prefix = $Root.TrimEnd([char[]]@('\', '/')) + [IO.Path]::DirectorySeparatorChar
    if (-not $Path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Enumerated package entry escaped its root: $Path"
    }
    return $Path.Substring($prefix.Length).Replace('\', '/')
}

function Get-ExpectedPackageChildren {
    $children = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
    $children.Add('.', (New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)))
    $directories = Get-ExpectedDirectories
    foreach ($directory in $directories) {
        $children.Add($directory, (New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)))
    }
    foreach ($directory in $directories) {
        $parent = [IO.Path]::GetDirectoryName($directory)
        if ([string]::IsNullOrEmpty($parent)) { $parent = '.' } else { $parent = $parent.Replace('\', '/') }
        $children[$parent].Add([IO.Path]::GetFileName($directory), 'directory')
    }
    foreach ($file in $ExactPackageFiles) {
        $parent = [IO.Path]::GetDirectoryName($file)
        if ([string]::IsNullOrEmpty($parent)) { $parent = '.' } else { $parent = $parent.Replace('\', '/') }
        $children[$parent].Add([IO.Path]::GetFileName($file), 'file')
    }
    return $children
}

function Assert-ExactPackageTree {
    param([string]$Root, [string]$Label)
    $validated = Get-ValidatedDirectory $Label $Root
    $topology = Get-ExpectedPackageChildren
    foreach ($relativeDirectory in @($topology.Keys) | Sort-Object -CaseSensitive) {
        $directory = if ($relativeDirectory -ceq '.') {
            $validated
        } else {
            [IO.Path]::GetFullPath([IO.Path]::Combine($validated, $relativeDirectory.Replace('/', [IO.Path]::DirectorySeparatorChar)))
        }
        [void](Get-ValidatedDirectory "$Label directory $relativeDirectory" $directory)
        $expected = $topology[$relativeDirectory]
        $observed = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
        $timeout = Get-ActivationOperationTimeoutMs "$Label directory inventory $relativeDirectory"
        try {
            $paths = [KeeperActivationNative]::EnumerateImmediateChildrenBounded(
                $directory,
                $expected.Count + 1,
                $timeout)
        }
        catch {
            if ($script:ActivationClock.ElapsedMilliseconds -ge $script:ActivationDeadlineAtMs) {
                Assert-ActivationDeadline "$Label directory inventory $relativeDirectory"
            }
            throw
        }
        foreach ($path in $paths) {
            Assert-ActivationDeadline "$Label directory inventory $relativeDirectory"
            $name = [IO.Path]::GetFileName($path)
            if ($observed.Count -ge $expected.Count -or -not $expected.ContainsKey($name)) {
                throw ([KeeperActivationPackageShapeException]::new(
                    "$Label exact allowlist contains an unexpected or case-mismatched entry in $relativeDirectory`: $name"))
            }
            $item = Get-Item -LiteralPath $path -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw ([KeeperActivationPackageShapeException]::new(
                    "$Label contains a reparse point or symbolic link: $relativeDirectory/$name"))
            }
            $expectedKind = $expected[$name]
            if (($expectedKind -ceq 'directory' -and -not $item.PSIsContainer) -or
                ($expectedKind -ceq 'file' -and -not ($item -is [IO.FileInfo]))) {
                throw ([KeeperActivationPackageShapeException]::new(
                    "$Label exact allowlist entry has the wrong kind: $relativeDirectory/$name"))
            }
            [void]$observed.Add($name)
        }
        if ($observed.Count -ne $expected.Count) {
            $missing = @($expected.Keys | Where-Object { -not $observed.Contains($_) })
            throw ([KeeperActivationPackageShapeException]::new(
                "$Label exact allowlist is missing entries in $relativeDirectory`: $($missing -join ', ')"))
        }
    }
    return $ExactPackageFiles
}

function Get-PackageEvidence {
    param([string]$Root, [string]$Label)
    $files = Assert-ExactPackageTree $Root $Label
    $totalBytes = [long]0
    $evidenceByPath = [ordered]@{}
    $hashes = [ordered]@{}
    foreach ($file in $files) {
        Assert-ActivationDeadline "$Label package evidence $file"
        $path = [IO.Path]::GetFullPath([IO.Path]::Combine($Root, $file.Replace('/', [IO.Path]::DirectorySeparatorChar)))
        $perFileLimit = if ($file.EndsWith('.json', [StringComparison]::OrdinalIgnoreCase)) {
            [long]$PackageMaximumJsonBytes
        } else {
            [long]$PackageMaximumFileBytes
        }
        $remaining = [long]$PackageMaximumTotalBytes - $totalBytes
        if ($remaining -lt 0) { throw "$Label activation package bytes exceed the aggregate limit of $PackageMaximumTotalBytes" }
        $maximumRead = [Math]::Min($perFileLimit, $remaining)
        $kind = if ($file.EndsWith('.json', [StringComparison]::OrdinalIgnoreCase)) { 'JSON' } else { 'file' }
        try {
            $evidence = [KeeperActivationNative]::ReadBoundedSingleLinkFile($path, $maximumRead)
        }
        catch {
            $detail = Get-ActivationExceptionDetail $_.Exception
            if (Test-ActivationPackageShapeException $_.Exception) {
                throw ([KeeperActivationPackageShapeException]::new(
                    "$Label activation package $kind $file bounded size limit or exact-shape check failed: $detail",
                    $_.Exception))
            }
            if ((Test-ActivationDeadlineException $_.Exception) -or
                (Test-ActivationExceptionType $_.Exception ([TimeoutException]))) {
                throw
            }
            throw ([KeeperActivationIdentityException]::new(
                "$Label activation package $kind $file identity could not be authenticated: $detail",
                $_.Exception))
        }
        $totalBytes += $evidence.Length
        if ($totalBytes -gt $PackageMaximumTotalBytes) {
            throw "$Label activation package bytes exceed the aggregate limit of $PackageMaximumTotalBytes"
        }
        $evidenceByPath[$file] = $evidence
        $hashes[$file] = $evidence.Sha256
    }
    Assert-ActivationDeadline "$Label package evidence"
    return [pscustomobject]@{ Files = $evidenceByPath; Manifest = $hashes; TotalBytes = $totalBytes }
}

function Convert-BoundedPackageJson {
    param([object]$Evidence, [string]$Label)
    try {
        return ([Text.Encoding]::UTF8.GetString($Evidence.Bytes) | ConvertFrom-Json)
    }
    catch {
        throw ([KeeperActivationPackageShapeException]::new(
            "$Label is not valid bounded JSON: $($_.Exception.Message)",
            $_.Exception))
    }
}

function Assert-PackageIdentity {
    param([object]$Evidence, [string]$Label)
    try {
        $plugin = Convert-BoundedPackageJson $Evidence.Files['.codex-plugin/plugin.json'] "$Label plugin manifest"
        $package = Convert-BoundedPackageJson $Evidence.Files['package.json'] "$Label package manifest"
        $configuration = Convert-BoundedPackageJson $Evidence.Files['.mcp.json'] "$Label MCP manifest"
        if ($plugin.name -ne 'project-design-keeper' -or $plugin.version -ne '1.0.2' -or
            $plugin.skills -ne './skills/' -or $plugin.mcpServers -ne './.mcp.json' -or
            $package.name -ne 'project-design-keeper' -or $package.version -ne '1.0.2') {
            throw ([KeeperActivationPackageShapeException]::new(
                "$Label has the wrong project-design-keeper package identity"))
        }
        $mcp = $configuration.mcpServers.'project-design-keeper'
        $mcpProperties = @($mcp.PSObject.Properties.Name) | Sort-Object -CaseSensitive
        if (@(Compare-Object -ReferenceObject @('args', 'command', 'cwd') -DifferenceObject $mcpProperties -CaseSensitive).Count -ne 0 -or
            $mcp.command -ne 'node' -or $mcp.cwd -ne '.' -or @($mcp.args).Count -ne 1 -or $mcp.args[0] -ne 'dist/index.js') {
            throw ([KeeperActivationPackageShapeException]::new(
                "$Label has the wrong relocatable MCP command"))
        }
    }
    catch {
        if (Test-ActivationPackageShapeException $_.Exception) { throw }
        throw ([KeeperActivationPackageShapeException]::new(
            "$Label has invalid or incomplete project-design-keeper package identity: " +
            (Get-ActivationExceptionDetail $_.Exception),
            $_.Exception))
    }
}

function Get-PackageManifest {
    param([string]$Root, [string]$Label)
    $evidence = Get-PackageEvidence $Root $Label
    Assert-PackageIdentity $evidence $Label
    return $evidence.Manifest
}

function Assert-SameManifest {
    param([string]$Label, [System.Collections.IDictionary]$Expected, [System.Collections.IDictionary]$Actual)
    $expectedKeys = @($Expected.Keys)
    $actualKeys = @($Actual.Keys)
    if (@(Compare-Object -ReferenceObject $expectedKeys -DifferenceObject $actualKeys -CaseSensitive).Count -ne 0) {
        throw "$Label file names changed"
    }
    foreach ($key in $expectedKeys) {
        if ($Expected[$key] -cne $Actual[$key]) {
            throw "$Label SHA-256 hash mismatch for $key"
        }
    }
}

function Assert-AuthenticatedInstallState {
    param(
        [string]$InstallRoot,
        [string]$InstallIdentity,
        [System.Collections.IDictionary]$InstallManifest,
        [string]$Backup,
        [string]$BackupIdentity,
        [System.Collections.IDictionary]$BackupManifest,
        [string]$InstallParent,
        [string]$InstallParentIdentity,
        [string]$Phase
    )
    try {
        Assert-VerifiedDirectoryIdentity 'Install parent' $InstallParent $InstallParentIdentity
        Assert-VerifiedDirectoryIdentity 'Activated install' $InstallRoot $InstallIdentity
        $observedInstallManifest = Get-PackageManifest $InstallRoot "Activated install $Phase"
        Assert-SameManifest "Activated install manifest changed $Phase" $InstallManifest $observedInstallManifest
        Assert-VerifiedDirectoryIdentity 'Activated install' $InstallRoot $InstallIdentity
        Assert-VerifiedDirectoryIdentity 'Retained backup' $Backup $BackupIdentity
        $observedBackupManifest = Get-PackageManifest $Backup "Retained backup $Phase"
        Assert-SameManifest "Retained backup manifest changed $Phase" $BackupManifest $observedBackupManifest
        Assert-VerifiedDirectoryIdentity 'Retained backup' $Backup $BackupIdentity
        Assert-VerifiedDirectoryIdentity 'Install parent' $InstallParent $InstallParentIdentity
    }
    catch {
        if ($_.Exception -is [KeeperActivationIdentityException]) { throw }
        throw ([KeeperActivationIdentityException]::new(
            "Activation state could not be authenticated $Phase; preserving active and backup evidence. $($_.Exception.Message)",
            $_.Exception))
    }
}

function Resolve-SecondRenameFailureState {
    param(
        [string]$Staging,
        [string]$StagingIdentity,
        [System.Collections.IDictionary]$StagingManifest,
        [string]$InstallRoot,
        [string]$Backup,
        [string]$BackupIdentity,
        [System.Collections.IDictionary]$BackupManifest,
        [string]$InstallParent,
        [string]$InstallParentIdentity
    )
    try {
        Assert-VerifiedDirectoryIdentity 'Install parent' $InstallParent $InstallParentIdentity
        Assert-VerifiedDirectoryIdentity 'Previous active backup' $Backup $BackupIdentity
        $observedBackupManifest = Get-PackageManifest $Backup 'Previous active backup after second rename failure'
        Assert-SameManifest 'Previous active backup changed after second rename failure' $BackupManifest $observedBackupManifest
        Assert-VerifiedDirectoryIdentity 'Previous active backup' $Backup $BackupIdentity
        Assert-VerifiedDirectoryIdentity 'Install parent' $InstallParent $InstallParentIdentity
    }
    catch {
        if ($_.Exception -is [KeeperActivationIdentityException]) { throw }
        throw ([KeeperActivationIdentityException]::new(
            "Previous active backup could not be authenticated after the second rename failure; preserving all evidence. $($_.Exception.Message)",
            $_.Exception))
    }

    $stagingExists = Test-Path -LiteralPath $Staging
    $installExists = Test-Path -LiteralPath $InstallRoot
    if ($stagingExists -and -not $installExists) {
        $stagingTrusted = $true
        try {
            Assert-VerifiedDirectoryIdentity 'Staging directory' $Staging $StagingIdentity
            $observedStagingManifest = Get-PackageManifest $Staging 'Staging directory after second rename failure'
            Assert-SameManifest 'Staging directory changed after second rename failure' $StagingManifest $observedStagingManifest
            Assert-VerifiedDirectoryIdentity 'Staging directory' $Staging $StagingIdentity
        }
        catch {
            if (Test-ActivationDeadlineException $_.Exception) { throw }
            $stagingTrusted = $false
        }
        Assert-VerifiedDirectoryIdentity 'Install parent' $InstallParent $InstallParentIdentity
        if ($stagingTrusted) { return 'BeforeRenameTrusted' }
        return 'BeforeRenameUntrustedCandidate'
    }
    if (-not $stagingExists -and $installExists) {
        Assert-VerifiedDirectoryIdentity 'Activated install' $InstallRoot $StagingIdentity
        $observedActivatedManifest = Get-PackageManifest $InstallRoot 'Activated install after second rename failure'
        Assert-SameManifest 'Activated install changed after second rename failure' $StagingManifest $observedActivatedManifest
        Assert-VerifiedDirectoryIdentity 'Activated install' $InstallRoot $StagingIdentity
        Assert-VerifiedDirectoryIdentity 'Install parent' $InstallParent $InstallParentIdentity
        return 'AfterRenameTrusted'
    }
    if (-not $stagingExists -and -not $installExists) {
        Assert-VerifiedDirectoryIdentity 'Install parent' $InstallParent $InstallParentIdentity
        return 'CandidateMissing'
    }
    throw ([KeeperActivationIdentityException]::new(
        'Both staging and install root exist after the second rename failure; preserving all ambiguous paths'))
}

function Copy-ExactPackage {
    param(
        [string]$Source,
        [string]$Destination,
        [string]$InstallParent,
        [string]$ExpectedParentIdentity,
        [bool]$TestContext
    )
    $sourceEvidence = Get-PackageEvidence $Source 'Package source during staging'
    Assert-PackageIdentity $sourceEvidence 'Package source during staging'
    $target = Assert-DirectChild 'Staging directory' $InstallParent $Destination
    if (Test-Path -LiteralPath $target) { throw "Random staging directory already exists: $target" }
    Assert-VerifiedDirectoryIdentity 'Install parent' $InstallParent $ExpectedParentIdentity
    [void][IO.Directory]::CreateDirectory($target)
    $targetIdentity = Get-VerifiedDirectoryIdentity 'Staging directory' $target
    Assert-VerifiedDirectoryIdentity 'Install parent' $InstallParent $ExpectedParentIdentity
    $directoryIdentities = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)
    $directoryIdentities.Add('.', $targetIdentity)
    $directoryLeases = New-Object 'System.Collections.Generic.List[IDisposable]'
    try {
        $directoryLeases.Add([KeeperActivationNative]::OpenDirectoryMutationLease($target))
        foreach ($directory in Get-ExpectedDirectories) {
            $path = [IO.Path]::GetFullPath([IO.Path]::Combine($target, $directory.Replace('/', [IO.Path]::DirectorySeparatorChar)))
            if (-not $path.StartsWith($target + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
                throw "Staging subdirectory escaped its root: $path"
            }
            $parentRelative = [IO.Path]::GetDirectoryName($directory)
            if ([string]::IsNullOrEmpty($parentRelative)) { $parentRelative = '.' } else { $parentRelative = $parentRelative.Replace('\', '/') }
            $parentPath = if ($parentRelative -ceq '.') {
                $target
            } else {
                [IO.Path]::GetFullPath([IO.Path]::Combine($target, $parentRelative.Replace('/', [IO.Path]::DirectorySeparatorChar)))
            }
            Assert-VerifiedDirectoryIdentity "Staging parent directory $parentRelative" $parentPath $directoryIdentities[$parentRelative]
            Assert-VerifiedDirectoryIdentity 'Staging directory' $target $targetIdentity
            Assert-VerifiedDirectoryIdentity 'Install parent' $InstallParent $ExpectedParentIdentity
            if (Test-Path -LiteralPath $path) { throw "Staging subdirectory was occupied before exclusive creation: $directory" }
            [void][IO.Directory]::CreateDirectory($path)
            $identity = Get-VerifiedDirectoryIdentity "Staging subdirectory $directory" $path
            $directoryIdentities.Add($directory, $identity)
            $directoryLeases.Add([KeeperActivationNative]::OpenDirectoryMutationLease($path))
        }

        Invoke-TestBarrier `
            $InstallParent $ExpectedParentIdentity $TestContext `
            'KEEPER_ACTIVATION_TEST_STAGING_COPY_BARRIER' 'Activation staging-copy barrier'

        foreach ($file in $ExactPackageFiles) {
            $targetPath = [IO.Path]::GetFullPath([IO.Path]::Combine($target, $file.Replace('/', [IO.Path]::DirectorySeparatorChar)))
            if (-not $targetPath.StartsWith($target + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
                throw "Package copy path escaped an expected root: $file"
            }
            $parentRelative = [IO.Path]::GetDirectoryName($file)
            if ([string]::IsNullOrEmpty($parentRelative)) { $parentRelative = '.' } else { $parentRelative = $parentRelative.Replace('\', '/') }
            $parentPath = if ($parentRelative -ceq '.') {
                $target
            } else {
                [IO.Path]::GetFullPath([IO.Path]::Combine($target, $parentRelative.Replace('/', [IO.Path]::DirectorySeparatorChar)))
            }
            Assert-VerifiedDirectoryIdentity "Staging file parent $parentRelative" $parentPath $directoryIdentities[$parentRelative]
            Assert-VerifiedDirectoryIdentity 'Staging directory' $target $targetIdentity
            Assert-VerifiedDirectoryIdentity 'Install parent' $InstallParent $ExpectedParentIdentity
            $stream = [IO.File]::Open(
                $targetPath,
                [IO.FileMode]::CreateNew,
                [IO.FileAccess]::Write,
                [IO.FileShare]::None)
            try {
                $bytes = $sourceEvidence.Files[$file].Bytes
                $stream.Write($bytes, 0, $bytes.Length)
                $stream.Flush($true)
            }
            finally {
                $stream.Dispose()
            }
            Assert-VerifiedDirectoryIdentity "Staging file parent $parentRelative" $parentPath $directoryIdentities[$parentRelative]
        }
        Assert-VerifiedDirectoryIdentity 'Staging directory' $target $targetIdentity
        Assert-VerifiedDirectoryIdentity 'Install parent' $InstallParent $ExpectedParentIdentity
        return $targetIdentity
    }
    finally {
        for ($index = $directoryLeases.Count - 1; $index -ge 0; $index -= 1) {
            $directoryLeases[$index].Dispose()
        }
    }
}

function Get-BoundedOldBackupPaths {
    param([string]$InstallParent, [string]$Prefix)
    $paths = New-Object 'System.Collections.Generic.List[string]'
    $timeout = Get-ActivationOperationTimeoutMs 'install parent backup inventory'
    $entries = [KeeperActivationNative]::EnumerateImmediateChildrenBounded(
        $InstallParent,
        $InstallParentMaximumEntries + 1,
        $timeout)
    if ($entries.Count -gt $InstallParentMaximumEntries) {
        throw "Install parent inventory exceeds the bounded entry limit of $InstallParentMaximumEntries"
    }
    foreach ($path in $entries) {
        Assert-ActivationDeadline 'install parent backup inventory'
        if ([IO.Path]::GetFileName($path).StartsWith($Prefix, [StringComparison]::Ordinal)) {
            $paths.Add($path)
        }
    }
    return @($paths)
}

function Get-PackageCleanupInventory {
    param([string]$Root, [string]$Label)
    $package = Get-PackageEvidence $Root $Label
    Assert-PackageIdentity $package $Label
    $directories = [ordered]@{}
    foreach ($directory in Get-ExpectedDirectories) {
        $path = [IO.Path]::GetFullPath([IO.Path]::Combine($Root, $directory.Replace('/', [IO.Path]::DirectorySeparatorChar)))
        $directories[$directory] = Get-VerifiedDirectoryIdentity "$Label directory $directory" $path
    }
    return [pscustomobject]@{ Package = $package; Directories = $directories }
}

function Assert-SameCleanupInventory {
    param([string]$Label, [object]$Expected, [object]$Actual)
    Assert-SameManifest "$Label content changed" $Expected.Package.Manifest $Actual.Package.Manifest
    foreach ($file in $ExactPackageFiles) {
        $left = $Expected.Package.Files[$file]
        $right = $Actual.Package.Files[$file]
        if ($left.Identity -cne $right.Identity -or $left.Length -ne $right.Length -or $left.Sha256 -cne $right.Sha256) {
            throw ([KeeperActivationIdentityException]::new(
                "$Label file identity or content changed: $file"))
        }
    }
    foreach ($directory in $Expected.Directories.Keys) {
        if (-not $Actual.Directories.Contains($directory) -or
            $Expected.Directories[$directory] -cne $Actual.Directories[$directory]) {
            throw ([KeeperActivationIdentityException]::new(
                "$Label directory identity changed: $directory"))
        }
    }
}

function Assert-DirectoryEmptyBounded {
    param([string]$Path, [string]$Label)
    $entries = [KeeperActivationNative]::EnumerateImmediateChildrenBounded(
        $Path,
        1,
        (Get-ActivationOperationTimeoutMs $Label))
    if ($entries.Count -ne 0) {
        throw ([KeeperActivationIdentityException]::new(
            "$Label was not empty during non-recursive cleanup; preserving quarantine evidence"))
    }
}

function Remove-VerifiedTree {
    param(
        [string]$Label,
        [string]$Path,
        [string]$ExpectedParent,
        [string]$ExpectedIdentity,
        [string]$ExpectedParentIdentity,
        [System.Collections.IDictionary]$ExpectedManifest,
        [bool]$TestContext,
        [string]$PredeleteBarrierEnvironmentVariable,
        [string]$PostAuthenticationBarrierEnvironmentVariable,
        [string]$HandleDeleteBarrierEnvironmentVariable
    )
    $target = Assert-DirectChild $Label $ExpectedParent $Path
    Assert-VerifiedDirectoryIdentity $Label $target $ExpectedIdentity
    Assert-VerifiedDirectoryIdentity 'Install parent' $ExpectedParent $ExpectedParentIdentity
    [void](Assert-ExactPackageTree $target $Label)
    Assert-VerifiedDirectoryIdentity $Label $target $ExpectedIdentity
    Assert-VerifiedDirectoryIdentity 'Install parent' $ExpectedParent $ExpectedParentIdentity
    if (-not [string]::IsNullOrWhiteSpace($PredeleteBarrierEnvironmentVariable)) {
        Invoke-TestBarrier `
            $ExpectedParent $ExpectedParentIdentity $TestContext `
            $PredeleteBarrierEnvironmentVariable "$Label pre-delete manifest barrier"
    }
    if ($null -eq $ExpectedManifest) {
        throw ([KeeperActivationIdentityException]::new(
            "$Label has no captured authenticated manifest; preserving the directory"))
    }
    $quarantine = Assert-DirectChild `
        "$Label cleanup quarantine" $ExpectedParent `
        ([IO.Path]::Combine($ExpectedParent, ".project-design-keeper.cleanup-$([guid]::NewGuid().ToString('N'))"))
    try {
        $captured = Get-PackageCleanupInventory $target "$Label immediately before quarantine"
        Assert-SameManifest "$Label content changed before cleanup" $ExpectedManifest $captured.Package.Manifest
        Assert-VerifiedDirectoryIdentity $Label $target $ExpectedIdentity
        Assert-VerifiedDirectoryIdentity 'Install parent' $ExpectedParent $ExpectedParentIdentity
        Assert-VerifiedRenameReady `
            $Label $target $ExpectedIdentity `
            "$Label cleanup quarantine" $quarantine $ExpectedParent $ExpectedParentIdentity
        Move-Item -LiteralPath $target -Destination $quarantine
        Assert-VerifiedRenameResult `
            $Label $target "$Label cleanup quarantine" $quarantine $ExpectedIdentity `
            $ExpectedParent $ExpectedParentIdentity
        $moved = Get-PackageCleanupInventory $quarantine "$Label cleanup quarantine"
        Assert-SameCleanupInventory "$Label cleanup quarantine" $captured $moved
        if (-not [string]::IsNullOrWhiteSpace($PostAuthenticationBarrierEnvironmentVariable)) {
            Invoke-TestBarrier `
                $ExpectedParent $ExpectedParentIdentity $TestContext `
                $PostAuthenticationBarrierEnvironmentVariable "$Label post-authentication cleanup barrier"
        }
        if (Test-Path -LiteralPath $target) {
            throw ([KeeperActivationIdentityException]::new(
                "$Label original path was replaced after quarantine; preserving both paths"))
        }
        $settled = Get-PackageCleanupInventory $quarantine "$Label cleanup quarantine after authentication"
        Assert-SameCleanupInventory "$Label cleanup quarantine after authentication" $captured $settled
        $fileLeases = [ordered]@{}
        $directoryLeases = [ordered]@{}
        try {
            foreach ($file in $ExactPackageFiles) {
                $path = [IO.Path]::GetFullPath([IO.Path]::Combine($quarantine, $file.Replace('/', [IO.Path]::DirectorySeparatorChar)))
                $maximumBytes = if ($file.EndsWith('.json', [StringComparison]::OrdinalIgnoreCase)) {
                    [long]$PackageMaximumJsonBytes
                } else {
                    [long]$PackageMaximumFileBytes
                }
                $expectedFile = $captured.Package.Files[$file]
                $fileLeases[$file] = [KeeperActivationNative]::OpenVerifiedFileDeleteLease(
                    $path,
                    $maximumBytes,
                    $expectedFile.Identity,
                    [long]$expectedFile.Length,
                    $expectedFile.Sha256)
            }

            $directories = @(Get-ExpectedDirectories) | Sort-Object {
                -($_.Split('/').Count)
            }, { $_ }
            foreach ($directory in $directories) {
                $path = [IO.Path]::GetFullPath([IO.Path]::Combine($quarantine, $directory.Replace('/', [IO.Path]::DirectorySeparatorChar)))
                $directoryLeases[$directory] = [KeeperActivationNative]::OpenVerifiedDirectoryDeleteLease(
                    $path,
                    $captured.Directories[$directory])
            }
            $directoryLeases['.'] = [KeeperActivationNative]::OpenVerifiedDirectoryDeleteLease(
                $quarantine,
                $ExpectedIdentity)

            if (-not [string]::IsNullOrWhiteSpace($HandleDeleteBarrierEnvironmentVariable)) {
                Invoke-TestBarrier `
                    $ExpectedParent $ExpectedParentIdentity $TestContext `
                    $HandleDeleteBarrierEnvironmentVariable "$Label final handle-delete barrier"
            }
            if (Test-Path -LiteralPath $target) {
                throw ([KeeperActivationIdentityException]::new(
                    "$Label original path was replaced before handle-bound deletion; preserving both paths"))
            }
            [void](Assert-ExactPackageTree $quarantine "$Label final handle-bound cleanup inventory")
            Assert-VerifiedDirectoryIdentity 'Install parent' $ExpectedParent $ExpectedParentIdentity

            foreach ($file in $ExactPackageFiles) {
                [KeeperActivationNative]::DeleteVerifiedLease($fileLeases[$file])
                $fileLeases[$file].Dispose()
                $fileLeases[$file] = $null
            }
            foreach ($directory in $directories) {
                $path = [IO.Path]::GetFullPath([IO.Path]::Combine($quarantine, $directory.Replace('/', [IO.Path]::DirectorySeparatorChar)))
                Assert-DirectoryEmptyBounded $path "$Label cleanup directory $directory"
                [KeeperActivationNative]::DeleteVerifiedLease($directoryLeases[$directory])
                $directoryLeases[$directory].Dispose()
                $directoryLeases[$directory] = $null
            }
            Assert-DirectoryEmptyBounded $quarantine "$Label cleanup quarantine"
            [KeeperActivationNative]::DeleteVerifiedLease($directoryLeases['.'])
            $directoryLeases['.'].Dispose()
            $directoryLeases['.'] = $null
        }
        finally {
            foreach ($lease in @($fileLeases.Values) + @($directoryLeases.Values)) {
                if ($null -ne $lease) { $lease.Dispose() }
            }
        }
        Assert-VerifiedDirectoryIdentity 'Install parent' $ExpectedParent $ExpectedParentIdentity
        if ((Test-Path -LiteralPath $quarantine) -or (Test-Path -LiteralPath $target)) {
            throw ([KeeperActivationIdentityException]::new(
                "$Label cleanup left an ambiguous path; preserving remaining evidence"))
        }
    }
    catch {
        if ($_.Exception -is [KeeperActivationIdentityException]) { throw }
        $evidencePath = if (Test-Path -LiteralPath $quarantine) { $quarantine } else { $target }
        throw ([KeeperActivationIdentityException]::new(
            "$Label cleanup could not be authenticated; preserving evidence at $evidencePath. $($_.Exception.Message)",
            $_.Exception))
    }
}

function Get-TestContext {
    param([string]$InstallParent)
    $testHookNames = @(
        'KEEPER_ACTIVATION_PROCESS_FIXTURE',
        'KEEPER_ACTIVATION_TEST_FAULT',
        'KEEPER_ACTIVATION_TEST_PRELOCK_BARRIER',
        'KEEPER_ACTIVATION_TEST_BARRIER',
        'KEEPER_ACTIVATION_TEST_SECOND_PRECHECK_BARRIER',
        'KEEPER_ACTIVATION_TEST_SECOND_RENAME_BARRIER',
        'KEEPER_ACTIVATION_TEST_SECOND_MOVE_FAILURE_BARRIER',
        'KEEPER_ACTIVATION_TEST_FINAL_LIVENESS_BARRIER',
        'KEEPER_ACTIVATION_TEST_ROLLBACK_BARRIER',
        'KEEPER_ACTIVATION_TEST_CLEANUP_BARRIER',
        'KEEPER_ACTIVATION_TEST_FINAL_SUCCESS_BARRIER',
        'KEEPER_ACTIVATION_TEST_OLD_BACKUP_PREDELETE_BARRIER',
        'KEEPER_ACTIVATION_TEST_STAGING_PREDELETE_BARRIER',
        'KEEPER_ACTIVATION_TEST_OLD_BACKUP_POSTAUTH_BARRIER',
        'KEEPER_ACTIVATION_TEST_STAGING_POSTAUTH_BARRIER',
        'KEEPER_ACTIVATION_TEST_OLD_BACKUP_HANDLE_DELETE_BARRIER',
        'KEEPER_ACTIVATION_TEST_STAGING_HANDLE_DELETE_BARRIER',
        'KEEPER_ACTIVATION_TEST_STAGING_COPY_BARRIER',
        'KEEPER_ACTIVATION_TEST_DEADLINE_MS',
        'KEEPER_ACTIVATION_TEST_EXPIRE_AFTER_FIRST_RENAME',
        'KEEPER_ACTIVATION_TEST_ORDINARY_FAILURE_AFTER_FIRST_RENAME',
        'KEEPER_ACTIVATION_TEST_SMOKE_TIMEOUT_MS'
    )
    $testHookRequested = $false
    foreach ($name in $testHookNames) {
        if (-not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name))) {
            $testHookRequested = $true
            break
        }
    }
    if ([string]::IsNullOrWhiteSpace($env:KEEPER_ACTIVATION_TEST_ROOT)) {
        if ($testHookRequested) {
            throw "Activation test hooks require KEEPER_ACTIVATION_TEST_ROOT and NODE_ENV=test"
        }
        return $false
    }
    if ($env:NODE_ENV -cne 'test') {
        throw "Activation test hooks require NODE_ENV=test"
    }
    Assert-FullyQualifiedPath 'KEEPER_ACTIVATION_TEST_ROOT' $env:KEEPER_ACTIVATION_TEST_ROOT
    $testRoot = [IO.Path]::GetFullPath($env:KEEPER_ACTIVATION_TEST_ROOT).TrimEnd([char[]]@('\', '/'))
    if (-not (Test-SamePath $InstallParent $testRoot)) {
        throw "KEEPER_ACTIVATION_TEST_ROOT must equal the verified install parent"
    }
    $systemTemporary = Get-ValidatedDirectory 'System temporary root' ([IO.Path]::GetTempPath())
    [void](Assert-DirectChild 'Activation test root' $systemTemporary $testRoot)
    return $true
}

function Get-ActivationProcesses {
    param([string]$InstallParent, [bool]$TestContext)
    Assert-ActivationDeadline 'activation process inventory'
    if (-not [string]::IsNullOrWhiteSpace($env:KEEPER_ACTIVATION_PROCESS_FIXTURE)) {
        if (-not $TestContext) { throw "A process fixture requires KEEPER_ACTIVATION_TEST_ROOT" }
        Assert-FullyQualifiedPath 'KEEPER_ACTIVATION_PROCESS_FIXTURE' $env:KEEPER_ACTIVATION_PROCESS_FIXTURE
        $fixture = Assert-DirectChild 'Process fixture' $InstallParent $env:KEEPER_ACTIVATION_PROCESS_FIXTURE
        Assert-NoReparsePathComponents 'Process fixture' $fixture
        $item = Get-Item -LiteralPath $fixture -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or -not ($item -is [IO.FileInfo]) -or
            [KeeperActivationNative]::GetLinkCount($fixture) -ne 1) {
            throw "Process fixture must be a single-link regular file"
        }
        try {
            $fixtureEvidence = [KeeperActivationNative]::ReadBoundedSingleLinkFile(
                $fixture,
                [long]$ProcessFixtureMaximumBytes)
            $processes = @([Text.Encoding]::UTF8.GetString($fixtureEvidence.Bytes) | ConvertFrom-Json)
        }
        catch {
            throw "Process fixture exceeds its bounded byte limit or is invalid JSON: $($_.Exception.Message)"
        }
        if ($processes.Count -gt $ActivationMaximumProcessRecords) {
            throw "Process fixture exceeds the bounded record limit of $ActivationMaximumProcessRecords"
        }
        Assert-ActivationDeadline 'activation process fixture'
        return $processes
    }
    $operationTimeoutSeconds = [int][Math]::Max(
        1,
        [Math]::Min(10, [Math]::Ceiling((Get-ActivationOperationTimeoutMs 'live process query' 10000) / 1000.0)))
    $processes = @(Get-CimInstance `
        -ClassName Win32_Process `
        -Filter "Name = 'node.exe' OR Name = 'Codex.exe'" `
        -OperationTimeoutSec $operationTimeoutSeconds |
        Select-Object Name, ProcessId, ParentProcessId, CommandLine |
        Select-Object -First ($ActivationMaximumProcessRecords + 1))
    if ($processes.Count -gt $ActivationMaximumProcessRecords) {
        throw "Live activation process inventory exceeds the bounded record limit of $ActivationMaximumProcessRecords"
    }
    Assert-ActivationDeadline 'live process query'
    return $processes
}

function Get-LiveInstalledMcpPids {
    param([string]$ActiveRoot, [object[]]$Processes)
    $byPid = @{}
    foreach ($process in $Processes) {
        if ($null -ne $process.ProcessId) { $byPid[[int64]$process.ProcessId] = $process }
    }
    $expectedRuntime = [IO.Path]::GetFullPath([IO.Path]::Combine($ActiveRoot, 'dist', 'index.js'))
    $matches = New-Object 'System.Collections.Generic.List[long]'
    foreach ($process in $Processes) {
        Assert-ActivationDeadline 'live process inspection'
        if (-not [string]::Equals([string]$process.Name, 'node.exe', [StringComparison]::OrdinalIgnoreCase)) { continue }
        $parent = $byPid[[int64]$process.ParentProcessId]
        if ($null -eq $parent -or -not [string]::Equals([string]$parent.Name, 'Codex.exe', [StringComparison]::OrdinalIgnoreCase)) { continue }
        if ([string]::IsNullOrWhiteSpace([string]$process.CommandLine)) {
            throw "Cannot safely inspect the command line for direct Codex child PID $($process.ProcessId). Close that Codex task or restart Codex before activation."
        }
        $arguments = [KeeperActivationNative]::ParseCommandLine([string]$process.CommandLine)
        if ($arguments.Count -ne 2) { continue }
        $nodeName = [IO.Path]::GetFileName($arguments[0])
        if (-not ([string]::Equals($nodeName, 'node.exe', [StringComparison]::OrdinalIgnoreCase) -or
            [string]::Equals($nodeName, 'node', [StringComparison]::OrdinalIgnoreCase))) { continue }
        if ([IO.Path]::IsPathRooted($arguments[1])) {
            $runtime = [IO.Path]::GetFullPath($arguments[1])
        }
        else {
            try {
                $workingDirectoryProperty = $process.PSObject.Properties['WorkingDirectory']
                $workingDirectory = if ($null -ne $workingDirectoryProperty) {
                    [string]$workingDirectoryProperty.Value
                }
                else {
                    [KeeperActivationNative]::GetProcessCurrentDirectory([int64]$process.ProcessId)
                }
                Assert-FullyQualifiedPath "Direct Codex child PID $($process.ProcessId) working directory" $workingDirectory
            }
            catch {
                throw "Cannot safely determine the working directory for direct Codex child PID $($process.ProcessId). Close that Codex task or restart Codex before activation. $($_.Exception.Message)"
            }
            $runtime = [IO.Path]::GetFullPath([IO.Path]::Combine($workingDirectory, $arguments[1]))
        }
        if (Test-SamePath $expectedRuntime $runtime) { $matches.Add([int64]$process.ProcessId) }
    }
    return @($matches) | Sort-Object
}

function Invoke-TestFault {
    param([string]$Name, [bool]$TestContext)
    if (-not [string]::IsNullOrWhiteSpace($env:KEEPER_ACTIVATION_TEST_FAULT)) {
        if (-not $TestContext) { throw "Activation fault injection requires KEEPER_ACTIVATION_TEST_ROOT" }
        if ($env:KEEPER_ACTIVATION_TEST_FAULT -eq $Name) {
            throw "Injected activation $Name failure"
        }
    }
}

function Enter-ActivationLock {
    param([string]$ActiveRoot, [string]$InstallParent, [string]$ExpectedParentIdentity)
    $leaf = [IO.Path]::GetFileName($ActiveRoot)
    $lockPath = Assert-DirectChild 'Activation lock' $InstallParent ([IO.Path]::Combine($InstallParent, ".$leaf.project-design-keeper.activation.lock"))
    Assert-NoReparsePathComponents 'Activation lock' $lockPath
    Assert-VerifiedDirectoryIdentity 'Install parent' $InstallParent $ExpectedParentIdentity
    try {
        if (Test-Path -LiteralPath $lockPath) {
            $item = Get-Item -LiteralPath $lockPath -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                -not ($item -is [IO.FileInfo]) -or [KeeperActivationNative]::GetLinkCount($lockPath) -ne 1) {
                throw "Activation lock must be a single-link regular file: $lockPath"
            }
        }
        $stream = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    }
    catch [IO.IOException] {
        throw "Activation is already in progress or its cross-session lock cannot be acquired for $ActiveRoot. Wait for that activation to finish before retrying. $($_.Exception.Message)"
    }
    if ($stream.Length -ne 0) {
        $stream.Dispose()
        throw "Activation lock contains unexpected data and was not trusted: $lockPath"
    }
    return $stream
}

function Write-TestMarkerCreateNew {
    param(
        [string]$Label,
        [string]$Marker,
        [string]$Container,
        [string]$ExpectedContainerIdentity
    )
    [void](Assert-DirectChild $Label $Container $Marker)
    Assert-NoReparsePathComponents $Label $Marker
    Assert-VerifiedDirectoryIdentity $Label.Replace(' entered marker', '') $Container $ExpectedContainerIdentity
    try {
        $stream = [IO.File]::Open(
            $Marker,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::Read)
    }
    catch [IO.IOException] {
        throw "$Label already exists or could not be created without clobbering an existing marker. $($_.Exception.Message)"
    }
    try {
        $bytes = [Text.Encoding]::ASCII.GetBytes([string][Diagnostics.Process]::GetCurrentProcess().Id)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
    $item = Get-Item -LiteralPath $Marker -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        -not ($item -is [IO.FileInfo]) -or [KeeperActivationNative]::GetLinkCount($Marker) -ne 1) {
        throw "$Label must be a single-link regular file"
    }
    Assert-VerifiedDirectoryIdentity $Label.Replace(' entered marker', '') $Container $ExpectedContainerIdentity
}

function Assert-TestReleaseMarker {
    param(
        [string]$Label,
        [string]$Marker,
        [string]$Container,
        [string]$ExpectedContainerIdentity
    )
    [void](Assert-DirectChild "$Label release marker" $Container $Marker)
    Assert-VerifiedDirectoryIdentity $Label $Container $ExpectedContainerIdentity
    Assert-NoReparsePathComponents "$Label release marker" $Marker
    $item = Get-Item -LiteralPath $Marker -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        -not ($item -is [IO.FileInfo]) -or [KeeperActivationNative]::GetLinkCount($Marker) -ne 1) {
        throw "$Label release marker must be a single-link regular file"
    }
    Assert-VerifiedDirectoryIdentity $Label $Container $ExpectedContainerIdentity
}

function Invoke-TestPrelockBarrier {
    param([string]$InstallParent, [string]$ExpectedParentIdentity, [bool]$TestContext)
    if ([string]::IsNullOrWhiteSpace($env:KEEPER_ACTIVATION_TEST_PRELOCK_BARRIER)) { return }
    if (-not $TestContext) { throw "Activation pre-lock barrier requires KEEPER_ACTIVATION_TEST_ROOT" }
    Assert-FullyQualifiedPath 'Activation pre-lock barrier' $env:KEEPER_ACTIVATION_TEST_PRELOCK_BARRIER
    $controlParent = Get-ValidatedDirectory 'Activation pre-lock barrier parent' ([IO.Path]::GetDirectoryName($InstallParent))
    [void](Assert-DirectChild 'Install parent' $controlParent $InstallParent)
    $controlParentIdentity = Get-VerifiedDirectoryIdentity 'Activation pre-lock barrier parent' $controlParent
    $barrier = [IO.Path]::GetFullPath($env:KEEPER_ACTIVATION_TEST_PRELOCK_BARRIER)
    [void](Assert-DirectChild 'Activation pre-lock barrier' $controlParent $barrier)
    if ([IO.Path]::GetFileName($barrier) -notmatch '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') {
        throw "Activation pre-lock barrier control path must end in a random UUID"
    }
    if (Test-Path -LiteralPath $barrier) {
        throw "Activation pre-lock barrier control directory is pre-existing; refusing test writes"
    }
    Assert-VerifiedDirectoryIdentity 'Activation pre-lock barrier parent' $controlParent $controlParentIdentity
    [KeeperActivationNative]::CreateDirectoryExclusive($barrier)
    $barrierLease = $null
    try {
        $barrierLease = [KeeperActivationNative]::OpenDirectoryMutationLease($barrier)
        $barrierIdentity = Get-VerifiedDirectoryIdentity 'Activation pre-lock barrier' $barrier
        Assert-VerifiedDirectoryIdentity 'Install parent' $InstallParent $ExpectedParentIdentity
        $entered = Assert-DirectChild 'Activation pre-lock barrier entered marker' $barrier ([IO.Path]::Combine($barrier, 'entered'))
        $release = Assert-DirectChild 'Activation pre-lock barrier release marker' $barrier ([IO.Path]::Combine($barrier, 'release'))
        if ((Test-Path -LiteralPath $entered) -or (Test-Path -LiteralPath $release)) {
            throw "Activation pre-lock barrier markers must not already exist"
        }
        Assert-VerifiedDirectoryIdentity 'Activation pre-lock barrier' $barrier $barrierIdentity
        Assert-VerifiedDirectoryIdentity 'Activation pre-lock barrier parent' $controlParent $controlParentIdentity
        Write-TestMarkerCreateNew `
            'Activation pre-lock barrier entered marker' $entered $barrier $barrierIdentity
        $localDeadline = $script:ActivationClock.ElapsedMilliseconds + 30000
        while (-not (Test-Path -LiteralPath $release)) {
            Assert-ActivationDeadline 'activation pre-lock test barrier'
            if ($script:ActivationClock.ElapsedMilliseconds -ge $localDeadline) {
                throw "Timed out waiting for the activation pre-lock test barrier"
            }
            Assert-VerifiedDirectoryIdentity 'Activation pre-lock barrier' $barrier $barrierIdentity
            Assert-VerifiedDirectoryIdentity 'Activation pre-lock barrier parent' $controlParent $controlParentIdentity
            Start-Sleep -Milliseconds 25
        }
        Assert-TestReleaseMarker 'Activation pre-lock barrier' $release $barrier $barrierIdentity
    }
    finally {
        if ($null -ne $barrierLease) { $barrierLease.Dispose() }
    }
}

function Invoke-TestBarrier {
    param(
        [string]$InstallParent,
        [string]$ExpectedParentIdentity,
        [bool]$TestContext,
        [string]$EnvironmentVariable = 'KEEPER_ACTIVATION_TEST_BARRIER',
        [string]$Label = 'Activation barrier'
    )
    $barrierValue = [Environment]::GetEnvironmentVariable($EnvironmentVariable)
    if ([string]::IsNullOrWhiteSpace($barrierValue)) { return }
    if (-not $TestContext) { throw "$Label requires KEEPER_ACTIVATION_TEST_ROOT" }
    Assert-FullyQualifiedPath $Label $barrierValue
    $barrier = [IO.Path]::GetFullPath($barrierValue)
    [void](Assert-DirectChild $Label $InstallParent $barrier)
    if ([IO.Path]::GetFileName($barrier) -notmatch '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') {
        throw "$Label control path must end in a random UUID"
    }
    if (Test-Path -LiteralPath $barrier) {
        throw "$Label control directory is pre-existing; refusing test writes"
    }
    Assert-VerifiedDirectoryIdentity 'Install parent' $InstallParent $ExpectedParentIdentity
    [KeeperActivationNative]::CreateDirectoryExclusive($barrier)
    $barrierLease = $null
    try {
        $barrierLease = [KeeperActivationNative]::OpenDirectoryMutationLease($barrier)
        $barrierIdentity = Get-VerifiedDirectoryIdentity $Label $barrier
        Assert-VerifiedDirectoryIdentity 'Install parent' $InstallParent $ExpectedParentIdentity
        $entered = Assert-DirectChild "$Label entered marker" $barrier ([IO.Path]::Combine($barrier, 'entered'))
        $release = Assert-DirectChild "$Label release marker" $barrier ([IO.Path]::Combine($barrier, 'release'))
        if ((Test-Path -LiteralPath $entered) -or (Test-Path -LiteralPath $release)) {
            throw "$Label markers must not already exist"
        }
        Assert-VerifiedDirectoryIdentity $Label $barrier $barrierIdentity
        Write-TestMarkerCreateNew "$Label entered marker" $entered $barrier $barrierIdentity
        $localDeadline = $script:ActivationClock.ElapsedMilliseconds + 30000
        while (-not (Test-Path -LiteralPath $release)) {
            Assert-ActivationDeadline $Label
            if ($script:ActivationClock.ElapsedMilliseconds -ge $localDeadline) {
                throw "Timed out waiting for $Label"
            }
            Assert-VerifiedDirectoryIdentity $Label $barrier $barrierIdentity
            Assert-VerifiedDirectoryIdentity 'Install parent' $InstallParent $ExpectedParentIdentity
            Start-Sleep -Milliseconds 25
        }
        Assert-TestReleaseMarker $Label $release $barrier $barrierIdentity
        Assert-VerifiedDirectoryIdentity $Label $barrier $barrierIdentity
        Assert-VerifiedDirectoryIdentity 'Install parent' $InstallParent $ExpectedParentIdentity
    }
    finally {
        if ($null -ne $barrierLease) { $barrierLease.Dispose() }
    }
}

function Assert-NoLiveInstalledMcp {
    param([string]$ActiveRoot, [string]$InstallParent, [bool]$TestContext)
    $pids = @(Get-LiveInstalledMcpPids $ActiveRoot (Get-ActivationProcesses $InstallParent $TestContext))
    if ($pids.Count -gt 0) {
        throw "Installed MCP is in use by a live direct Codex child PID $($pids -join ', '). Close the Codex task or restart Codex before activation."
    }
}

function ConvertTo-QuotedProcessArgument {
    param([string]$Label, [string]$Value)
    if ($Value.Contains('"') -or $Value.EndsWith('\', [StringComparison]::Ordinal)) {
        throw "$Label cannot be represented safely on the Windows process command line"
    }
    return '"' + $Value + '"'
}

function Invoke-BoundedInstalledSmoke {
    param([string]$Script, [string]$InstallRoot, [string]$SmokeProject)
    $maximumWait = 120000
    if ($null -ne $script:ActivationSmokeTimeoutOverrideMs) {
        $maximumWait = [int]$script:ActivationSmokeTimeoutOverrideMs
    }
    $waitMilliseconds = Get-ActivationOperationTimeoutMs 'installed smoke child' $maximumWait
    $arguments = @(
        (ConvertTo-QuotedProcessArgument 'Installed smoke script' $Script),
        (ConvertTo-QuotedProcessArgument 'Installed smoke install root' $InstallRoot),
        (ConvertTo-QuotedProcessArgument 'Installed smoke project root' $SmokeProject)
    ) -join ' '
    $nodeCommand = @(Get-Command node -CommandType Application -ErrorAction Stop)[0]
    $nodeExecutable = [IO.Path]::GetFullPath($nodeCommand.Source)
    $nativeResult = $null
    try {
        $nativeResult = [KeeperActivationNative]::RunBoundedOwnedProcess(
            $nodeExecutable,
            $arguments,
            $waitMilliseconds,
            5000,
            1024 * 1024)
    }
    catch {
        throw ([KeeperActivationIdentityException]::new(
            "Installed smoke owned process tree could not reach a confirmed zero-process state; preserving active and backup evidence. $($_.Exception.Message)",
            $_.Exception))
    }
    if ($nativeResult.TimedOut) {
        $script:ActivationForwardDeadlineExpired = $true
        throw ([KeeperActivationDeadlineException]::new(
            "Installed smoke exceeded the bounded activation deadline; owned child tree rooted at PID $($nativeResult.RootPid) reached ActiveProcesses=0 and exit was confirmed"))
    }
    if ($nativeResult.OutputLimitExceeded) {
        throw "Installed smoke exceeded the bounded aggregate output limit; owned child tree rooted at PID $($nativeResult.RootPid) reached ActiveProcesses=0 and exit was confirmed`n$($nativeResult.Output)"
    }
    return [pscustomobject]@{
        ExitCode = $nativeResult.ExitCode
        Output = $nativeResult.Output
    }
}

function Assert-EmptySmokeProject {
    param([string]$Path, [string]$ExpectedIdentity)
    Assert-VerifiedDirectoryIdentity 'Smoke project root' $Path $ExpectedIdentity
    $entries = [KeeperActivationNative]::EnumerateImmediateChildrenBounded(
        $Path,
        1,
        (Get-ActivationOperationTimeoutMs 'smoke project inventory'))
    Assert-VerifiedDirectoryIdentity 'Smoke project root' $Path $ExpectedIdentity
    if ($entries.Count -ne 0) {
        throw "Smoke project root must be an empty disposable directory; refusing to modify a nonempty project"
    }
}

$resolvedPackage = Get-ValidatedDirectory 'Package root' $PackageRoot
$resolvedInstall = Get-ValidatedDirectory 'Install root' $InstallRoot
$resolvedSmoke = Get-ValidatedDirectory 'Smoke project root' $SmokeProject
$packageParent = Get-ValidatedDirectory 'Package parent' ([IO.Path]::GetDirectoryName($resolvedPackage))
$installParent = Get-ValidatedDirectory 'Install parent' ([IO.Path]::GetDirectoryName($resolvedInstall))
$smokeParent = Get-ValidatedDirectory 'Smoke project parent' ([IO.Path]::GetDirectoryName($resolvedSmoke))
[void](Assert-DirectChild 'Package root' $packageParent $resolvedPackage)
[void](Assert-DirectChild 'Install root' $installParent $resolvedInstall)
[void](Assert-DirectChild 'Smoke project root' $smokeParent $resolvedSmoke)
if ((Test-SamePath $resolvedPackage $resolvedInstall) -or (Test-SamePath $resolvedInstall $resolvedSmoke) -or
    (Test-SamePath $resolvedPackage $resolvedSmoke)) {
    throw "Package, install, and smoke project roots must be distinct"
}

$packageParentIdentity = Get-VerifiedDirectoryIdentity 'Package parent' $packageParent
$installParentIdentity = Get-VerifiedDirectoryIdentity 'Install parent' $installParent
$smokeParentIdentity = Get-VerifiedDirectoryIdentity 'Smoke project parent' $smokeParent
if (($packageParentIdentity -ceq $installParentIdentity) -or
    ($packageParentIdentity -ceq $smokeParentIdentity) -or
    ($installParentIdentity -ceq $smokeParentIdentity)) {
    throw 'Package root parent, install root parent, and smoke project root parent must be verified disjoint directories'
}
$activeIdentity = Get-VerifiedDirectoryIdentity 'Install root' $resolvedInstall
$smokeIdentity = Get-VerifiedDirectoryIdentity 'Smoke project root' $resolvedSmoke
Assert-EmptySmokeProject $resolvedSmoke $smokeIdentity
$testContext = Get-TestContext $installParent
if (-not [string]::IsNullOrWhiteSpace($env:KEEPER_ACTIVATION_TEST_DEADLINE_MS)) {
    if (-not $testContext) { throw 'Activation deadline test seam requires the strict temporary test context' }
    [long]$deadlineOverride = 0
    if (-not [long]::TryParse(
        $env:KEEPER_ACTIVATION_TEST_DEADLINE_MS,
        [Globalization.NumberStyles]::None,
        [Globalization.CultureInfo]::InvariantCulture,
        [ref]$deadlineOverride) -or
        $deadlineOverride -lt 1 -or $deadlineOverride -gt 5000) {
        throw 'Activation deadline test seam must be an integer from 1 through 5000 milliseconds'
    }
    $script:ActivationDeadlineAtMs = $script:ActivationClock.ElapsedMilliseconds + $deadlineOverride
    Start-Sleep -Milliseconds ([int][Math]::Min(10, $deadlineOverride + 1))
}
if (-not [string]::IsNullOrWhiteSpace($env:KEEPER_ACTIVATION_TEST_SMOKE_TIMEOUT_MS)) {
    if (-not $testContext) { throw 'Installed smoke timeout test seam requires the strict temporary test context' }
    [int]$smokeTimeoutOverride = 0
    if (-not [int]::TryParse(
        $env:KEEPER_ACTIVATION_TEST_SMOKE_TIMEOUT_MS,
        [Globalization.NumberStyles]::None,
        [Globalization.CultureInfo]::InvariantCulture,
        [ref]$smokeTimeoutOverride) -or
        $smokeTimeoutOverride -lt 1 -or $smokeTimeoutOverride -gt 5000) {
        throw 'Installed smoke timeout test seam must be an integer from 1 through 5000 milliseconds'
    }
    $script:ActivationSmokeTimeoutOverrideMs = $smokeTimeoutOverride
}
Assert-ActivationDeadline 'validated activation inputs'
Invoke-TestPrelockBarrier $installParent $installParentIdentity $testContext
Assert-VerifiedDirectoryIdentity 'Install parent' $installParent $installParentIdentity
Assert-VerifiedDirectoryIdentity 'Install root' $resolvedInstall $activeIdentity
Assert-VerifiedDirectoryIdentity 'Smoke project parent' $smokeParent $smokeParentIdentity
Assert-EmptySmokeProject $resolvedSmoke $smokeIdentity

$activationLock = $null
try {
$activationLock = Enter-ActivationLock $resolvedInstall $installParent $installParentIdentity
Assert-VerifiedDirectoryIdentity 'Install parent' $installParent $installParentIdentity
Assert-VerifiedDirectoryIdentity 'Install root' $resolvedInstall $activeIdentity

$packageManifestBefore = Get-PackageManifest $resolvedPackage 'Package root'
$activeManifest = Get-PackageManifest $resolvedInstall 'Install root'
Assert-VerifiedDirectoryIdentity 'Install root' $resolvedInstall $activeIdentity
Assert-VerifiedDirectoryIdentity 'Install parent' $installParent $installParentIdentity
Assert-NoLiveInstalledMcp $resolvedInstall $installParent $testContext

$installLeaf = [IO.Path]::GetFileName($resolvedInstall)
$reservedBackupPrefix = "$installLeaf.backup-"
foreach ($explicitInput in @(
    [pscustomobject]@{ Label = 'Package root'; Path = $resolvedPackage; Parent = $packageParent },
    [pscustomobject]@{ Label = 'Smoke project root'; Path = $resolvedSmoke; Parent = $smokeParent }
)) {
    if ((Test-SamePath $explicitInput.Parent $installParent) -and
        [IO.Path]::GetFileName($explicitInput.Path).StartsWith($reservedBackupPrefix, [StringComparison]::Ordinal)) {
        throw "$($explicitInput.Label) uses the reserved activation-backup name prefix $reservedBackupPrefix and cannot share the install parent"
    }
}
$timestamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ', [Globalization.CultureInfo]::InvariantCulture)
$staging = Assert-DirectChild 'Staging directory' $installParent ([IO.Path]::Combine($installParent, "$installLeaf.staging-$([guid]::NewGuid().ToString('N'))"))
$backup = Assert-DirectChild 'Backup directory' $installParent ([IO.Path]::Combine($installParent, "$installLeaf.backup-$timestamp-$([guid]::NewGuid().ToString('N'))"))
$failed = Assert-DirectChild 'Failed-package evidence directory' $installParent ([IO.Path]::Combine($installParent, "$installLeaf.failed-$timestamp-$([guid]::NewGuid().ToString('N'))"))
foreach ($target in @($staging, $backup, $failed)) {
    if (Test-Path -LiteralPath $target) { throw "Random activation path already exists: $target" }
}

$oldBackups = @(Get-BoundedOldBackupPaths $installParent "$installLeaf.backup-")
$oldBackupRecords = New-Object 'System.Collections.Generic.List[object]'
foreach ($oldBackup in $oldBackups) {
    Assert-ActivationDeadline 'existing backup authentication'
    $path = Assert-DirectChild 'Existing backup' $installParent $oldBackup
    if ((Test-SamePath $path $resolvedPackage) -or (Test-SamePath $path $resolvedSmoke)) {
        throw "Explicit package or smoke input was classified as an activation backup; refusing any cleanup: $path"
    }
    $identity = $null
    try {
        $identity = Get-VerifiedDirectoryIdentity 'Existing backup' $path
        $manifest = Get-PackageManifest $path 'Existing backup'
        Assert-VerifiedDirectoryIdentity 'Existing backup' $path $identity
        Assert-VerifiedDirectoryIdentity 'Install parent' $installParent $installParentIdentity
        $oldBackupRecords.Add([pscustomobject]@{ Path = $path; Identity = $identity; Manifest = $manifest })
    }
    catch {
        $classificationFailure = $_.Exception
        if (-not (Test-ActivationPackageShapeException $classificationFailure)) { throw }
        Assert-ActivationDeadline 'existing legacy backup classification'
        Assert-VerifiedDirectoryIdentity 'Existing legacy backup' $path $identity
        Assert-VerifiedDirectoryIdentity 'Install parent' $installParent $installParentIdentity
        Write-Warning (
            "Preserving legacy or unrecognized activation backup without cleanup: $path. " +
            "Its package identity or exact shape is legacy rather than the current package: " +
            (Get-ActivationExceptionDetail $classificationFailure))
    }
}

$activeMoved = $false
$stagingMoved = $false
$failedEvidenceMoved = $false
$stagingIdentity = $null
$backupTrusted = $false
$preserveStagingEvidence = $false
$errors = New-Object 'System.Collections.Generic.List[string]'
try {
    $stagingIdentity = Copy-ExactPackage `
        $resolvedPackage $staging $installParent $installParentIdentity $testContext
    $packageManifestAfter = Get-PackageManifest $resolvedPackage 'Package root after staging'
    $stagingManifest = Get-PackageManifest $staging 'Staging directory'
    Assert-SameManifest 'Package changed while staging' $packageManifestBefore $packageManifestAfter
    Assert-SameManifest 'Staging manifest' $packageManifestBefore $stagingManifest
    Assert-VerifiedDirectoryIdentity 'Staging directory' $staging $stagingIdentity
    Assert-VerifiedDirectoryIdentity 'Install root' $resolvedInstall $activeIdentity
    Assert-VerifiedDirectoryIdentity 'Install parent' $installParent $installParentIdentity

    Invoke-TestBarrier $installParent $installParentIdentity $testContext
    Invoke-TestFault 'first-rename' $testContext
    Assert-VerifiedDirectoryIdentity 'Install parent' $installParent $installParentIdentity
    Assert-VerifiedDirectoryIdentity 'Install root' $resolvedInstall $activeIdentity
    $activeManifestBeforeRename = Get-PackageManifest $resolvedInstall 'Install root before rename'
    Assert-SameManifest 'Install root changed before rename' $activeManifest $activeManifestBeforeRename
    Assert-VerifiedDirectoryIdentity 'Install root' $resolvedInstall $activeIdentity
    try {
        Assert-VerifiedDirectoryIdentity 'Staging directory' $staging $stagingIdentity
        $stagingManifestBeforeRename = Get-PackageManifest $staging 'Staging directory before rename'
        Assert-SameManifest 'Staging directory changed before rename' $stagingManifest $stagingManifestBeforeRename
        Assert-VerifiedDirectoryIdentity 'Staging directory' $staging $stagingIdentity
    }
    catch {
        $preserveStagingEvidence = $true
        throw ([KeeperActivationCandidateException]::new(
            "Staging candidate identity or manifest changed before the first rename; preserving candidate evidence. $($_.Exception.Message)",
            $_.Exception))
    }
    Assert-VerifiedDirectoryIdentity 'Install parent' $installParent $installParentIdentity
    Invoke-TestBarrier `
        $installParent $installParentIdentity $testContext `
        'KEEPER_ACTIVATION_TEST_FINAL_LIVENESS_BARRIER' 'Activation final liveness barrier'
    Assert-NoLiveInstalledMcp $resolvedInstall $installParent $testContext
    Assert-VerifiedDirectoryIdentity 'Smoke project parent' $smokeParent $smokeParentIdentity
    Assert-EmptySmokeProject $resolvedSmoke $smokeIdentity
    Assert-VerifiedRenameReady `
        'Install root' $resolvedInstall $activeIdentity `
        'Backup directory' $backup $installParent $installParentIdentity
    try {
        Move-Item -LiteralPath $resolvedInstall -Destination $backup
    }
    catch {
        throw ([KeeperActivationIdentityException]::new(
            "Install root rename could not be completed safely; preserving all ambiguous paths. $($_.Exception.Message)",
            $_.Exception))
    }
    $activeMoved = $true
    if (-not [string]::IsNullOrWhiteSpace($env:KEEPER_ACTIVATION_TEST_EXPIRE_AFTER_FIRST_RENAME)) {
        if (-not $testContext -or $env:KEEPER_ACTIVATION_TEST_EXPIRE_AFTER_FIRST_RENAME -cne '1') {
            throw 'First-rename deadline test seam requires value 1 and the strict temporary test context'
        }
        $script:ActivationExpireAtNextDeadlineCheck = $true
    }
    Assert-VerifiedRenameResult `
        'Install root' $resolvedInstall 'Backup directory' $backup $activeIdentity `
        $installParent $installParentIdentity

    try {
        Assert-VerifiedDirectoryIdentity 'Backup directory' $backup $activeIdentity
        $backupManifestAfterFirstRename = Get-PackageManifest $backup 'Backup directory after first rename'
        Assert-SameManifest 'Backup directory changed during first rename' $activeManifest $backupManifestAfterFirstRename
        Assert-VerifiedDirectoryIdentity 'Backup directory' $backup $activeIdentity
        Assert-VerifiedDirectoryIdentity 'Install parent' $installParent $installParentIdentity
        $backupTrusted = $true
    }
    catch {
        if ($_.Exception -is [KeeperActivationIdentityException]) { throw }
        throw ([KeeperActivationIdentityException]::new(
            "Previous active backup manifest could not be trusted after the first rename; preserving all evidence. $($_.Exception.Message)",
            $_.Exception))
    }

    if (-not [string]::IsNullOrWhiteSpace($env:KEEPER_ACTIVATION_TEST_ORDINARY_FAILURE_AFTER_FIRST_RENAME)) {
        if (-not $testContext -or $env:KEEPER_ACTIVATION_TEST_ORDINARY_FAILURE_AFTER_FIRST_RENAME -cne '1') {
            throw 'Ordinary post-mutation failure test seam requires value 1 and the strict temporary test context'
        }
        $script:ActivationDeadlineAtMs = $script:ActivationClock.ElapsedMilliseconds
        throw 'Injected ordinary post-mutation failure at the forward deadline'
    }

    Invoke-TestFault 'second-rename' $testContext
    Invoke-TestBarrier `
        $installParent $installParentIdentity $testContext `
        'KEEPER_ACTIVATION_TEST_SECOND_PRECHECK_BARRIER' 'Activation second-precheck barrier'
    try {
        Assert-VerifiedDirectoryIdentity 'Install parent' $installParent $installParentIdentity
        Assert-VerifiedDirectoryIdentity 'Backup directory' $backup $activeIdentity
        $backupManifestBeforeSecondRename = Get-PackageManifest $backup 'Backup directory before second rename'
        Assert-SameManifest 'Backup directory changed before second rename' $activeManifest $backupManifestBeforeSecondRename
        Assert-VerifiedDirectoryIdentity 'Backup directory' $backup $activeIdentity
        Assert-VerifiedDirectoryIdentity 'Install parent' $installParent $installParentIdentity
    }
    catch {
        if ($_.Exception -is [KeeperActivationIdentityException]) { throw }
        throw ([KeeperActivationIdentityException]::new(
            "Previous active backup manifest could not be trusted before the second rename; preserving all evidence. $($_.Exception.Message)",
            $_.Exception))
    }
    try {
        Assert-VerifiedDirectoryIdentity 'Staging directory' $staging $stagingIdentity
        $stagingManifestBeforeSecondRename = Get-PackageManifest $staging 'Staging directory before second rename'
        Assert-SameManifest 'Staging directory changed before second rename' $stagingManifest $stagingManifestBeforeSecondRename
        Assert-VerifiedDirectoryIdentity 'Staging directory' $staging $stagingIdentity
    }
    catch {
        $preserveStagingEvidence = $true
        throw ([KeeperActivationCandidateException]::new(
            "Staging candidate identity or manifest changed before the second rename; preserving candidate evidence. $($_.Exception.Message)",
            $_.Exception))
    }
    Assert-VerifiedDirectoryIdentity 'Install parent' $installParent $installParentIdentity
    Invoke-TestBarrier `
        $installParent $installParentIdentity $testContext `
        'KEEPER_ACTIVATION_TEST_SECOND_RENAME_BARRIER' 'Activation second-rename barrier'
    Assert-VerifiedRenameReady `
        'Staging directory' $staging $stagingIdentity `
        'Install root' $resolvedInstall $installParent $installParentIdentity
    try {
        Move-Item -LiteralPath $staging -Destination $resolvedInstall
    }
    catch {
        $secondRenameFailure = $_.Exception
        Invoke-TestBarrier `
            $installParent $installParentIdentity $testContext `
            'KEEPER_ACTIVATION_TEST_SECOND_MOVE_FAILURE_BARRIER' 'Activation second Move-Item failure barrier'
        $secondRenameState = Resolve-SecondRenameFailureState `
            $staging $stagingIdentity $stagingManifestBeforeSecondRename `
            $resolvedInstall $backup $activeIdentity $activeManifest `
            $installParent $installParentIdentity
        $backupTrusted = $true
        if ($secondRenameState -eq 'AfterRenameTrusted') { $stagingMoved = $true }
        if ($secondRenameState -ne 'BeforeRenameTrusted' -and $secondRenameState -ne 'AfterRenameTrusted') {
            $preserveStagingEvidence = $true
        }
        throw ([KeeperActivationCandidateException]::new(
            "Staging directory rename failed in a recognizable $secondRenameState state; restoring the verified backup. $($secondRenameFailure.Message)",
            $secondRenameFailure))
    }
    $stagingMoved = $true
    Assert-VerifiedRenameResult `
        'Staging directory' $staging 'Install root' $resolvedInstall $stagingIdentity `
        $installParent $installParentIdentity
    try {
        $activatedManifest = Get-PackageManifest $resolvedInstall 'Activated install'
        Assert-SameManifest 'Activated install changed during the second rename' $stagingManifestBeforeSecondRename $activatedManifest
        Assert-VerifiedDirectoryIdentity 'Install root' $resolvedInstall $stagingIdentity
    }
    catch {
        if ($_.Exception -is [KeeperActivationIdentityException]) { throw }
        throw ([KeeperActivationCandidateException]::new(
            "Activated candidate manifest changed during the second rename; preserving failed-package evidence. $($_.Exception.Message)",
            $_.Exception))
    }
    try {
        Assert-VerifiedDirectoryIdentity 'Backup directory' $backup $activeIdentity
        $backupManifestAfterSecondRename = Get-PackageManifest $backup 'Backup directory after second rename'
        Assert-SameManifest 'Previous active backup changed during second rename' $activeManifest $backupManifestAfterSecondRename
        Assert-VerifiedDirectoryIdentity 'Backup directory' $backup $activeIdentity
        Assert-VerifiedDirectoryIdentity 'Install parent' $installParent $installParentIdentity
        $backupTrusted = $true
    }
    catch {
        if ($_.Exception -is [KeeperActivationIdentityException]) { throw }
        throw ([KeeperActivationIdentityException]::new(
            "Previous active backup manifest could not be trusted after the second rename; preserving all evidence. $($_.Exception.Message)",
            $_.Exception))
    }

    $smokeScript = [IO.Path]::GetFullPath([IO.Path]::Combine($PSScriptRoot, 'smoke-installed-plugin.mjs'))
    $smokeItem = Get-Item -LiteralPath $smokeScript -Force
    if (($smokeItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or -not ($smokeItem -is [IO.FileInfo])) {
        throw "Installed smoke script must be a regular file"
    }
    $smokeResult = Invoke-BoundedInstalledSmoke $smokeScript $resolvedInstall $resolvedSmoke
    Assert-ActivationDeadline 'installed smoke result handling'
    $smokeOutput = @($smokeResult.Output)
    if ($smokeResult.ExitCode -ne 0) {
        throw "Installed smoke failed with exit code $($smokeResult.ExitCode)`n$($smokeOutput -join [Environment]::NewLine)"
    }

    Assert-AuthenticatedInstallState `
        $resolvedInstall $stagingIdentity $stagingManifestBeforeSecondRename `
        $backup $activeIdentity $activeManifest `
        $installParent $installParentIdentity 'after installed smoke'

    Invoke-TestBarrier `
        $installParent $installParentIdentity $testContext `
        'KEEPER_ACTIVATION_TEST_CLEANUP_BARRIER' 'Activation success cleanup barrier'
    Assert-AuthenticatedInstallState `
        $resolvedInstall $stagingIdentity $stagingManifestBeforeSecondRename `
        $backup $activeIdentity $activeManifest `
        $installParent $installParentIdentity 'after the success cleanup barrier'
    foreach ($oldBackup in $oldBackupRecords) {
        Remove-VerifiedTree `
            'Superseded backup' $oldBackup.Path $installParent $oldBackup.Identity $installParentIdentity `
            $oldBackup.Manifest $testContext 'KEEPER_ACTIVATION_TEST_OLD_BACKUP_PREDELETE_BARRIER' `
            'KEEPER_ACTIVATION_TEST_OLD_BACKUP_POSTAUTH_BARRIER' `
            'KEEPER_ACTIVATION_TEST_OLD_BACKUP_HANDLE_DELETE_BARRIER'
    }
    Invoke-TestBarrier `
        $installParent $installParentIdentity $testContext `
        'KEEPER_ACTIVATION_TEST_FINAL_SUCCESS_BARRIER' 'Activation final-success barrier'
    Assert-AuthenticatedInstallState `
        $resolvedInstall $stagingIdentity $stagingManifestBeforeSecondRename `
        $backup $activeIdentity $activeManifest `
        $installParent $installParentIdentity 'immediately before success'
    Write-Output ($smokeOutput -join [Environment]::NewLine)
    Write-Output "Activated project-design-keeper; installed smoke passed. Backup: $backup. Open a new Codex task or restart the app before claiming the new runtime is active."
}
catch {
    $errors.Add($_.Exception.Message)
    $deadlineFailure = Test-ActivationDeadlineException $_.Exception
    $needsRecoveryDeadline = $activeMoved -or ($script:ActivationForwardDeadlineExpired -and $deadlineFailure)
    if ($needsRecoveryDeadline -and -not $script:ActivationRecoveryMode) {
        $script:ActivationRecoveryMode = $true
        $script:ActivationDeadlineAtMs = $script:ActivationClock.ElapsedMilliseconds + 30000
        if ($deadlineFailure) {
            $preserveStagingEvidence = $true
            $errors.Add('Forward activation deadline expired; switched to the independent bounded recovery deadline')
        }
        else {
            $errors.Add('Post-mutation failure occurred; switched to the independent bounded recovery deadline')
        }
    }
    $identityAmbiguous = ($_.Exception -is [KeeperActivationIdentityException]) -and -not $deadlineFailure
    if (-not $identityAmbiguous) {
        Invoke-TestBarrier `
            $installParent $installParentIdentity $testContext `
            'KEEPER_ACTIVATION_TEST_ROLLBACK_BARRIER' 'Activation rollback barrier'
    }
    if (-not $identityAmbiguous -and $activeMoved) {
        try {
            Assert-VerifiedDirectoryIdentity 'Install parent' $installParent $installParentIdentity
            Assert-VerifiedDirectoryIdentity 'Backup directory' $backup $activeIdentity
            $backupManifestBeforeRollback = Get-PackageManifest $backup 'Backup directory before rollback'
            Assert-SameManifest 'Previous active backup changed before rollback' $activeManifest $backupManifestBeforeRollback
            Assert-VerifiedDirectoryIdentity 'Backup directory' $backup $activeIdentity
            Assert-VerifiedDirectoryIdentity 'Install parent' $installParent $installParentIdentity
            $backupTrusted = $true
        }
        catch {
            $errors.Add("Previous active backup is not trusted for rollback: $($_.Exception.Message)")
            $backupTrusted = $false
            $identityAmbiguous = $true
        }
    }
    if (-not $identityAmbiguous -and $activeMoved -and -not $backupTrusted) {
        $errors.Add('Previous active backup trust was not established; rollback mutation was stopped')
        $identityAmbiguous = $true
    }
    if (-not $identityAmbiguous -and $stagingMoved) {
        try {
            Assert-NoLiveInstalledMcp $resolvedInstall $installParent $testContext
        }
        catch {
            $errors.Add("Rollback cannot move the activated candidate because its MCP liveness is live or inconclusive: $($_.Exception.Message)")
            $identityAmbiguous = $true
        }
    }
    if (-not $identityAmbiguous -and $stagingMoved) {
        if (-not (Test-Path -LiteralPath $resolvedInstall)) {
            $errors.Add('Activated install disappeared before failed-package evidence could be preserved')
            $identityAmbiguous = $true
        }
    }
    if (-not $identityAmbiguous -and $stagingMoved) {
        try {
            Assert-VerifiedRenameReady `
                'Activated install' $resolvedInstall $stagingIdentity `
                'Failed-package evidence directory' $failed $installParent $installParentIdentity
            try {
                Move-Item -LiteralPath $resolvedInstall -Destination $failed
            }
            catch {
                throw ([KeeperActivationIdentityException]::new(
                    "Activated install could not be moved to failed-package evidence safely; preserving all ambiguous paths. $($_.Exception.Message)",
                    $_.Exception))
            }
            $stagingMoved = $false
            $failedEvidenceMoved = $true
            Assert-VerifiedRenameResult `
                'Activated install' $resolvedInstall 'Failed-package evidence directory' $failed $stagingIdentity `
                $installParent $installParentIdentity
        }
        catch {
            $errors.Add("Failed to preserve failed-package evidence: $($_.Exception.Message)")
            $identityAmbiguous = $true
        }
    }
    if (-not $identityAmbiguous -and $activeMoved) {
        if (-not (Test-Path -LiteralPath $backup) -or (Test-Path -LiteralPath $resolvedInstall)) {
            $errors.Add('Previous active backup or install destination changed before restore')
            $identityAmbiguous = $true
        }
    }
    if (-not $identityAmbiguous -and $activeMoved) {
        try {
            $backupManifestBeforeRestore = Get-PackageManifest $backup 'Backup directory before restore'
            Assert-SameManifest 'Previous active backup changed before restore' $activeManifest $backupManifestBeforeRestore
            Assert-VerifiedDirectoryIdentity 'Backup directory' $backup $activeIdentity
            Assert-VerifiedDirectoryIdentity 'Install parent' $installParent $installParentIdentity
            Assert-VerifiedRenameReady `
                'Backup directory' $backup $activeIdentity `
                'Install root' $resolvedInstall $installParent $installParentIdentity
            try {
                Move-Item -LiteralPath $backup -Destination $resolvedInstall
            }
            catch {
                throw ([KeeperActivationIdentityException]::new(
                    "Previous active backup could not be restored safely; preserving all ambiguous paths. $($_.Exception.Message)",
                    $_.Exception))
            }
            $activeMoved = $false
            Assert-VerifiedRenameResult `
                'Backup directory' $backup 'Install root' $resolvedInstall $activeIdentity `
                $installParent $installParentIdentity
        }
        catch {
            $errors.Add("Failed to restore the previous active install: $($_.Exception.Message)")
            $identityAmbiguous = $true
        }
    }
    if (-not $identityAmbiguous -and -not $failedEvidenceMoved -and -not $preserveStagingEvidence -and (Test-Path -LiteralPath $staging)) {
        try {
            Remove-VerifiedTree `
                'Staging cleanup' $staging $installParent $stagingIdentity $installParentIdentity `
                $stagingManifest $testContext 'KEEPER_ACTIVATION_TEST_STAGING_PREDELETE_BARRIER' `
                'KEEPER_ACTIVATION_TEST_STAGING_POSTAUTH_BARRIER' `
                'KEEPER_ACTIVATION_TEST_STAGING_HANDLE_DELETE_BARRIER'
        }
        catch {
            $errors.Add("Failed to clean staging evidence: $($_.Exception.Message)")
            $identityAmbiguous = $true
        }
    }
    if ($identityAmbiguous) {
        $errors.Add('Directory identity is ambiguous; no further rollback mutation or recursive cleanup was attempted, and evidence was preserved.')
    }
    $message = "Activation failed; rollback was attempted.`n" + ($errors -join "`n")
    throw $message
}
}
finally {
    if ($null -ne $activationLock) { $activationLock.Dispose() }
}
