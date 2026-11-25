// Private Windows stdio lifetime containment. Uses only installed .NET/Win32.
// Compile with Windows PowerShell Add-Type. No subprocess is started on load.
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

public static class AotgWindowsIoJobV2
{
    public sealed class Result
    {
        public int ProcessId;
        public uint ExitCode;
        public bool TimedOut;
        public bool Cancelled;
        public bool JobEmpty;
        public double Seconds;
        public string ExecutableSha256;
        public string CleanupScope = "windows-job-object";
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS
    {
        public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount;
        public ulong ReadTransferCount, WriteTransferCount, OtherTransferCount;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct BASIC_LIMIT
    {
        public long PerProcessUserTimeLimit, PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass, SchedulingClass;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct EXTENDED_LIMIT
    {
        public BASIC_LIMIT BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct ACCOUNTING
    {
        public long TotalUserTime, TotalKernelTime, ThisPeriodTotalUserTime, ThisPeriodTotalKernelTime;
        public uint TotalPageFaultCount, TotalProcesses, ActiveProcesses, TotalTerminatedProcesses;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb;
        public string lpReserved, lpDesktop, lpTitle;
        public uint dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess, hThread;
        public uint dwProcessId, dwThreadId;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObject(IntPtr attributes, string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(IntPtr job, int infoClass, ref EXTENDED_LIMIT info, uint length);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool QueryInformationJobObject(IntPtr job, int infoClass, ref ACCOUNTING info, uint length, IntPtr returnLength);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateJobObject(IntPtr job, uint code);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr process, uint code);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetStdHandle(int number);
    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DuplicateHandle(IntPtr sourceProcess, IntPtr source, IntPtr targetProcess,
                                                out IntPtr target, uint access, bool inherit, uint options);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr size);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute,
                                                       IntPtr value, IntPtr size, IntPtr previous, IntPtr returned);
    [DllImport("kernel32.dll")]
    private static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcessW(string applicationName, StringBuilder commandLine,
                                              IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles,
                                              uint flags, IntPtr environment, string directory,
                                              ref STARTUPINFOEX startup, out PROCESS_INFORMATION process);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(IntPtr process, out uint code);

    private static void Check(bool value, string operation)
    {
        if (!value) throw new Win32Exception(Marshal.GetLastWin32Error(), operation);
    }

    private static IntPtr DuplicateStandard(int kind)
    {
        IntPtr original = GetStdHandle(kind);
        if (original == IntPtr.Zero || original == new IntPtr(-1)) throw new InvalidOperationException("Missing standard handle");
        IntPtr duplicate;
        Check(DuplicateHandle(GetCurrentProcess(), original, GetCurrentProcess(), out duplicate, 0, true, 2), "Duplicate stdio handle");
        return duplicate;
    }

    // Microsoft CRT command-line quoting; applicationName separately pins exe.
    public static string Quote(string value)
    {
        if (value == null || value.IndexOf('\0') >= 0) throw new ArgumentException("Invalid argv value");
        StringBuilder result = new StringBuilder("\"");
        int slashes = 0;
        foreach (char c in value)
        {
            if (c == '\\') { slashes++; continue; }
            if (c == '"') { result.Append('\\', slashes * 2 + 1); result.Append('"'); }
            else { result.Append('\\', slashes); result.Append(c); }
            slashes = 0;
        }
        result.Append('\\', slashes * 2); result.Append('"');
        return result.ToString();
    }

    private static bool Empty(IntPtr job)
    {
        ACCOUNTING accounting = new ACCOUNTING();
        Check(QueryInformationJobObject(job, 1, ref accounting, (uint)Marshal.SizeOf(typeof(ACCOUNTING)), IntPtr.Zero), "Query owned job accounting");
        return accounting.ActiveProcesses == 0;
    }

    public static Result Run(string executable, string expectedSha256, string[] args,
                             string directory, int timeoutMilliseconds, string cancelPath)
    {
        if (!Path.IsPathRooted(executable) || !Path.IsPathRooted(directory) || !Directory.Exists(directory))
            throw new ArgumentException("Absolute existing executable/directory required");
        if (timeoutMilliseconds < 100 || timeoutMilliseconds > 6275000) throw new ArgumentException("Finite timeout required");
        if (args == null || args.Length > 128) throw new ArgumentException("Bounded explicit argv required");
        if (String.IsNullOrEmpty(cancelPath)) cancelPath = null;
        if (cancelPath != null && (!Path.IsPathRooted(cancelPath) || File.Exists(cancelPath)))
            throw new ArgumentException("Cancellation marker must be a new explicit absolute path");
        IntPtr job = IntPtr.Zero, handleList = IntPtr.Zero;
        IntPtr[] stdio = new IntPtr[3];
        STARTUPINFOEX startup = new STARTUPINFOEX();
        PROCESS_INFORMATION process = new PROCESS_INFORMATION();
        bool attributesInitialized = false, assigned = false, cleanupVerified = false;
        Stopwatch elapsed = Stopwatch.StartNew();
        Result result = new Result();
        // Sharing only for reads pins file content across CreateProcess; no write
        // or delete sharing. Do not change permissions on the existing binary.
        using (FileStream executableLock = new FileStream(executable, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            using (SHA256 sha = SHA256.Create())
                result.ExecutableSha256 = BitConverter.ToString(sha.ComputeHash(executableLock)).Replace("-", "").ToLowerInvariant();
            if (!String.Equals(expectedSha256, result.ExecutableSha256, StringComparison.Ordinal))
                throw new InvalidOperationException("Existing executable hash changed");
            try
            {
                job = CreateJobObject(IntPtr.Zero, null);
                Check(job != IntPtr.Zero, "Create unnamed owned job");
                EXTENDED_LIMIT limit = new EXTENDED_LIMIT();
                limit.BasicLimitInformation.LimitFlags = 0x2000; // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                Check(SetInformationJobObject(job, 9, ref limit, (uint)Marshal.SizeOf(typeof(EXTENDED_LIMIT))), "Set kill-on-close job");
                stdio[0] = DuplicateStandard(-10); stdio[1] = DuplicateStandard(-11); stdio[2] = DuplicateStandard(-12);
                startup.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFOEX));
                startup.StartupInfo.dwFlags = 0x100; // STARTF_USESTDHANDLES
                startup.StartupInfo.hStdInput = stdio[0]; startup.StartupInfo.hStdOutput = stdio[1]; startup.StartupInfo.hStdError = stdio[2];
                IntPtr attributeBytes = IntPtr.Zero;
                InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref attributeBytes);
                if (attributeBytes == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "Size attribute list");
                startup.lpAttributeList = Marshal.AllocHGlobal(attributeBytes);
                Check(InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, ref attributeBytes), "Initialize attribute list");
                attributesInitialized = true;
                handleList = Marshal.AllocHGlobal(IntPtr.Size * stdio.Length);
                Marshal.Copy(stdio, 0, handleList, stdio.Length);
                Check(UpdateProcThreadAttribute(startup.lpAttributeList, 0, new IntPtr(0x20002), handleList,
                                                new IntPtr(IntPtr.Size * stdio.Length), IntPtr.Zero, IntPtr.Zero), "Restrict inherited handles");
                StringBuilder command = new StringBuilder(Quote(executable));
                foreach (string arg in args) { command.Append(' '); command.Append(Quote(arg)); }
                if (command.Length > 30000) throw new ArgumentException("Command exceeds fixed limit");
                Check(CreateProcessW(executable, command, IntPtr.Zero, IntPtr.Zero, true,
                                     0x4 | 0x80000 | 0x08000000, IntPtr.Zero, directory, ref startup, out process), "Create suspended child");
                result.ProcessId = (int)process.dwProcessId;
                Check(AssignProcessToJobObject(job, process.hProcess), "Assign suspended child to owned job");
                assigned = true;
                if (ResumeThread(process.hThread) == 0xFFFFFFFF) throw new Win32Exception(Marshal.GetLastWin32Error(), "Resume assigned child");
                while (true)
                {
                    uint wait = WaitForSingleObject(process.hProcess, 20);
                    if (wait == 0) break;
                    if (wait != 258) throw new Win32Exception(Marshal.GetLastWin32Error(), "Wait for owned child");
                    if (elapsed.ElapsedMilliseconds >= timeoutMilliseconds) { result.TimedOut = true; break; }
                    if (cancelPath != null && File.Exists(cancelPath)) { result.Cancelled = true; break; }
                }
                uint exitCode;
                Check(GetExitCodeProcess(process.hProcess, out exitCode), "Read child exit code");
                result.ExitCode = exitCode;
            }
            finally
            {
                // Also terminate remaining grandchildren after normal direct-child
                // exit. CREATE_BREAKAWAY_FROM_JOB was never permitted for this job.
                try
                {
                    if (job != IntPtr.Zero && assigned)
                    {
                        Check(TerminateJobObject(job, 0xE001), "Terminate remaining owned job processes");
                        Stopwatch cleanup = Stopwatch.StartNew();
                        while (!Empty(job) && cleanup.ElapsedMilliseconds < 5000) Thread.Sleep(20);
                        cleanupVerified = Empty(job);
                    }
                    else if (process.hProcess != IntPtr.Zero)
                    {
                        // Assignment failure: the only child is still suspended.
                        TerminateProcess(process.hProcess, 0xE002);
                        WaitForSingleObject(process.hProcess, 5000);
                    }
                }
                finally
                {
                    if (process.hThread != IntPtr.Zero) CloseHandle(process.hThread);
                    if (process.hProcess != IntPtr.Zero) CloseHandle(process.hProcess);
                    if (attributesInitialized) DeleteProcThreadAttributeList(startup.lpAttributeList);
                    if (startup.lpAttributeList != IntPtr.Zero) Marshal.FreeHGlobal(startup.lpAttributeList);
                    if (handleList != IntPtr.Zero) Marshal.FreeHGlobal(handleList);
                    foreach (IntPtr handle in stdio) if (handle != IntPtr.Zero) CloseHandle(handle);
                    // Kernel kill-on-close also covers failed cleanup operations.
                    if (job != IntPtr.Zero) CloseHandle(job);
                }
            }
        }
        if (!cleanupVerified) throw new InvalidOperationException("Windows job cleanup was not verified");
        result.JobEmpty = true;
        result.Seconds = elapsed.Elapsed.TotalSeconds;
        return result;
    }
}
