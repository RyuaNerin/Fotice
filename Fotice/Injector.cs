using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;
using Microsoft.Win32.SafeHandles;

namespace Fotice
{
    internal static class Injector
    {
        public static bool Inject()
        {
            var result = false;
            var hwnd = IntPtr.Zero;

            while ((hwnd = NativeMethods.FindWindowEx(IntPtr.Zero, hwnd, "FFXIVGAME", null)) != IntPtr.Zero)
                result |= NativeMethods.Inject(hwnd);

            return result;
        }


        private static class NativeMethods
        {
            public class SafeHandle : SafeHandleZeroOrMinusOneIsInvalid
            {
                public SafeHandle(IntPtr handle)
                    : base(true)
                {
                    this.SetHandle(handle);
                }

                protected override bool ReleaseHandle()
                {
                    return NativeMethods.CloseHandle(this.handle);
                }

                public static implicit operator IntPtr(SafeHandle alloc)
                {
                    return alloc.handle;
                }
            }

            public class SafeVMHandle : SafeHandleZeroOrMinusOneIsInvalid
            {
                private readonly IntPtr m_hProcess;

                public SafeVMHandle(IntPtr hProcess, IntPtr handle)
                    : base(true)
                {
                    this.m_hProcess = hProcess;
                    this.SetHandle(handle);
                }

                protected override bool ReleaseHandle()
                {
                    return NativeMethods.VirtualFreeEx(this.m_hProcess, handle, IntPtr.Zero, NativeMethods.FreeType.Release);
                }

                public static implicit operator IntPtr(SafeVMHandle alloc)
                {
                    return alloc.handle;
                }
            }

            [DllImport("kernel32.dll", CallingConvention = CallingConvention.Winapi)]
            [return: MarshalAs(UnmanagedType.Bool)]
            private static extern bool IsWow64Process([In] IntPtr processHandle, [Out, MarshalAs(UnmanagedType.Bool)] out bool wow64Process);

            [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
            private static extern IntPtr GetModuleHandle(string lpModuleName);

            [DllImport("kernel32.dll", CharSet = CharSet.Ansi, BestFitMapping = false)]
            private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

            [DllImport("kernel32.dll")]
            private static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

            [DllImport("kernel32.dll")]
            private static extern bool CloseHandle(IntPtr hHandle);

            [DllImport("kernel32.dll")]
            private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

            [DllImport("kernel32.dll")]
            private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, IntPtr nSize, out IntPtr lpNumberOfBytesWritten);

            [DllImport("kernel32.dll")]
            private static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, IntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

            [DllImport("kernel32.dll")]
            private static extern int WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

            [DllImport("kernel32.dll")]
            private static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, FreeType dwFreeType);

            [DllImport("kernel32.dll")]
            private static extern bool GetExitCodeThread(IntPtr hThread, out int lpExitCode);

            [DllImport("kernel32.dll")]
            private static extern IntPtr CreateToolhelp32Snapshot(SnapshotFlags dwFlags, int th32ProcessID);

            [DllImport("kernel32.dll")]
            private static extern bool Module32First(IntPtr hSnapshot, ref MODULEENTRY32 lpme);

            [DllImport("kernel32.dll")]
            private static extern bool Module32Next(IntPtr hSnapshot, ref MODULEENTRY32 lpme);

            [DllImport("kernel32.dll")]
            private static extern IntPtr VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, IntPtr dwLength);

            [DllImport("kernel32.dll")]
            [return: MarshalAs(UnmanagedType.Bool)]
            private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, IntPtr nSize, out IntPtr lpNumberOfBytesRead);

            [DllImport("kernel32.dll")]
            private static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, AllocationProtectEnum flNewProtect, out AllocationProtectEnum lpflOldProtect);

            [DllImport("user32.dll", CharSet = CharSet.Auto)]
            public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out int lpdwProcessId);

            [DllImport("user32.dll", CharSet = CharSet.Auto)]
            public static extern IntPtr FindWindowEx(IntPtr hwndParent, IntPtr hwndChildAfter, string lpszClass, string lpszWindow);

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
            public struct MODULEENTRY32
            {
                internal uint dwSize;
                internal uint th32ModuleID;
                internal uint th32ProcessID;
                internal uint GlblcntUsage;
                internal uint ProccntUsage;
                internal IntPtr modBaseAddr;
                internal uint modBaseSize;
                internal IntPtr hModule;
                [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
                internal string szModule;
                [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
                internal string szExePath;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct MEMORY_BASIC_INFORMATION
            {
                public IntPtr BaseAddress;
                public IntPtr AllocationBase;
                public AllocationProtectEnum AllocationProtect;
                public IntPtr RegionSize;
                public StateEnum State;
                public AllocationProtectEnum Protect;
                public TypeEnum Type;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct IMAGE_DOS_HEADER
            {
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
                public byte[] e_magic;       // Magic number
                public ushort e_cblp;    // Bytes on last page of file
                public ushort e_cp;      // Pages in file
                public ushort e_crlc;    // Relocations
                public ushort e_cparhdr;     // Size of header in paragraphs
                public ushort e_minalloc;    // Minimum extra paragraphs needed
                public ushort e_maxalloc;    // Maximum extra paragraphs needed
                public ushort e_ss;      // Initial (relative) SS value
                public ushort e_sp;      // Initial SP value
                public ushort e_csum;    // Checksum
                public ushort e_ip;      // Initial IP value
                public ushort e_cs;      // Initial (relative) CS value
                public ushort e_lfarlc;      // File address of relocation table
                public ushort e_ovno;    // Overlay number
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
                public ushort[] e_res1;    // Reserved words
                public ushort e_oemid;       // OEM identifier (for e_oeminfo)
                public ushort e_oeminfo;     // OEM information; e_oemid specific
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
                public ushort[] e_res2;    // Reserved words
                public Int32 e_lfanew;      // File address of new exe header
            }
            [StructLayout(LayoutKind.Sequential)]
            public struct IMAGE_NT_HEADERS32
            {
                public uint Signature;
                public IMAGE_FILE_HEADER FileHeader;
                public IMAGE_OPTIONAL_HEADER32 OptionalHeader;
            }
            [StructLayout(LayoutKind.Sequential)]
            public struct IMAGE_FILE_HEADER
            {
                public ushort Machine;
                public ushort NumberOfSections;
                public uint TimeDateStamp;
                public uint PointerToSymbolTable;
                public uint NumberOfSymbols;
                public ushort SizeOfOptionalHeader;
                public ushort Characteristics;
            }

            [StructLayout(LayoutKind.Explicit)]
            public struct IMAGE_OPTIONAL_HEADER32
            {
                [FieldOffset(0)]
                public MagicType Magic;

                [FieldOffset(2)]
                public byte MajorLinkerVersion;

                [FieldOffset(3)]
                public byte MinorLinkerVersion;

                [FieldOffset(4)]
                public uint SizeOfCode;

                [FieldOffset(8)]
                public uint SizeOfInitializedData;

                [FieldOffset(12)]
                public uint SizeOfUninitializedData;

                [FieldOffset(16)]
                public uint AddressOfEntryPoint;

                [FieldOffset(20)]
                public uint BaseOfCode;

                // PE32 contains this additional field
                [FieldOffset(24)]
                public uint BaseOfData;

                [FieldOffset(28)]
                public uint ImageBase;

                [FieldOffset(32)]
                public uint SectionAlignment;

                [FieldOffset(36)]
                public uint FileAlignment;

                [FieldOffset(40)]
                public ushort MajorOperatingSystemVersion;

                [FieldOffset(42)]
                public ushort MinorOperatingSystemVersion;

                [FieldOffset(44)]
                public ushort MajorImageVersion;

                [FieldOffset(46)]
                public ushort MinorImageVersion;

                [FieldOffset(48)]
                public ushort MajorSubsystemVersion;

                [FieldOffset(50)]
                public ushort MinorSubsystemVersion;

                [FieldOffset(52)]
                public uint Win32VersionValue;

                [FieldOffset(56)]
                public uint SizeOfImage;

                [FieldOffset(60)]
                public uint SizeOfHeaders;

                [FieldOffset(64)]
                public uint CheckSum;

                [FieldOffset(68)]
                public SubSystemType Subsystem;

                [FieldOffset(70)]
                public DllCharacteristicsType DllCharacteristics;

                [FieldOffset(72)]
                public uint SizeOfStackReserve;

                [FieldOffset(76)]
                public uint SizeOfStackCommit;

                [FieldOffset(80)]
                public uint SizeOfHeapReserve;

                [FieldOffset(84)]
                public uint SizeOfHeapCommit;

                [FieldOffset(88)]
                public uint LoaderFlags;

                [FieldOffset(92)]
                public uint NumberOfRvaAndSizes;

                [FieldOffset(96)]
                public IMAGE_DATA_DIRECTORY ExportTable;

                [FieldOffset(104)]
                public IMAGE_DATA_DIRECTORY ImportTable;

                [FieldOffset(112)]
                public IMAGE_DATA_DIRECTORY ResourceTable;

                [FieldOffset(120)]
                public IMAGE_DATA_DIRECTORY ExceptionTable;

                [FieldOffset(128)]
                public IMAGE_DATA_DIRECTORY CertificateTable;

                [FieldOffset(136)]
                public IMAGE_DATA_DIRECTORY BaseRelocationTable;

                [FieldOffset(144)]
                public IMAGE_DATA_DIRECTORY Debug;

                [FieldOffset(152)]
                public IMAGE_DATA_DIRECTORY Architecture;

                [FieldOffset(160)]
                public IMAGE_DATA_DIRECTORY GlobalPtr;

                [FieldOffset(168)]
                public IMAGE_DATA_DIRECTORY TLSTable;

                [FieldOffset(176)]
                public IMAGE_DATA_DIRECTORY LoadConfigTable;

                [FieldOffset(184)]
                public IMAGE_DATA_DIRECTORY BoundImport;

                [FieldOffset(192)]
                public IMAGE_DATA_DIRECTORY IAT;

                [FieldOffset(200)]
                public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

                [FieldOffset(208)]
                public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

                [FieldOffset(216)]
                public IMAGE_DATA_DIRECTORY Reserved;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct IMAGE_DATA_DIRECTORY
            {
                public uint VirtualAddress;
                public uint Size;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct IMAGE_EXPORT_DIRECTORY
            {
                public uint Characteristics;
                public uint TimeDateStamp;
                public ushort MajorVersion;
                public ushort MinorVersion;
                public uint Name;
                public uint Base;
                public uint NumberOfFunctions;
                public uint NumberOfNames;
                public uint AddressOfFunctions;     // RVA from base of image
                public uint AddressOfNames;     // RVA from base of image
                public uint AddressOfNameOrdinals;  // RVA from base of image
            }

            [Flags]
            private enum ProcessAccessFlags : uint
            {
                All = 0x001F0FFF,
                Terminate = 0x00000001,
                CreateThread = 0x00000002,
                VirtualMemoryOperation = 0x00000008,
                VirtualMemoryRead = 0x00000010,
                VirtualMemoryWrite = 0x00000020,
                DuplicateHandle = 0x00000040,
                CreateProcess = 0x000000080,
                SetQuota = 0x00000100,
                SetInformation = 0x00000200,
                QueryInformation = 0x00000400,
                QueryLimitedInformation = 0x00001000,
                Synchronize = 0x00100000
            }

            [Flags]
            private enum AllocationType
            {
                Commit = 0x1000,
                Reserve = 0x2000,
                Decommit = 0x4000,
                Release = 0x8000,
                Reset = 0x80000,
                Physical = 0x400000,
                TopDown = 0x100000,
                WriteWatch = 0x200000,
                LargePages = 0x20000000
            }

            [Flags]
            private enum MemoryProtection
            {
                Execute = 0x10,
                ExecuteRead = 0x20,
                ExecuteReadWrite = 0x40,
                ExecuteWriteCopy = 0x80,
                NoAccess = 0x01,
                ReadOnly = 0x02,
                ReadWrite = 0x04,
                WriteCopy = 0x08,
                GuardModifierflag = 0x100,
                NoCacheModifierflag = 0x200,
                WriteCombineModifierflag = 0x400
            }

            [Flags]
            private enum FreeType
            {
                Decommit = 0x4000,
                Release = 0x8000,
            }

            [Flags]
            public enum SnapshotFlags : uint
            {
                HeapList = 0x00000001,
                Process  = 0x00000002,
                Thread   = 0x00000004,
                Module   = 0x00000008,
                Module32 = 0x00000010,
                All      = (HeapList | Process | Thread | Module),
                Inherit  = 0x80000000,
                NoHeaps  = 0x40000000
            }

            [Flags]
            public enum AllocationProtectEnum : uint
            {
                None = 0,
                PAGE_EXECUTE = 0x00000010,
                PAGE_EXECUTE_READ = 0x00000020,
                PAGE_EXECUTE_READWRITE = 0x00000040,
                PAGE_EXECUTE_WRITECOPY = 0x00000080,
                PAGE_NOACCESS = 0x00000001,
                PAGE_READONLY = 0x00000002,
                PAGE_READWRITE = 0x00000004,
                PAGE_WRITECOPY = 0x00000008,
                PAGE_GUARD = 0x00000100,
                PAGE_NOCACHE = 0x00000200,
                PAGE_WRITECOMBINE = 0x00000400
            }

            public enum StateEnum : uint
            {
                MEM_COMMIT = 0x1000,
                MEM_FREE = 0x10000,
                MEM_RESERVE = 0x2000
            }

            public enum TypeEnum : uint
            {
                MEM_IMAGE = 0x1000000,
                MEM_MAPPED = 0x40000,
                MEM_PRIVATE = 0x20000
            }

            public enum MachineType : ushort
            {
                Native = 0,
                I386 = 0x014c,
                Itanium = 0x0200,
                x64 = 0x8664
            }

            public enum MagicType : ushort
            {
                IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
                IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
            }

            public enum SubSystemType : ushort
            {
                IMAGE_SUBSYSTEM_UNKNOWN = 0,
                IMAGE_SUBSYSTEM_NATIVE = 1,
                IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
                IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
                IMAGE_SUBSYSTEM_POSIX_CUI = 7,
                IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
                IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
                IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
                IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
                IMAGE_SUBSYSTEM_EFI_ROM = 13,
                IMAGE_SUBSYSTEM_XBOX = 14
            }

            public enum DllCharacteristicsType : ushort
            {
                RES_0 = 0x0001,
                RES_1 = 0x0002,
                RES_2 = 0x0004,
                RES_3 = 0x0008,
                IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x0040,
                IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
                IMAGE_DLL_CHARACTERISTICS_NX_COMPAT = 0x0100,
                IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200,
                IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
                IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800,
                RES_4 = 0x1000,
                IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
                IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
            }

            private static bool ReadProcessMemoryEx(IntPtr hProcess, IntPtr lpBaseAddress, byte[] array)
            {
                var mbi = new MEMORY_BASIC_INFORMATION();
                var mbiSize = new IntPtr(Marshal.SizeOf(mbi));
                IntPtr lpNumberOfBytesRead;

                if (NativeMethods.VirtualQueryEx(hProcess, lpBaseAddress, out mbi, mbiSize) != mbiSize)
                    return false;

                if (mbi.Protect == 0 || (mbi.Protect & AllocationProtectEnum.PAGE_GUARD) == AllocationProtectEnum.PAGE_GUARD)
                    return false;

                if ((mbi.Protect & AllocationProtectEnum.PAGE_READONLY) == AllocationProtectEnum.PAGE_READONLY)
                {
                    AllocationProtectEnum flOldProtect;
                    if (!VirtualProtectEx(hProcess, mbi.BaseAddress, mbi.RegionSize, AllocationProtectEnum.PAGE_READONLY, out flOldProtect))
                        return false;

                    ReadProcessMemory(hProcess, lpBaseAddress, array, new IntPtr(array.Length), out lpNumberOfBytesRead);

                    return VirtualProtectEx(hProcess, mbi.BaseAddress, mbi.RegionSize, flOldProtect, out flOldProtect);
                }

                var result = ReadProcessMemory(hProcess, lpBaseAddress, array, new IntPtr(array.Length), out lpNumberOfBytesRead);

                return result;
            }

            public static bool Inject(IntPtr ffxiv)
            {
                int pid;
                if (NativeMethods.GetWindowThreadProcessId(ffxiv, out pid) == 0)
                    return false;

                var hProcess = new SafeHandle(NativeMethods.OpenProcess(NativeMethods.ProcessAccessFlags.All, false, pid));
                if (hProcess.IsInvalid)
                    return false;

                var lpLoadLibraryW = NativeMethods.GetProcAddress(NativeMethods.GetModuleHandle("kernel32.dll"), "LoadLibraryW");

                var dllPath = Path.Combine(Path.GetTempPath(), "Fotice.dll");
                try
                {
                    File.WriteAllBytes(dllPath, Properties.Resources.dll);
                }
                catch
                { }
                if (!File.Exists(dllPath))
                    return false;

                if (lpLoadLibraryW == IntPtr.Zero)
                    return false;

                dllPath += "\0";
                var size = new IntPtr(Encoding.Unicode.GetByteCount(dllPath));
                var buff = Encoding.Unicode.GetBytes(dllPath);

                var hVAlloc = new SafeVMHandle(hProcess, NativeMethods.VirtualAllocEx(hProcess, IntPtr.Zero, size, NativeMethods.AllocationType.Commit, NativeMethods.MemoryProtection.ReadWrite));
                if (hVAlloc.IsInvalid)
                    return false;

                IntPtr lpNumberOfBytesWritten;
                if (!NativeMethods.WriteProcessMemory(hProcess, hVAlloc, buff, size, out lpNumberOfBytesWritten) && lpNumberOfBytesWritten != size)
                    return false;

                IntPtr lpThreadId;
                var hThread = new SafeHandle(NativeMethods.CreateRemoteThread(hProcess, IntPtr.Zero, IntPtr.Zero, lpLoadLibraryW, hVAlloc, 0, out lpThreadId));
                if (hThread.IsInvalid)
                    return false;

                NativeMethods.WaitForSingleObject(hThread, 0xFFFFFFFF);

                int exitCode;
                return NativeMethods.GetExitCodeThread(hThread, out exitCode) && exitCode != 0;
            }
        }
    }
}
