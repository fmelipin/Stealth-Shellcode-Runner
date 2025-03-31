# 🧬 Stealth Shellcode Runner – AES + Donut + PowerShell Loader

This project demonstrates a stealthy end-to-end technique to execute an AES-encrypted PowerShell reverse shell using:

- **Process Hollowing**
- **AES-256-CBC Encryption**
- **Donut Shellcode Generator**
- **.NET AMSI Bypass**
- **Indirect Syscalls**
- **PPID Spoofing (optional)**

Tested in OSEP-like environments with **Windows Defender enabled**.

---

## 🧩 Step 1: Build the PowerShell Loader

- The C# loader patches AMSI via `.NET Reflection`, downloads a remote PowerShell payload, and executes it in memory using `Runspace`.
- Uses base64 string obfuscation for script names like `shell.ps1`.

📌 **Note:** You may need to reference:
```
C:\Program Files\WindowsPowerShell\Modules\PowerShellGet\<version>\System.Management.Automation.dll
```

---

## 🧪 Step 2: Generate Shellcode with Donut

Convert the compiled `Loader.exe` into raw shellcode with `donut`:

```bash
donut.exe -i Loader.exe -a 2 -f 1 -b 1 -o shellcode.bin
```

**Explanation of Donut flags:**
- `-a 2`: Target architecture (x64)
- `-f 1`: Output format: raw shellcode
- `-b 1`: Enable AMSI/WLDP/ETW bypass with fallback  
  - `1`: **No bypass**  
  - `2`: Abort on failure  
  - `3`: Continue on failure 

* I use donut in my Windows host an then transfer to kali linux to encrypt the shellcode.bin file.
---

## 🔐 Step 3: Encrypt the Shellcode with AES

Use the provided Python script to encrypt the shellcode using AES-256-CBC:

```bash
python3 Aes_encryption.py
```

- The script generates `encryptedShellcode`, `aesKey`, and `aesIV` as C#-formatted byte arrays.
- Paste these into the `Advanced_Process_Hollowing.cs` runner.

---

## 🧠 Step 4: Execute with Process Hollowing + Indirect Syscalls

The shellcode runner performs the following:

- Creates a suspended process (e.g., `svchost.exe`)
- Allocates memory using `NtAllocateVirtualMemory` (indirect syscall)
- Decrypts the AES shellcode in memory
- Writes shellcode using `NtWriteVirtualMemory` (indirect syscall)
- Sets memory protection to `RX` using `NtProtectVirtualMemory`
- Launches a thread using `NtCreateThreadEx` (indirect syscall)

✅ All syscalls are performed using dynamically allocated stubs copied directly from `ntdll.dll`, bypassing userland hooks from AV/EDR.

✅ PPID spoofing support can be added for stealthier process lineage.

---

## 🌐 Step 5: Host the PowerShell Reverse Shell

Create a `shell.ps1` PowerShell script containing your reverse shell logic.

Then host it using a simple HTTP server:

```bash
python3 -m http.server 80
```

---

## 📡 Step 6: Start Listener with Netcat

Use `netcat` (and optionally `rlwrap`) to catch the reverse shell:

```bash
rlwrap -cAr nc -lnvp 443
```

---

## 🚀 Step 7: Run the Shellcode Runner

Once everything is set:

```bash
.\Advanced_Process_Hollowing.exe
```

If successful, your listener will receive the reverse shell.

---

## ✅ Summary

- AMSI is bypassed silently at runtime via .NET Reflection
- Shellcode is encrypted with AES and decrypted just-in-time
- Execution flow uses indirect syscalls to evade userland hooks
- Shellcode loads a PowerShell loader that fetches and runs a remote payload
- Designed for stealth and tested in real-world offensive scenarios

---

## ⚠️ Legal Notice

This project is for **educational and authorized penetration testing** purposes only.  
Do not use this code outside of lab environments or without **explicit permission**.  
Misuse may be illegal and unethical.

---
