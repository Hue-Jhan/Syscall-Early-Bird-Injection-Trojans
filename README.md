# Syscall Early-Bird Injection Trojans (Direct/Indirect)
Collection of remote shellcode Loaders using Early Bird APC injection, direct/indirect syscalls, ntdll and low level utilities, undetected by Windows Defender and BitDefender. This code is for educational purposes only, do not use it for any malicious or unauthorized activity.

This code is an improved version of [this](https://github.com/Hue-Jhan/Syscall-Apc-Injection-Trojans), and includes both the direct syscall and indirect syscalls version of a classic shellcode injection via APC, its dll version, and a DLL injector queuing LoadLibraryA.

# 🖥️ Code
This repo is a more advanced version of [this one](https://github.com/Hue-Jhan/Early-Bird-Process-and-Dll-injection/), it consists of 3 projects that have the same basic structure and share most of the code, they are: Nt Early bird APC injection, DLL version, and a DLL Injector (LoadLibrary using APC), the shellcode is for a windows msg box. Every code includes 2 versions, one with NtCreateUserProcess (stealthier, low level, using syscalls), and an old one with RtlCreateUserProcess (higher level but easier to manage, dont uncomment it).

Next to each code as you can see i put the virus total detections for its raw executable.

# 🛡️ AV Detection
bb

