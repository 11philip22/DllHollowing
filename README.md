# DllHollowing

## Dll Hollower
### This code works on my machine @ 22-06-2021
Injects shellcode to remote process
#### Explanation
Create a `notepad.exe` process as host.  
Load Dll into remote process by calling `LoadLibaryW` with a remote thread.  
Get Dll AddressofEntryPoint.  
Write shellcode to AddressofEntryPoint and call shellcode with `CreateRemoteThread`.  

#### References
https://www.ired.team/offensive-security/code-injection-process-injection/modulestomping-dll-hollowing-shellcode-injection  

## Phantom Dll Hollower
### This code works on my machine @ 22-06-2021
Loads shellcode in local process.  
Forrest-orr's PoC but then in C.  
I added usermode capabilities where all dll's drom system32 are copied to temp folder if program is not run elevated.
#### Explanation
#### References
https://www.forrest-orr.net/post/malicious-memory-artifacts-part-i-dll-hollowing
