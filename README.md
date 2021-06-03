# DllHollowing

## Dll Hollower
### This code works on my machine
My implementation of https://www.ired.team/offensive-security/code-injection-process-injection/modulestomping-dll-hollowing-shellcode-injection  
Injects shellcode to remote process

## Phantom Dll Hollower
### This code works on my machine
Loads shellcode in local process.  
https://www.forrest-orr.net/post/malicious-memory-artifacts-part-i-dll-hollowing But then in C.  
I added usermode capabilities where all dll's drom system32 are copied to temp folder if program is not run elevated.

## Phantom Dll Hollower Remote
### This is not working
https://www.forrest-orr.net/post/malicious-memory-artifacts-part-i-dll-hollowing But then in C. But then in a remote processs.  
I am unable to start a thread on the shellcode in the mapped section in the remote process.

## PhantomDllHollowerEX
### This is not working
My implementation of https://www.forrest-orr.net/post/malicious-memory-artifacts-part-i-dll-hollowing.  
Copies Dll to temp if not run in privileged mode. I am unable to start a thread on the shellcode in the mapped section in the remote process.
