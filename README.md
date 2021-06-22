# DllHollowing

## Dll Hollower
### This code works on my machine @ 22-06-2021
Injects shellcode to remote process
#### Explanation
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

## PhantomDllHollowerEX
### This is not working @ 22-06-2021
The phantom dll hollower but in a remote process.   
Copies Dll to temp if not run in privileged mode. I am unable to start a thread on the shellcode in the mapped section in the remote process.
#### Explanation
#### References
https://www.forrest-orr.net/post/malicious-memory-artifacts-part-i-dll-hollowing
