<p align='center'>
  <img src='assets/htb.png' alt="HTB">
</p>

# [__Challenges__](#challenges)
| Category      | Name                                                                    | Objective         | Difficulty [⭐⭐⭐⭐⭐] |
|---------------|-------------------------------------------------------------------------|--------------------------------------------------|-------------------------|
| **Web** | [GateCrash](uni-ctf-2023/web/[Easy]%20GateCrash) | SQL injection via CRLF injection | ⭐ |
| **Web** | [Nexus Void](uni-ctf-2023/web/[Medium]%20Nexus%20Void) | Dotnet deserialisaiton via SQL injection | ⭐⭐ |
| **Web** | [PhantomFeed](uni-ctf-2023/web/[Hard]%20PhantomFeed) | Race condition via reDos, open-redirect in Nuxt.js to perofrm CSRF and leak OAuth 2 access token, RCE in Reportlab  | ⭐⭐⭐ |
| **Pwn** | [Great Old Talisman](uni-ctf-2023/pwn/[Easy]%20Great%20Old%20Talisman) |  Overwrite `exit@GOT` with the address of the function that reads the flag | ⭐ |
| **Pwn** | [Zombienator](uni-ctf-2023/pwn/[Medium]%20Zombienator) | Make 9 allocations and 8 frees to leak a libc address, abuse scanf("ld") to bypass the canary check, use pwntools struct to pack doubles, and perform a ret2libc attack with one gadget | ⭐⭐ |
| **Pwn** | [Zombiedote](uni-ctf-2023/pwn/[Hard]%20Zombiedote) | Leverage a single malloc call, an out of bounds read and two out of bounds writes in order into code execution in glibc 2.34 | ⭐⭐⭐ |
| **Reversing** | [WindowOfOpportunity](uni-ctf-2023/rev/[Easy]%20WindowOfOpportunity) | Reversing simple flag checker algorithm | ⭐ |
| **Reversing** | [BioBundle](uni-ctf-2023/rev/[Medium]%20BioBundle) | Reversing a flag checker embedded in a library encrypted and loaded with memfd_create | ⭐⭐ |
| **Reversing** | [RiseFromTheDead](uni-ctf-2023/rev/[Hard]%20RiseFromTheDead) | Reversing a flag encoder then recovering a core dump to retrieve the flagg | ⭐⭐⭐ |
| **Forensics** | [One Step Closer](uni-ctf-2023/forensics/[Easy]%20One%20Step%20Closer) | Windows JScript deobfuscation - Malware delivery - VBS debugging | ⭐ |
| **Forensics** | [ZombieNet](uni-ctf-2023/forensics/[Medium]%20ZombieNet) | OpenWrt firwmare analysis - MIPS binary emulation using QEMU  | ⭐⭐ |
| **Forensics** | [Shadow of the Undead](uni-ctf-2023/forensics/[Hard]%20Shadow%20of%20the%20Undead) | Meterpreter parsing/decryption - custom windows shellcode emulation | ⭐⭐⭐ |
| **Crypto** | [MSS](uni-ctf-2023/crypto/[Easy]%20MSS)| Use CRT to get the entire secret on a Mignotte Secret Sharing scheme | ⭐|
| **Crypto** | [Mayday Mayday](uni-ctf-2023/crypto/[Medium]%20Mayday%20Mayday) | Factor N by exploiting the partial leakage of the CRT components | ⭐⭐ |
| **Crypto** | [Zombie Rolled](uni-ctf-2023/crypto/[Hard]%20Zombie%20Rolled) | Solve a diophantine equation to get the private key and apply LLL to recover the flag from the signature | ⭐⭐⭐ |
