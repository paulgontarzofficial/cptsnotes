![[Pasted image 20251104214127.png]]
Netsh is a command-line tool that can help with the network configuration of a particular windows system. 
- Finding Routes
- Viewing the firewall configuration
- Adding Proxies
- Creating port forwarding rules

**Using Netsh.exe to Port Forward**
```cmd-session
C:\Windows\system32> netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=172.16.5.25
```

**Verifying Port Forward**
```cmd-session
C:\Windows\system32> netsh.exe interface portproxy show v4tov4

Listen on ipv4:             Connect to ipv4:

Address         Port        Address         Port
--------------- ----------  --------------- ----------
10.129.15.150   8080        172.16.5.25     3389
```

