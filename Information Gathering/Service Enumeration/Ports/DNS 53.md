
Domain Name System


Server Types: 

|**Server Type**|**Description**|
|---|---|
|`DNS Root Server`|The root servers of the DNS are responsible for the top-level domains (`TLD`). As the last instance, they are only requested if the name server does not respond. Thus, a root server is a central interface between users and content on the Internet, as it links domain and IP address. The [Internet Corporation for Assigned Names and Numbers](https://www.icann.org/) (`ICANN`) coordinates the work of the root name servers. There are `13` such root servers around the globe.|
|`Authoritative Nameserver`|Authoritative name servers hold authority for a particular zone. They only answer queries from their area of responsibility, and their information is binding. If an authoritative name server cannot answer a client's query, the root name server takes over at that point. Based on the country, company, etc., authoritative nameservers provide answers to recursive DNS nameservers, assisting in finding the specific web server(s).|
|`Non-authoritative Nameserver`|Non-authoritative name servers are not responsible for a particular DNS zone. Instead, they collect information on specific DNS zones themselves, which is done using recursive or iterative DNS querying.|
|`Caching DNS Server`|Caching DNS servers cache information from other name servers for a specified period. The authoritative name server determines the duration of this storage.|
|`Forwarding Server`|Forwarding servers perform only one function: they forward DNS queries to another DNS server.|
|`Resolver`|Resolvers are not authoritative DNS servers but perform name resolution locally in the computer or router.|
![[Pasted image 20251015144257.png]]

## DNS Records

Used for DNS Queries: 

|**DNS Record**|**Description**|
|---|---|
|`A`|Returns an IPv4 address of the requested domain as a result.|
|`AAAA`|Returns an IPv6 address of the requested domain.|
|`MX`|Returns the responsible mail servers as a result.|
|`NS`|Returns the DNS servers (nameservers) of the domain.|
|`TXT`|This record can contain various information. The all-rounder can be used, e.g., to validate the Google Search Console or validate SSL certificates. In addition, SPF and DMARC entries are set to validate mail traffic and protect it from spam.|
|`CNAME`|This record serves as an alias for another domain name. If you want the domain [www.hackthebox.eu](http://www.hackthebox.eu) to point to the same IP as hackthebox.eu, you would create an A record for hackthebox.eu and a CNAME record for [www.hackthebox.eu](http://www.hackthebox.eu).|
|`PTR`|The PTR record works the other way around (reverse lookup). It converts IP addresses into valid domain names.|
|`SOA`|Provides information about the corresponding DNS zone and email address of the administrative contact.|
Using the command 'dig' to look at the SOA record: 

```
realCustampin@htb[/htb]$ dig soa www.inlanefreight.com

; <<>> DiG 9.16.27-Debian <<>> soa www.inlanefreight.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 15876
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
;www.inlanefreight.com.         IN      SOA

;; AUTHORITY SECTION:
inlanefreight.com.      900     IN      SOA     ns-161.awsdns-20.com. awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400

;; Query time: 16 msec
;; SERVER: 8.8.8.8#53(8.8.8.8)
;; WHEN: Thu Jan 05 12:56:10 GMT 2023
;; MSG SIZE  rcvd: 128
```

## Default Configuration

Three Main Types: 
1. Local DNS Configuration Files
2. Zone Files
3. Reverse Name Resolution Files

Common linux DNS server that is used is "Bind9" which stores their configuration files in /etc/bind/named.conf.local

```
root@bind9:~# cat /etc/bind/named.conf.local

//
// Do any local configuration here
//

// Consider adding the 1918 zones here, if they are not used in your
// organization
//include "/etc/bind/zones.rfc1918";
zone "domain.com" {
    type master;
    file "/etc/bind/db.domain.com";
    allow-update { key rndc-key; };
};
```

**What is a zone file?**
- A `zone file` is a text file that describes a DNS zone with the BIND file format. In other words it is a point of delegation in the DNS tree.
- Uses the BIND File Format (Industry Standard)

```
root@bind9:~# cat /etc/bind/db.domain.com

;
; BIND reverse data file for local loopback interface
;
$ORIGIN domain.com
$TTL 86400
@     IN     SOA    dns1.domain.com.     hostmaster.domain.com. (
                    2001062501 ; serial
                    21600      ; refresh after 6 hours
                    3600       ; retry after 1 hour
                    604800     ; expire after 1 week
                    86400 )    ; minimum TTL of 1 day

      IN     NS     ns1.domain.com.
      IN     NS     ns2.domain.com.

      IN     MX     10     mx.domain.com.
      IN     MX     20     mx2.domain.com.

             IN     A       10.129.14.5

server1      IN     A       10.129.14.5
server2      IN     A       10.129.14.7
ns1          IN     A       10.129.14.2
ns2          IN     A       10.129.14.3

ftp          IN     CNAME   server1
mx           IN     CNAME   server1
mx2          IN     CNAME   server2
www          IN     CNAME   server2
```


In order for the FQDN to be fully resolved, we must have a reverse lookup BIND file as well. 

```
root@bind9:~# cat /etc/bind/db.10.129.14

;
; BIND reverse data file for local loopback interface
;
$ORIGIN 14.129.10.in-addr.arpa
$TTL 86400
@     IN     SOA    dns1.domain.com.     hostmaster.domain.com. (
                    2001062501 ; serial
                    21600      ; refresh after 6 hours
                    3600       ; retry after 1 hour
                    604800     ; expire after 1 week
                    86400 )    ; minimum TTL of 1 day

      IN     NS     ns1.domain.com.
      IN     NS     ns2.domain.com.

5    IN     PTR    server1.domain.com.
7    IN     MX     mx.domain.com.
...SNIP...
```

## Dangerous Settings

| **Option**        | **Description**                                                                |
| ----------------- | ------------------------------------------------------------------------------ |
| `allow-query`     | Defines which hosts are allowed to send requests to the DNS server.            |
| `allow-recursion` | Defines which hosts are allowed to send recursive requests to the DNS server.  |
| `allow-transfer`  | Defines which hosts are allowed to receive zone transfers from the DNS server. |
| `zone-statistics` | Collects statistical data of zones.                                            |
## Footprinting the Service

Using the 'dig' command to gather information: 

```
realCustampin@htb[/htb]$ dig ns inlanefreight.htb @10.129.14.128

; <<>> DiG 9.16.1-Ubuntu <<>> ns inlanefreight.htb @10.129.14.128
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 45010
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 2

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: ce4d8681b32abaea0100000061475f73842c401c391690c7 (good)
;; QUESTION SECTION:
;inlanefreight.htb.             IN      NS

;; ANSWER SECTION:
inlanefreight.htb.      604800  IN      NS      ns.inlanefreight.htb.

;; ADDITIONAL SECTION:
ns.inlanefreight.htb.   604800  IN      A       10.129.34.136

;; Query time: 0 msec
;; SERVER: 10.129.14.128#53(10.129.14.128)
;; WHEN: So Sep 19 18:04:03 CEST 2021
;; MSG SIZE  rcvd: 107
```
- We see that we pass the dig command and specify the name server and the ip address that we would like to target. 

We can query the version of DNS that is running on that ip address. 
```
realCustampin@htb[/htb]$ dig CH TXT version.bind 10.129.120.85

; <<>> DiG 9.10.6 <<>> CH TXT version.bind
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 47786
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; ANSWER SECTION:
version.bind.       0       CH      TXT     "9.10.6-P1"

;; ADDITIONAL SECTION:
version.bind.       0       CH      TXT     "9.10.6-P1-Debian"

;; Query time: 2 msec
;; SERVER: 10.129.120.85#53(10.129.120.85)
;; WHEN: Wed Jan 05 20:23:14 UTC 2023
;; MSG SIZE  rcvd: 101
```

Viewing all the records at once: 

```
realCustampin@htb[/htb]$ dig any inlanefreight.htb @10.129.14.128

; <<>> DiG 9.16.1-Ubuntu <<>> any inlanefreight.htb @10.129.14.128
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 7649
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 2

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: 064b7e1f091b95120100000061476865a6026d01f87d10ca (good)
;; QUESTION SECTION:
;inlanefreight.htb.             IN      ANY

;; ANSWER SECTION:
inlanefreight.htb.      604800  IN      TXT     "v=spf1 include:mailgun.org include:_spf.google.com include:spf.protection.outlook.com include:_spf.atlassian.net ip4:10.129.124.8 ip4:10.129.127.2 ip4:10.129.42.106 ~all"
inlanefreight.htb.      604800  IN      TXT     "atlassian-domain-verification=t1rKCy68JFszSdCKVpw64A1QksWdXuYFUeSXKU"
inlanefreight.htb.      604800  IN      TXT     "MS=ms97310371"
inlanefreight.htb.      604800  IN      SOA     inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
inlanefreight.htb.      604800  IN      NS      ns.inlanefreight.htb.

;; ADDITIONAL SECTION:
ns.inlanefreight.htb.   604800  IN      A       10.129.34.136

;; Query time: 0 msec
;; SERVER: 10.129.14.128#53(10.129.14.128)
;; WHEN: So Sep 19 18:42:13 CEST 2021
;; MSG SIZE  rcvd: 437
```
- This allows us to view all things related to the DNS that is on that server.

## Asynchronous Full Transfer Zone (AXFR)

Refers to the transfer of zones to another server in DNS. 

```
realCustampin@htb[/htb]$ dig axfr inlanefreight.htb @10.129.14.128

; <<>> DiG 9.16.1-Ubuntu <<>> axfr inlanefreight.htb @10.129.14.128
;; global options: +cmd
inlanefreight.htb.      604800  IN      SOA     inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
inlanefreight.htb.      604800  IN      TXT     "MS=ms97310371"
inlanefreight.htb.      604800  IN      TXT     "atlassian-domain-verification=t1rKCy68JFszSdCKVpw64A1QksWdXuYFUeSXKU"
inlanefreight.htb.      604800  IN      TXT     "v=spf1 include:mailgun.org include:_spf.google.com include:spf.protection.outlook.com include:_spf.atlassian.net ip4:10.129.124.8 ip4:10.129.127.2 ip4:10.129.42.106 ~all"
inlanefreight.htb.      604800  IN      NS      ns.inlanefreight.htb.
app.inlanefreight.htb.  604800  IN      A       10.129.18.15
internal.inlanefreight.htb. 604800 IN   A       10.129.1.6
mail1.inlanefreight.htb. 604800 IN      A       10.129.18.201
ns.inlanefreight.htb.   604800  IN      A       10.129.34.136
inlanefreight.htb.      604800  IN      SOA     inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
;; Query time: 4 msec
;; SERVER: 10.129.14.128#53(10.129.14.128)
;; WHEN: So Sep 19 18:51:19 CEST 2021
;; XFR size: 9 records (messages 1, bytes 520)
```

```
realCustampin@htb[/htb]$ dig axfr internal.inlanefreight.htb @10.129.14.128

; <<>> DiG 9.16.1-Ubuntu <<>> axfr internal.inlanefreight.htb @10.129.14.128
;; global options: +cmd
internal.inlanefreight.htb. 604800 IN   SOA     inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
internal.inlanefreight.htb. 604800 IN   TXT     "MS=ms97310371"
internal.inlanefreight.htb. 604800 IN   TXT     "atlassian-domain-verification=t1rKCy68JFszSdCKVpw64A1QksWdXuYFUeSXKU"
internal.inlanefreight.htb. 604800 IN   TXT     "v=spf1 include:mailgun.org include:_spf.google.com include:spf.protection.outlook.com include:_spf.atlassian.net ip4:10.129.124.8 ip4:10.129.127.2 ip4:10.129.42.106 ~all"
internal.inlanefreight.htb. 604800 IN   NS      ns.inlanefreight.htb.
dc1.internal.inlanefreight.htb. 604800 IN A     10.129.34.16
dc2.internal.inlanefreight.htb. 604800 IN A     10.129.34.11
mail1.internal.inlanefreight.htb. 604800 IN A   10.129.18.200
ns.internal.inlanefreight.htb. 604800 IN A      10.129.34.136
vpn.internal.inlanefreight.htb. 604800 IN A     10.129.1.6
ws1.internal.inlanefreight.htb. 604800 IN A     10.129.1.34
ws2.internal.inlanefreight.htb. 604800 IN A     10.129.1.35
wsus.internal.inlanefreight.htb. 604800 IN A    10.129.18.2
internal.inlanefreight.htb. 604800 IN   SOA     inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
;; Query time: 0 msec
;; SERVER: 10.129.14.128#53(10.129.14.128)
;; WHEN: So Sep 19 18:53:11 CEST 2021
;; XFR size: 15 records (messages 1, bytes 664)
```


We can use a for-loop in bash to query all the domains that are a part of one of the IP Address. 
```
realCustampin@htb[/htb]$ for sub in $(cat /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.inlanefreight.htb @10.129.14.128 | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done

ns.inlanefreight.htb.   604800  IN      A       10.129.34.136
mail1.inlanefreight.htb. 604800 IN      A       10.129.18.201
app.inlanefreight.htb.  604800  IN      A       10.129.18.15
```

## Tools

DNSenum: 

```
realCustampin@htb[/htb]$ dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb

dnsenum VERSION:1.2.6

-----   inlanefreight.htb   -----


Host's addresses:
__________________



Name Servers:
______________

ns.inlanefreight.htb.                    604800   IN    A        10.129.34.136


Mail (MX) Servers:
___________________



Trying Zone Transfers and getting Bind Versions:
_________________________________________________

unresolvable name: ns.inlanefreight.htb at /usr/bin/dnsenum line 900 thread 1.

Trying Zone Transfer for inlanefreight.htb on ns.inlanefreight.htb ...
AXFR record query failed: no nameservers


Brute forcing with /home/cry0l1t3/Pentesting/SecLists/Discovery/DNS/subdomains-top1million-110000.txt:
_______________________________________________________________________________________________________

ns.inlanefreight.htb.                    604800   IN    A        10.129.34.136
mail1.inlanefreight.htb.                 604800   IN    A        10.129.18.201
app.inlanefreight.htb.                   604800   IN    A        10.129.18.15
ns.inlanefreight.htb.                    604800   IN    A        10.129.34.136

...SNIP...
done.
```

## Lab Questions

Target IP: 10.129.165.243

1. Interact with the target DNS using its IP address and enumerate the FQDN of it for the "inlanefreight.htb" domain.
	1. ns.inlanefreight.htb
2. Identify if its possible to perform a zone transfer and submit the TXT record as the answer. (Format: HTB{...})
	1. HTB{DN5_z0N3_7r4N5F3r_iskdufhcnlu34}
3. What is the IPv4 address of the hostname DC1?
	1. 10.129.34.16
4. What is the FQDN of the host where the last octet ends with "x.x.x.203"?


----------------------------------------------------------------------

## Web Recon for DNS

How does DNS Work? 
1. Starts with a DNS Query: When you enter a domain name, the computer firsts checks its memory to see if it remembers the IP from a previous visit, if it comes up short then it will most likely reach out to your ISP. 
2. The DNS Resolver Checks its map (Recursive Lookup): Resolver also has a cache, if it is not in there, then we start going through the DNS Hierarchy. Begins by asking a root name server. 
3. Root Name Server Points the Way: Root server doesn't know the exact address but knows who does - the Top-Level Domain name server responsible for the domain's ending. 
4. TLD Name Server Narrows It Down: The TLD server is like a regional map, it knows which authoritative name server is responsible for the specific domain you're looking for and sends it there. 
5. Authoritative Name Server Delivers the Address: The authoritative name server is the final stop. It's like the street address of the website you want. Holds the correct IP and sends it back to the resolver. 
6. DNS Resolver returns the Information: The resolver then receives the IP and gives it to your computer. It also remembers it for a while (Caches it) in case you want to revisit. 
7. Your Computer Connects: Now that your computer knows the IP Address, it can connect directly to the web server hosting the website, and you can start browsing. 

**The Hosts File**
- Simple text file that is used to map hostnames to IP Addresses. 
- Manual method for DNS Resolution.
- **Location:**
	- Windows: C:\Windows\System32\drivers\etc\hosts
	- Linux: /etc/hosts
Example: 
```
127.0.0.1     localhost
192.168.1.10  devserver.local
```

## Key DNS Concepts: 
- Zones: Distinct part of the domain namespace that a specific admin manages. 
	- For example: *example.com* and all of it's subdomains *mail.example.com or blog.example.com* would typically belong to the same DNS Zone. 


| DNS Concept               | Description                                                                    | Example                                                   |
| ------------------------- | ------------------------------------------------------------------------------ | --------------------------------------------------------- |
| Domain Name               | Human readable label for a webpage or other internet resource.                 | www.example.com                                           |
| IP Address                | Unique numerical identifier assigned to each device connected to the internet. | 192.168.0.1                                               |
| DNS Resolver              | Server that translates domain names into IP addresses.                         | Your ISP's DNS server or public resolvers like Google DNS |
| Root Name Server          | Top-level servers in the DNS Heirarchy                                         | There are 13 root servers worldwide                       |
| TLD Name Server           | Servers responsible for specific top-level domains                             | Verisign for .com                                         |
| Authroitative Name Server | The server that holds the actual IP Addresses for a domain.                    | Often managed by hosting providers or domain registrars.  |
## Record Types on a Deeper Note

| Record Type | Full Name                 | Description                                                                                      | Zone File Example                                                  |
| ----------- | ------------------------- | ------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------ |
| A           | Address Record            | Maps a hostname to an IP Address                                                                 | www.example.com. IN A 192.0.2.1                                    |
| AAAA        | IPv6 Address Record       | Maps a hostname to an IPv6 Address                                                               | www.example.com. IN AAAA 2001:db8:85a3::8a2e:370:7334              |
| CNAME       | Canonical Name Record     | Creates an alias for a hostname pointing it to another hostname.                                 | blog.example.com. IN CNAME webserver.example.net.                  |
| MX          | Mail Exchange Record      | Specifies the mail servers responsible for handling email for the domain.                        | example.com IN MX 10 mail.example.com.                             |
| NS          | Name Server Record        | Delegates a DNS zone to a specific authoritative name server.                                    | example.com IN NS ns1.example.com.                                 |
| TXT         | Text Record               | Stores arbitrary text information, typically used for domain verification, or security policies. | example.com. IN TXT "v=spf1 mx - all"                              |
| SOA         | Start of Authority Record | Specifies administrative information about a DNS zone.                                           | example.com. IN SOA ns1.example.com. admin.example.com. 2024060301 |
| SRV         | Service Record            | Defines the hostname and port number for specific services                                       | _sip._udp.example.com IN SRV 10 5 5060 sipserver.example.com.      |
| PTR         | Pointer Record            | Used for reverse DNS lookups, mapping an IP address to a hostname.                               | 1.2.0.192.in-addr.rapa. in PTR www.example.com                     |
The "IN" in the examples stand for Internet. This is known as the Class Field which specifies the protocol family. Most of the time you will see "IN"

## Why Does DNS Matter?

- Uncovering Assets: DNS Records can reveal a wealth of information, including subdomains, mail server, and name server records. 
- Mapping the Network Infrastructure: You can create a map of the target's network infrastructure by analyzing DNS Data. 
- Monitoring for Changes: Monitoring DNS Records can reveal changes in the target's infrastructure over time. Sudden appearance of a TXT record containing a value like 1password=.. strongly suggests that the company is using 1Password. 


## Tools Used for Digging

