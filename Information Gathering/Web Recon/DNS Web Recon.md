
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

| Tool                         | Key Features                                                                                            | Use Cases                                                                                                                               |
| ---------------------------- | ------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `dig`                        | Versatile DNS lookup tool that supports various query types (A, MX, NS, TXT, etc.) and detailed output. | Manual DNS queries, zone transfers (if allowed), troubleshooting DNS issues, and in-depth analysis of DNS records.                      |
| `nslookup`                   | Simpler DNS lookup tool, primarily for A, AAAA, and MX records.                                         | Basic DNS queries, quick checks of domain resolution and mail server records.                                                           |
| `host`                       | Streamlined DNS lookup tool with concise output.                                                        | Quick checks of A, AAAA, and MX records.                                                                                                |
| `dnsenum`                    | Automated DNS enumeration tool, dictionary attacks, brute-forcing, zone transfers (if allowed).         | Discovering subdomains and gathering DNS information efficiently.                                                                       |
| `fierce`                     | DNS reconnaissance and subdomain enumeration tool with recursive search and wildcard detection.         | User-friendly interface for DNS reconnaissance, identifying subdomains and potential targets.                                           |
| `dnsrecon`                   | Combines multiple DNS reconnaissance techniques and supports various output formats.                    | Comprehensive DNS enumeration, identifying subdomains, and gathering DNS records for further analysis.                                  |
| `theHarvester`               | OSINT tool that gathers information from various sources, including DNS records (email addresses).      | Collecting email addresses, employee information, and other data associated with a domain from multiple sources.                        |
| `Online DNS Lookup Services` | User-friendly interfaces for performing DNS lookups.                                                    | Quick and easy DNS lookups, convenient when command-line tools are not available, checking for domain availability or basic information |
## Domain Information Groper (dig)

- Utility used for gathering querying DNS server and retrieving various types of DNS Records. 
**Examples:**

| Command                         | Description                                                                                                                                                                                          |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `dig domain.com`                | Performs a default A record lookup for the domain.                                                                                                                                                   |
| `dig domain.com A`              | Retrieves the IPv4 address (A record) associated with the domain.                                                                                                                                    |
| `dig domain.com AAAA`           | Retrieves the IPv6 address (AAAA record) associated with the domain.                                                                                                                                 |
| `dig domain.com MX`             | Finds the mail servers (MX records) responsible for the domain.                                                                                                                                      |
| `dig domain.com NS`             | Identifies the authoritative name servers for the domain.                                                                                                                                            |
| `dig domain.com TXT`            | Retrieves any TXT records associated with the domain.                                                                                                                                                |
| `dig domain.com CNAME`          | Retrieves the canonical name (CNAME) record for the domain.                                                                                                                                          |
| `dig domain.com SOA`            | Retrieves the start of authority (SOA) record for the domain.                                                                                                                                        |
| `dig @1.1.1.1 domain.com`       | Specifies a specific name server to query; in this case 1.1.1.1                                                                                                                                      |
| `dig +trace domain.com`         | Shows the full path of DNS resolution.                                                                                                                                                               |
| `dig -x 192.168.1.1`            | Performs a reverse lookup on the IP address 192.168.1.1 to find the associated host name. You may need to specify a name server.                                                                     |
| `dig +short domain.com`         | Provides a short, concise answer to the query.                                                                                                                                                       |
| `dig +noall +answer domain.com` | Displays only the answer section of the query output.                                                                                                                                                |
| `dig domain.com ANY`            | Retrieves all available DNS records for the domain (Note: Many DNS servers ignore `ANY` queries to reduce load and prevent abuse, as per [RFC 8482](https://datatracker.ietf.org/doc/html/rfc8482)). |
- One thing to note is that some servers and firewalls can detect excessive DNS queries and can block them. Respect rate limits!

Let's put dig into use: 

```shell-session
realCustampin@htb[/htb]$ dig google.com

; <<>> DiG 9.18.24-0ubuntu0.22.04.1-Ubuntu <<>> google.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 16449
;; flags: qr rd ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
;; WARNING: recursion requested but not available

;; QUESTION SECTION:
;google.com.                    IN      A

;; ANSWER SECTION:
google.com.             0       IN      A       142.251.47.142

;; Query time: 0 msec
;; SERVER: 172.23.176.1#53(172.23.176.1) (UDP)
;; WHEN: Thu Jun 13 10:45:58 SAST 2024
;; MSG SIZE  rcvd: 54
```

A dig output can be broken down into four different sections: 
1. Header
2. Question Section
3. Answer Section 
4. Footer

## Lab Questions
1. Which IP address maps to inlanefreight.com?
	1. 134.209.24.248
2. Which domain is returned when querying the PTR record for 134.209.24.248?
	1. inlanefreight.com
3. What is the full domain returned when you query the mail records for facebook.com?
	1. smtpin.vvv.facebook.com
