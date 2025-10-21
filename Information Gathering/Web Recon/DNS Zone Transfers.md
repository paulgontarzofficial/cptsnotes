
![[Pasted image 20251021075830.png]]

**Breakdown:**

1. Zone Transfer Request (AXFR): Secondary DNS server initiates the process by sedning a zone transfer request to the primary server.  
2. SOA Record Transfer: Upon receiving the request, primary server then sends the Start of Authority (SOA) Record that contains **VITAL INFORMATION** about the zone, including the serial number.
3. DNS Records Transmission: Primary server then transfers all the DNS records in the zone to the secodnary server one by one. **ALL RECORDS**
4. Zone Transfer Complete: Once all records have been transmitted, the primary server then signals the end of the zone transfer. 
5. Acknowledgement: Secondary server sends an ACK message to the primary server, confirming the successful receipt. 

## Zone Transfer Vulnerability
- In earlier times, any client was able to ask a DNS server for a zone transfer. Essentially meaning that a malicious actor could ask for a complete copy of their DNS Zone. 

## Exploiting Zone Transfers

- Main goal here is to generate an axfr query  

```shell-session
realCustampin@htb[/htb]$ dig axfr @nsztm1.digi.ninja zonetransfer.me
```

## Lab Questions: 

Target IP: 10.129.186.248

1. After performing a zone transfer for the domain inlanefreight.htb on the target system, how many DNS records are retrieved from the target system's name server? Provide your answer as an integer, e.g, 123.
	1. 22
2. Within the zone record transferred above, find the ip address for ftp.admin.inlanefreight.htb. Respond only with the IP address, eg 127.0.0.1
	1. 10.10.34.2
3. Within the same zone record, identify the largest IP address allocated within the 10.10.200 IP range. Respond with the full IP address, eg 10.10.200.1
	1. 10.10.200.14