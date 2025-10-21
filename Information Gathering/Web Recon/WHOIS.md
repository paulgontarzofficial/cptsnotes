
- Widely used query that is used to access databases that store information about registered internet resources. 
- The giant phonebook for the internet. 
**WHOIS Command in Use:**
```
realCustampin@htb[/htb]$ whois inlanefreight.com

[...]
Domain Name: inlanefreight.com
Registry Domain ID: 2420436757_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.registrar.amazon
Registrar URL: https://registrar.amazon.com
Updated Date: 2023-07-03T01:11:15Z
Creation Date: 2019-08-05T22:43:09Z
[...]
```


**Information Provided by WHOIS:**
- `Domain Name`: The domain name itself (e.g., example.com)
- `Registrar`: The company where the domain was registered (e.g., GoDaddy, Namecheap)
- `Registrant Contact`: The person or organization that registered the domain.
- `Administrative Contact`: The person responsible for managing the domain.
- `Technical Contact`: The person handling technical issues related to the domain.
- `Creation and Expiration Dates`: When the domain was registered and when it's set to expire.
- `Name Servers`: Servers that translate the domain name into an IP address.

## Why Does WHOIS Matter? 

- Identifies Key Personnel: Often retains names, email addresses, and phone numbers of individuals responsible for managing the domain. 
- Discovering Network Infrastructure: Technical details like name servers and IP Addresses provide clues about target's network infrastructure. 
- Historical Data Analysis: WhoIsFreaks shows us the previous WHOIS records the reveal previous ownerships, contact information, or technical details over time. 
## Utilizing WHOIS

**Phishing Investigation:**
- Imagine that you receive an email that states that it is from a bank and needs you to click on a link urgently to update banking information. One quick look using WHOIS can identify the Registration Date, Registrant, or Name Servers that are being used. 

**Malware Analysis:**
- Analysis of malware indicates that multiple systems are being infected and we now know that files are being sent to a C2 Server. We can utilize WHOIS and the C2 Domain to gather information such as the Registrant, Location, Registrar. 

**Threat Intelligence Report:**
- Tracking the activity of a sophisticated threat actor, analysts gather WHOIS data on multiple domains associated with the group's past campaigns to compile a comprehensive threat intelligence report. 
	- Registration Date: Domains were registered in clusters, often shortly before a major attack
	- Registrants: Use various aliases and Fake ID's 
	- Name Servers: The domains often share the same name servers, suggesting a common infrastructure. 
	- Takedown History: Many domains have been taken don after attacks, indicating previous law enforcement or security interventions. 

## Using WHOIS

**Installation:**

```
realCustampin@htb[/htb]$ sudo apt update
realCustampin@htb[/htb]$ sudo apt install whois -y
```

**Utilizing WHOIS against facebook.com:**
```
realCustampin@htb[/htb]$ whois facebook.com

   Domain Name: FACEBOOK.COM
   Registry Domain ID: 2320948_DOMAIN_COM-VRSN
   Registrar WHOIS Server: whois.registrarsafe.com
   Registrar URL: http://www.registrarsafe.com
   Updated Date: 2024-04-24T19:06:12Z
   Creation Date: 1997-03-29T05:00:00Z
   Registry Expiry Date: 2033-03-30T04:00:00Z
   Registrar: RegistrarSafe, LLC
   Registrar IANA ID: 3237
   Registrar Abuse Contact Email: abusecomplaints@registrarsafe.com
   Registrar Abuse Contact Phone: +1-650-308-7004
   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
   Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
   Domain Status: serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited
   Domain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited
   Domain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited
   Name Server: A.NS.FACEBOOK.COM
   Name Server: B.NS.FACEBOOK.COM
   Name Server: C.NS.FACEBOOK.COM
   Name Server: D.NS.FACEBOOK.COM
   DNSSEC: unsigned
   URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
>>> Last update of whois database: 2024-06-01T11:24:10Z <<<

[...]
Registry Registrant ID:
Registrant Name: Domain Admin
Registrant Organization: Meta Platforms, Inc.
[...]
```

We can see that we got some key details, let's break it down: 

- Domain Registration:
	- `Registrar`: RegistrarSafe, LLC
	- `Creation Date`: 1997-03-29
	- `Expiry Date`: 2033-03-30
- Domain Owner: 
	- `Registrant/Admin/Tech Organization`: Meta Platforms, Inc.
	- `Registrant/Admin/Tech Contact`: Domain Admin
- Domain Status: 
	- `clientDeleteProhibited`, `clientTransferProhibited`, `clientUpdateProhibited`, `serverDeleteProhibited`, `serverTransferProhibited`, and `serverUpdateProhibited`
- Name Servers: 
	- `A.NS.FACEBOOK.COM`, `B.NS.FACEBOOK.COM`, `C.NS.FACEBOOK.COM`, `D.NS.FACEBOOK.COM`

## !!!Complete the Labs!!!

1. Perform a WHOIS lookup against the paypal.com domain. What is the registrar Internet Assigned Numbers Authority (IANA) ID number?
	1. 292
2. What is the admin email contact for the tesla.com domain (also in-scope for the Tesla bug bounty program)?
	1. admin@dnstinations.com
