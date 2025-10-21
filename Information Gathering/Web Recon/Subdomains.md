
- In previous modules when looking at domains we have only focused on the main domain (example.com) what about blog.example.com or mail.example.com. We should probably be taking a look at those subdomains as well. 

## Why look at subdomains?

- Development and staging areas: Companies often use subdomains to test apps and other features in an isolated environment.
- Hidden Login Portals: Might host admin pages not meant to be publicly accessible 
- Legacy Applications: Older, forgotten applications might reside on subdomains
- Sensitive Information: Subdomains can inadvertently expose confidential documents

## Subdomain Enumeration

**Active Subdomain Enumeration:**
- Involves directly interacting with the target domain's DNS servers. 
	- Example would be attempting a DNS Zone Transfer
- Active Techniques are usually brute-force enumeration
	- dnsenum, ffuf, gobuster

**Passive Subdomain Enumeration:**
- Relies on external sources of information to discover subdomains without directly querying the target's DNS servers. 
	- Certificate Transparency Logs, google dorking, online databases

