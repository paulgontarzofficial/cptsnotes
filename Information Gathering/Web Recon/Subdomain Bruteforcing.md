
- leverages pre-defined lists of subdomain names. 

## Process
1. Wordlist Selection: Selecting a wordlist containing potential subdomain names. These wordlists can be:
	1. General Purpose: Containing a broad range of common subdomain names (dev, mail, blog, staging, etc)
	2. Targeted: Focused on specific industries, technologies, or naming patterns
	3. Custom: You can create your own wordlist based on specific keywords or patterns
2. Iteration and Querying: Script or tool that iterates through the wordlists, appending each word or phrase to the main
3. DNS Lookup: DNS query is performed for each potential subdomain to check if it resolves to an IP address. Typically done with A or AAAA records. 
4. Filtering and Validation: If a subdomain resolves successfully, it's added to a list of valid subdomains. 

## Tools
| Tool                                                    | Description                                                                                                                     |
| ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| [dnsenum](https://github.com/fwaeytens/dnsenum)         | Comprehensive DNS enumeration tool that supports dictionary and brute-force attacks for discovering subdomains.                 |
| [fierce](https://github.com/mschwager/fierce)           | User-friendly tool for recursive subdomain discovery, featuring wildcard detection and an easy-to-use interface.                |
| [dnsrecon](https://github.com/darkoperator/dnsrecon)    | Versatile tool that combines multiple DNS reconnaissance techniques and offers customisable output formats.                     |
| [amass](https://github.com/owasp-amass/amass)           | Actively maintained tool focused on subdomain discovery, known for its integration with other tools and extensive data sources. |
| [assetfinder](https://github.com/tomnomnom/assetfinder) | Simple yet effective tool for finding subdomains using various techniques, ideal for quick and lightweight scans.               |
| [puredns](https://github.com/d3mondev/puredns)          | Powerful and flexible DNS brute-forcing tool, capable of resolving and filtering results effectively.                           |

**DNSenum**
`dnsenum` is a versatile and widely-used command-line tool written in Perl. It is a comprehensive toolkit for DNS reconnaissance, providing various functionalities to gather information about a target domain's DNS infrastructure and potential subdomains. The tool offers several key functions:

- `DNS Record Enumeration`: `dnsenum` can retrieve various DNS records, including A, AAAA, NS, MX, and TXT records, providing a comprehensive overview of the target's DNS configuration.
- `Zone Transfer Attempts`: The tool automatically attempts zone transfers from discovered name servers. While most servers are configured to prevent unauthorised zone transfers, a successful attempt can reveal a treasure trove of DNS information.
- `Subdomain Brute-Forcing`: `dnsenum` supports brute-force enumeration of subdomains using a wordlist. This involves systematically testing potential subdomain names against the target domain to identify valid ones.
- `Google Scraping`: The tool can scrape Google search results to find additional subdomains that might not be listed in DNS records directly.
- `Reverse Lookup`: `dnsenum` can perform reverse DNS lookups to identify domains associated with a given IP address, potentially revealing other websites hosted on the same server.
- `WHOIS Lookups`: The tool can also perform WHOIS queries to gather information about domain ownership and registration details.

Example: 
```bash
dnsenum --enum inlanefreight.com -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -r
```
- Specify the the target inlanefreight.com and tune with the --enum command
- The we specify a wordlist to use /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
- -r recursive means that once a subdomain is found, it will try to find a subdomain of that subdomain. 

```shell-session
realCustampin@htb[/htb]$ dnsenum --enum inlanefreight.com -f  /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt 

dnsenum VERSION:1.2.6

-----   inlanefreight.com   -----


Host's addresses:
__________________

inlanefreight.com.                       300      IN    A        134.209.24.248

[...]

Brute forcing with /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt:
_______________________________________________________________________________________

www.inlanefreight.com.                   300      IN    A        134.209.24.248
support.inlanefreight.com.               300      IN    A        134.209.24.248
[...]


done.
```

## Lab Questions: 

1. Using the known subdomains for inlanefreight.com (www, ns1, ns2, ns3, blog, support, customer), find any missing subdomains by brute-forcing possible domain names. Provide your answer with the complete subdomain, e.g., www.inlanefreight.com.
	1. my.inlanefreight.com.