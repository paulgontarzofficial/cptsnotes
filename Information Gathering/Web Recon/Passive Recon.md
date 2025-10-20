- Passive Recon involves information gathering about the target without directly interacting with it. 
- The following are techniques and forms of passive recon. 

|Technique|Description|Example|Tools|Risk of Detection|
|---|---|---|---|---|
|`Search Engine Queries`|Utilising search engines to uncover information about the target, including websites, social media profiles, and news articles.|Searching Google for "`[Target Name] employees`" to find employee information or social media profiles.|Google, DuckDuckGo, Bing, and specialised search engines (e.g., Shodan)|Very Low: Search engine queries are normal internet activity and unlikely to trigger alerts.|
|`WHOIS Lookups`|Querying WHOIS databases to retrieve domain registration details.|Performing a WHOIS lookup on a target domain to find the registrant's name, contact information, and name servers.|whois command-line tool, online WHOIS lookup services|Very Low: WHOIS queries are legitimate and do not raise suspicion.|
|`DNS`|Analysing DNS records to identify subdomains, mail servers, and other infrastructure.|Using `dig` to enumerate subdomains of a target domain.|dig, nslookup, host, dnsenum, fierce, dnsrecon|Very Low: DNS queries are essential for internet browsing and are not typically flagged as suspicious.|
|`Web Archive Analysis`|Examining historical snapshots of the target's website to identify changes, vulnerabilities, or hidden information.|Using the Wayback Machine to view past versions of a target website to see how it has changed over time.|Wayback Machine|Very Low: Accessing archived versions of websites is a normal activity.|
|`Social Media Analysis`|Gathering information from social media platforms like LinkedIn, Twitter, or Facebook.|Searching LinkedIn for employees of a target organisation to learn about their roles, responsibilities, and potential social engineering targets.|LinkedIn, Twitter, Facebook, specialised OSINT tools|Very Low: Accessing public social media profiles is not considered intrusive.|
|`Code Repositories`|Analysing publicly accessible code repositories like GitHub for exposed credentials or vulnerabilities.|Searching GitHub for code snippets or repositories related to the target that might contain sensitive information or code vulnerabilities.|GitHub, GitLab|Very Low: Code repositories are meant for public access, and searching them is not suspicious.|

- This form of recon is a lot more stealthy as this is all public information, which typically do not trigger any alarms. 
- However may yield less comprehensive information. 