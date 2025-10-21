
The extraction of technical details about the technologies powering a website or web application.  

- `Targeted Attacks`: By knowing the specific technologies in use, attackers can focus their efforts on exploits and vulnerabilities that are known to affect those systems. This significantly increases the chances of a successful compromise.
- `Identifying Misconfigurations`: Fingerprinting can expose misconfigured or outdated software, default settings, or other weaknesses that might not be apparent through other reconnaissance methods.
- `Prioritising Targets`: When faced with multiple potential targets, fingerprinting helps prioritise efforts by identifying systems more likely to be vulnerable or hold valuable information.
- `Building a Comprehensive Profile`: Combining fingerprint data with other reconnaissance findings creates a holistic view of the target's infrastructure, aiding in understanding its overall security posture and potential attack vectors.

## Footprinting Techniques

- `Banner Grabbing`: Banner grabbing involves analysing the banners presented by web servers and other services. These banners often reveal the server software, version numbers, and other details.
- `Analysing HTTP Headers`: HTTP headers transmitted with every web page request and response contain a wealth of information. The `Server` header typically discloses the web server software, while the `X-Powered-By` header might reveal additional technologies like scripting languages or frameworks.
- `Probing for Specific Responses`: Sending specially crafted requests to the target can elicit unique responses that reveal specific technologies or versions. For example, certain error messages or behaviours are characteristic of particular web servers or software components.
- `Analysing Page Content`: A web page's content, including its structure, scripts, and other elements, can often provide clues about the underlying technologies. There may be a copyright header that indicates specific software being used, for example.

## Tools

| Tool         | Description                                                                                                           | Features                                                                                            |
| ------------ | --------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `Wappalyzer` | Browser extension and online service for website technology profiling.                                                | Identifies a wide range of web technologies, including CMSs, frameworks, analytics tools, and more. |
| `BuiltWith`  | Web technology profiler that provides detailed reports on a website's technology stack.                               | Offers both free and paid plans with varying levels of detail.                                      |
| `WhatWeb`    | Command-line tool for website fingerprinting.                                                                         | Uses a vast database of signatures to identify various web technologies.                            |
| `Nmap`       | Versatile network scanner that can be used for various reconnaissance tasks, including service and OS fingerprinting. | Can be used with scripts (NSE) to perform more specialised fingerprinting.                          |
| `Netcraft`   | Offers a range of web security services, including website fingerprinting and security reporting.                     | Provides detailed reports on a website's technology, hosting provider, and security posture.        |
| `wafw00f`    | Command-line tool specifically designed for identifying Web Application Firewalls (WAFs).                             | Helps determine if a WAF is present and, if so, its type and configuration.                         |

## Banner Grabbing

```shell-session
realCustampin@htb[/htb]$ curl -I inlanefreight.com

HTTP/1.1 301 Moved Permanently
Date: Fri, 31 May 2024 12:07:44 GMT
Server: Apache/2.4.41 (Ubuntu)
Location: https://inlanefreight.com/
Content-Type: text/html; charset=iso-8859-1
```
- Using the -I argument, we are able to pull the HTTP Headers and not the entire page. 
- We can see that it is trying to redirect us to https://inlanefreight.com, let's curl that as well. 

```shell-session
realCustampin@htb[/htb]$ curl -I https://inlanefreight.com

HTTP/1.1 301 Moved Permanently
Date: Fri, 31 May 2024 12:12:12 GMT
Server: Apache/2.4.41 (Ubuntu)
X-Redirect-By: WordPress
Location: https://www.inlanefreight.com/
Content-Type: text/html; charset=UTF-8
```
- We can see that we have a server that is running WordPress. 
- Now we can see another redirection to https://www.inlanefreight.com, let's curl that as well. 

```shell-session
realCustampin@htb[/htb]$ curl -I https://www.inlanefreight.com

HTTP/1.1 200 OK
Date: Fri, 31 May 2024 12:12:26 GMT
Server: Apache/2.4.41 (Ubuntu)
Link: <https://www.inlanefreight.com/index.php/wp-json/>; rel="https://api.w.org/"
Link: <https://www.inlanefreight.com/index.php/wp-json/wp/v2/pages/7>; rel="alternate"; type="application/json"
Link: <https://www.inlanefreight.com/>; rel=shortlink
Content-Type: text/html; charset=UTF-8
```
- We can see that we get a wp-json file, common wordpress file. 


## Web Application Firewalls

**Wafw00f**

Installation:
```shell-session
realCustampin@htb[/htb]$ pip3 install git+https://github.com/EnableSecurity/wafw00f
```

Usage:
```shell-session
realCustampin@htb[/htb]$ wafw00f inlanefreight.com

                ______
               /      \
              (  W00f! )
               \  ____/
               ,,    __            404 Hack Not Found
           |`-.__   / /                      __     __
           /"  _/  /_/                       \ \   / /
          *===*    /                          \ \_/ /  405 Not Allowed
         /     )__//                           \   /
    /|  /     /---`                        403 Forbidden
    \\/`   \ |                                 / _ \
    `\    /_\\_              502 Bad Gateway  / / \ \  500 Internal Error
      `_____``-`                             /_/   \_\

                        ~ WAFW00F : v2.2.0 ~
        The Web Application Firewall Fingerprinting Toolkit
    
[*] Checking https://inlanefreight.com
[+] The site https://inlanefreight.com is behind Wordfence (Defiant) WAF.
[~] Number of requests: 2
```
- From the scan, we can see that the website is currently sitting behind Wordfence WAF. 
- This site has additional security in front of it.

## Nikto 

- Powerful open source web server scanner. Used for web fingerprinting. 

Installation: 
```shell-session
realCustampin@htb[/htb]$ sudo apt update && sudo apt install -y perl
realCustampin@htb[/htb]$ git clone https://github.com/sullo/nikto
realCustampin@htb[/htb]$ cd nikto/program
realCustampin@htb[/htb]$ chmod +x ./nikto.pl
```

Usage: 
```shell-session
realCustampin@htb[/htb]$ nikto -h inlanefreight.com -Tuning b
```
- The -h flag specifies the target (host)
- The -Tuning b flag tells Nikto to only run Software Identification Modules. 

```shell-session
realCustampin@htb[/htb]$ nikto -h inlanefreight.com -Tuning b

- Nikto v2.5.0
---------------------------------------------------------------------------
+ Multiple IPs found: 134.209.24.248, 2a03:b0c0:1:e0::32c:b001
+ Target IP:          134.209.24.248
+ Target Hostname:    www.inlanefreight.com
+ Target Port:        443
---------------------------------------------------------------------------
+ SSL Info:        Subject:  /CN=inlanefreight.com
                   Altnames: inlanefreight.com, www.inlanefreight.com
                   Ciphers:  TLS_AES_256_GCM_SHA384
                   Issuer:   /C=US/O=Let's Encrypt/CN=R3
+ Start Time:         2024-05-31 13:35:54 (GMT0)
---------------------------------------------------------------------------
+ Server: Apache/2.4.41 (Ubuntu)
+ /: Link header found with value: ARRAY(0x558e78790248). See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Link
+ /: The site uses TLS and the Strict-Transport-Security HTTP header is not defined. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ /index.php?: Uncommon header 'x-redirect-by' found, with contents: WordPress.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /: The Content-Encoding header is set to "deflate" which may mean that the server is vulnerable to the BREACH attack. See: http://breachattack.com/
+ Apache/2.4.41 appears to be outdated (current is at least 2.4.59). Apache 2.2.34 is the EOL for the 2.x branch.
+ /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
+ /license.txt: License file found may identify site software.
+ /: A Wordpress installation was found.
+ /wp-login.php?action=register: Cookie wordpress_test_cookie created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ /wp-login.php:X-Frame-Options header is deprecated and has been replaced with the Content-Security-Policy HTTP header with the frame-ancestors directive instead. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /wp-login.php: Wordpress login found.
+ 1316 requests: 0 error(s) and 12 item(s) reported on remote host
+ End Time:           2024-05-31 13:47:27 (GMT0) (693 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```
The following is a breakdown of the Nikto scan: 

- `IPs`: The website resolves to both IPv4 (`134.209.24.248`) and IPv6 (`2a03:b0c0:1:e0::32c:b001`) addresses.
- `Server Technology`: The website runs on `Apache/2.4.41 (Ubuntu)`
- `WordPress Presence`: The scan identified a WordPress installation, including the login page (`/wp-login.php`). This suggests the site might be a potential target for common WordPress-related exploits.
- `Information Disclosure`: The presence of a `license.txt` file could reveal additional details about the website's software components.
- `Headers`: Several non-standard or insecure headers were found, including a missing `Strict-Transport-Security` header and a potentially insecure `x-redirect-by` header.

## Lab Questions:


Target IP: 10.129.54.222
vHosts Needed: app.inlanefreight.local dev.inlanefreight.local
1. Determine the Apache version running on app.inlanefreight.local on the target system. (Format: 0.0.0)
	1. 2.4.41
2. Which CMS is used on app.inlanefreight.local on the target system? Respond with the name only, e.g., WordPress.
	1. Joomla
3. On which operating system is the dev.inlanefreight.local webserver running in the target system? Respond with the name only, e.g., Debian.
	1. Ubuntu