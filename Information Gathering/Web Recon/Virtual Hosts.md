- Once DNS directs traffic to the correct server, it is up to the web configuration to determine how that traffic is handled. 
- Web Servers like Apache, nginx, and IIS all are able to host multiple websites or applications using one server. This is all because of Virtual Hosts

## Understanding VHosts and Subdomains

- **Subdomains:**
	- Extensions of a main domain name
	- Have their own DNS Record
- **Virtual Hosts:**
	- Configured within the web server that allow multiple websites or applications to be hosted on a single server. 
	- Each VHost has it's own seperate configuration.
	- If the Virtual Host does not have a current DNS entry, you can always add it to your hosts file on the machine. 

```apacheconf
# Example of name-based virtual host configuration in Apache
<VirtualHost *:80>
    ServerName www.example1.com
    DocumentRoot /var/www/example1
</VirtualHost>

<VirtualHost *:80>
    ServerName www.example2.org
    DocumentRoot /var/www/example2
</VirtualHost>

<VirtualHost *:80>
    ServerName www.another-example.net
    DocumentRoot /var/www/another-example
</VirtualHost>
```

## Server VHost Lookup

![[Pasted image 20251021092719.png]]
1. Browser requests a website: Initiates an HTTP request
2. Host header reveals the domain: Browser includes the domain name in the request's header.
3. Web server determines the virtual host: Web server receives the request examines the Host header, consults with the VHost config file to find matching entry for the requested domain name. 
4. Serving the right content: Identifying the correct Vhost config, the web server then retrieves the proper files and resources associated with that website from it's document root. 

## Types of Virtual Hosting
1. `Name-Based Virtual Hosting`: This method relies solely on the `HTTP Host header` to distinguish between websites. It is the most common and flexible method, as it doesn't require multiple IP addresses. It’s cost-effective, easy to set up, and supports most modern web servers. However, it requires the web server to support name-based `virtual hosting` and can have limitations with certain protocols like `SSL/TLS`.
2. `IP-Based Virtual Hosting`: This type of hosting assigns a unique IP address to each website hosted on the server. The server determines which website to serve based on the IP address to which the request was sent. It doesn't rely on the `Host header`, can be used with any protocol, and offers better isolation between websites. Still, it requires multiple IP addresses, which can be expensive and less scalable.
3. `Port-Based Virtual Hosting`: Different websites are associated with different ports on the same IP address. For example, one website might be accessible on port 80, while another is on port 8080. `Port-based virtual hosting` can be used when IP addresses are limited, but it’s not as common or user-friendly as `name-based virtual hosting` and might require users to specify the port number in the URL.

## Tools

| Tool                                                 | Description                                                                                                      | Features                                                        |
| ---------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| [gobuster](https://github.com/OJ/gobuster)           | A multi-purpose tool often used for directory/file brute-forcing, but also effective for virtual host discovery. | Fast, supports multiple HTTP methods, can use custom wordlists. |
| [Feroxbuster](https://github.com/epi052/feroxbuster) | Similar to Gobuster, but with a Rust-based implementation, known for its speed and flexibility.                  | Supports recursion, wildcard discovery, and various filters.    |
| [ffuf](https://github.com/ffuf/ffuf)                 | Another fast web fuzzer that can be used for virtual host discovery by fuzzing the `Host` header.                | Customizable wordlist input and filtering options.              |

**gobuster**
- Sends HTTP requests with different Host headers to the target ip address and then analyses the response to identify valid VHosts. 
- Items needed to brute-force Host headers:
	- Target Identification: First, identify the target web server's IP address. **nslookup**
	- Wordlist Preparation: Prepare a wordlist containing potential virtual host names. You can use a pre-compiled wordlist, such as Seclists, or a custom one based on your target's industry. 

**VHost Brute Force Example:**
```shell-session
realCustampin@htb[/htb]$ gobuster vhost -u http://<target_IP_address> -w <wordlist_file> --append-domain
```

- The -u flag specifies the target URL
- The -w flag specifies the wordlist file
- the --append-domain appends the base domain to each word in the wordlist

**Full Example:**

```shell-session
realCustampin@htb[/htb]$ gobuster vhost -u http://inlanefreight.htb:81 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://inlanefreight.htb:81
[+] Method:          GET
[+] Threads:         10
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: forum.inlanefreight.htb:81 Status: 200 [Size: 100]
[...]
Progress: 114441 / 114442 (100.00%)
===============================================================
Finished
===============================================================
```

## Lab Questions: 

Target IP: 94.237.61.88:42429
vHosts Needed: inlanefreight.htb
- Add to hosts file
1. Brute-force vhosts on the target system. What is the full subdomain that is prefixed with "web"? Answer using the full domain, e.g. "x.inlanefreight.htb"
	1. web17611.inlanefreight.htb
2. Brute-force vhosts on the target system. What is the full subdomain that is prefixed with "vm"? Answer using the full domain, e.g. "x.inlanefreight.htb"
	1. vm5.inlanefreight.htb
3. Brute-force vhosts on the target system. What is the full subdomain that is prefixed with "br"? Answer using the full domain, e.g. "x.inlanefreight.htb"
	1. browse.inlanefreight.htb
4. Brute-force vhosts on the target system. What is the full subdomain that is prefixed with "a"? Answer using the full domain, e.g. "x.inlanefreight.htb"
	1. admin.inlanefreight.htb
5. Brute-force vhosts on the target system. What is the full subdomain that is prefixed with "su"? Answer using the full domain, e.g. "x.inlanefreight.htb"
	1. support.inlanefreight.htb

