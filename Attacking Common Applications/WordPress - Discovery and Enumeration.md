- WordPress was launched in 2003 and is an open-source Content Management System (CMS) that can be used for multiple purposes. 
- WordPress accounts for around 32.5% of all sites on the internet and is the most popular CMS by market share. 

The [Hacking WordPress](https://academy.hackthebox.com/course/preview/hacking-wordpress) module on HTB Academy goes very far in-depth on the structure and function of WordPress and ways it can be abused.

### Discovery / Footprinting 
- One quick way to see if we are dealing with a WordPress install is looking at the /robots.txt file. 

```shell-session
User-agent: *
Disallow: /wp-admin/
Allow: /wp-admin/admin-ajax.php
Disallow: /wp-content/uploads/wpforms/

Sitemap: https://inlanefreight.local/wp-sitemap.xml
```

- We can see that there is a /wp-admin and /wp-content which tells us that wordpress is present. 

**Types of Users in WordPress**
1. Administrator: This user has access to administrative features within the website. This includes adding and deleting users and posts, as well as editing source code.
2. Editor: An editor can publish and manage posts, including the posts of other users.
3. Author: They can publish and manage their own posts.
4. Contributor: These users can write and manage their own posts but cannot publish them.
5. Subscriber: These are standard users who can browse posts and edit their profiles.

### Enumeration 
- Using a simple curl request of the webpage and grepping for 'wordpress' can also tell us some good information. 

```shell-session
realCustampin@htb[/htb]$ curl -s http://blog.inlanefreight.local | grep WordPress

<meta name="generator" content="WordPress 5.8" /
```

We should also look at the wp-content directory, themes and plugins which we can then build a list of interesting data points. 

```shell-session
realCustampin@htb[/htb]$ curl -s http://blog.inlanefreight.local/ | grep themes

<link rel='stylesheet' id='bootstrap-css'  href='http://blog.inlanefreight.local/wp-content/themes/business-gravity/assets/vendors/bootstrap/css/bootstrap.min.css' type='text/css' media='all' />
```
- As we can see, the theme that is in use is the business-gravity theme. 

```shell-session
realCustampin@htb[/htb]$ curl -s http://blog.inlanefreight.local/ | grep plugins

<link rel='stylesheet' id='contact-form-7-css'  href='http://blog.inlanefreight.local/wp-content/plugins/contact-form-7/includes/css/styles.css?ver=5.4.2' type='text/css' media='all' />
<script type='text/javascript' src='http://blog.inlanefreight.local/wp-content/plugins/mail-masta/lib/subscriber.js?ver=5.8' id='subscriber-js-js'></script>
<script type='text/javascript' src='http://blog.inlanefreight.local/wp-content/plugins/mail-masta/lib/jquery.validationEngine-en.js?ver=5.8' id='validation-engine-en-js'></script>
<script type='text/javascript' src='http://blog.inlanefreight.local/wp-content/plugins/mail-masta/lib/jquery.validationEngine.js?ver=5.8' id='validation-engine-js'></script>
		<link rel='stylesheet' id='mm_frontend-css'  href='http://blog.inlanefreight.local/wp-content/plugins/mail-masta/lib/css/mm_frontend.css?ver=5.8' type='text/css' media='all' />
<script type='text/javascript' src='http://blog.inlanefreight.local/wp-content/plugins/contact-form-7/includes/js/index.js?ver=5.4.2' id='contact-form-7-js'></script>
```
- Next we are grepping for plugins and we can see that Contact Form 7 and mail-masta plugins are installed. 
- Now we can enumerate the versions of the plugins. 
- Browsing to `http://blog.inlanefreight.local/wp-content/plugins/mail-masta/` shows us that directory listing is enabled and that a readme.txt file is present. 

We can search for other plugins and we can find the wpDiscuz plugin is installed and it appears to be version 7.0.4. 

```shell-session
realCustampin@htb[/htb]$ curl -s http://blog.inlanefreight.local/?p=1 | grep plugins

<link rel='stylesheet' id='contact-form-7-css'  href='http://blog.inlanefreight.local/wp-content/plugins/contact-form-7/includes/css/styles.css?ver=5.4.2' type='text/css' media='all' />
<link rel='stylesheet' id='wpdiscuz-frontend-css-css'  href='http://blog.inlanefreight.local/wp-content/plugins/wpdiscuz/themes/default/style.css?ver=7.0.4' type='text/css' media='all' />
```
- Using google, we can do a quick search and find that there is an RCE vulnerability that is published in June 2021 that we can use. 

### Enumerating Users
- We can do some manual enumeration by using the /wp-login.php login portal. 

![WordPress login page with error message: 'The password for username admin is incorrect.'](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/113/valid_user.png)
- If there are valid usernames, we can see this error message above. 

![WordPress login page with error message: 'The username someone is not registered on this site.'](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/113/invalid_user.png)
- However, if we enter a username that does not exist, then we get the error above. 
- Notice the difference in a Valid and Invalid user. 

Now let us try to automate the process of gathering some information now that we have key data points. 

### WPScan
- This application is used for automating fingerprinting/enumeration of a wordpress application. 
- The --enumerate flag is used to enumerate various components of the WordPress application, such as plugins, themes, and users. WPScan enumerates vulnerable plugins, themes, users, media, and backups. 

```shell-session
realCustampin@htb[/htb]$ sudo wpscan --url http://blog.inlanefreight.local --enumerate --api-token dEOFB<SNIP>

<SNIP>

[+] URL: http://blog.inlanefreight.local/ [10.129.42.195]
[+] Started: Thu Sep 16 23:11:43 2021

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.41 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://blog.inlanefreight.local/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access

[+] WordPress readme found: http://blog.inlanefreight.local/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://blog.inlanefreight.local/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] WordPress version 5.8 identified (Insecure, released on 2021-07-20).
 | Found By: Rss Generator (Passive Detection)
 |  - http://blog.inlanefreight.local/?feed=rss2, <generator>https://wordpress.org/?v=5.8</generator>
 |  - http://blog.inlanefreight.local/?feed=comments-rss2, <generator>https://wordpress.org/?v=5.8</generator>
 |
 | [!] 3 vulnerabilities identified:
 |
 | [!] Title: WordPress 5.4 to 5.8 - Data Exposure via REST API
 |     Fixed in: 5.8.1
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/38dd7e87-9a22-48e2-bab1-dc79448ecdfb
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-39200
 |      - https://wordpress.org/news/2021/09/wordpress-5-8-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/ca4765c62c65acb732b574a6761bf5fd84595706
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-m9hc-7v5q-x8q5
 |
 | [!] Title: WordPress 5.4 to 5.8 - Authenticated XSS in Block Editor
 |     Fixed in: 5.8.1
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/5b754676-20f5-4478-8fd3-6bc383145811
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-39201
 |      - https://wordpress.org/news/2021/09/wordpress-5-8-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-wh69-25hr-h94v
 |
 | [!] Title: WordPress 5.4 to 5.8 -  Lodash Library Update
 |     Fixed in: 5.8.1
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/5d6789db-e320-494b-81bb-e678674f4199
 |      - https://wordpress.org/news/2021/09/wordpress-5-8-1-security-and-maintenance-release/
 |      - https://github.com/lodash/lodash/wiki/Changelog
 |      - https://github.com/WordPress/wordpress-develop/commit/fb7ecd92acef6c813c1fde6d9d24a21e02340689

[+] WordPress theme in use: transport-gravity
 | Location: http://blog.inlanefreight.local/wp-content/themes/transport-gravity/
 | Latest Version: 1.0.1 (up to date)
 | Last Updated: 2020-08-02T00:00:00.000Z
 | Readme: http://blog.inlanefreight.local/wp-content/themes/transport-gravity/readme.txt
 | [!] Directory listing is enabled
 | Style URL: http://blog.inlanefreight.local/wp-content/themes/transport-gravity/style.css
 | Style Name: Transport Gravity
 | Style URI: https://keonthemes.com/downloads/transport-gravity/
 | Description: Transport Gravity is an enhanced child theme of Business Gravity. Transport Gravity is made for tran...
 | Author: Keon Themes
 | Author URI: https://keonthemes.com/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 | Confirmed By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.0.1 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://blog.inlanefreight.local/wp-content/themes/transport-gravity/style.css, Match: 'Version: 1.0.1'

[+] Enumerating Vulnerable Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] mail-masta
 | Location: http://blog.inlanefreight.local/wp-content/plugins/mail-masta/
 | Latest Version: 1.0 (up to date)
 | Last Updated: 2014-09-19T07:52:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | [!] 2 vulnerabilities identified:
 |
 | [!] Title: Mail Masta <= 1.0 - Unauthenticated Local File Inclusion (LFI)

<SNIP>

| [!] Title: Mail Masta 1.0 - Multiple SQL Injection
      
 <SNIP
 
 | Version: 1.0 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://blog.inlanefreight.local/wp-content/plugins/mail-masta/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://blog.inlanefreight.local/wp-content/plugins/mail-masta/readme.txt

<SNIP>

[i] User(s) Identified:

[+] by:
									admin
 | Found By: Author Posts - Display Name (Passive Detection)

[+] admin
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By:
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] john
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
```

