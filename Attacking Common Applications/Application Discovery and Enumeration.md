- We need to focus on gaining the most information on all applications that are currently on the network, whether that be VHosts or seperate Web Apps hosted on different IPs, wee need to assist the client in understanding what they have going on internally on their network. 
- We can utilize nmap to discover all the web applications on the network. 

```shell-session
realCustampin@htb[/htb]$ nmap -p 80,443,8000,8080,8180,8888,10000 --open -oA web_discovery -iL scope_list
```

Once we get a full list of all the web applications and all the positive hits from the nmap scan, we can utilize tools such as EyeWitness and Aquatone to sift through all of our findings automatically instead of going through manually. 

### Initial Enumeration 
- Let's assume that we were given this list for in-scope targets: 

```shell-session
realCustampin@htb[/htb]$ cat scope_list 

app.inlanefreight.local
dev.inlanefreight.local
drupal-dev.inlanefreight.local
drupal-qa.inlanefreight.local
drupal-acc.inlanefreight.local
drupal.inlanefreight.local
blog-dev.inlanefreight.local
blog.inlanefreight.local
app-dev.inlanefreight.local
jenkins-dev.inlanefreight.local
jenkins.inlanefreight.local
web01.inlanefreight.local
gitlab-dev.inlanefreight.local
gitlab.inlanefreight.local
support-dev.inlanefreight.local
support.inlanefreight.local
inlanefreight.local
10.129.201.50
```

Usually when we are first starting our scan we are going to scan ports `80,443,8000,8080,8180,8888,10000` and then pass that data into EyeWitness or Aquatone depending on the results against the initial scan. 

```shell-session
realCustampin@htb[/htb]$ sudo  nmap -p 80,443,8000,8080,8180,8888,10000 --open -oA web_discovery -iL scope_list 

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-07 21:49 EDT
Stats: 0:00:07 elapsed; 1 hosts completed (4 up), 4 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 81.24% done; ETC: 21:49 (0:00:01 remaining)

Nmap scan report for app.inlanefreight.local (10.129.42.195)
Host is up (0.12s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap scan report for app-dev.inlanefreight.local (10.129.201.58)
Host is up (0.12s latency).
Not shown: 993 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8000/tcp open  http-alt
8009/tcp open  ajp13
8080/tcp open  http-proxy
8180/tcp open  unknown
8888/tcp open  sun-answerbook

Nmap scan report for gitlab-dev.inlanefreight.local (10.129.201.88)
Host is up (0.12s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8081/tcp open  blackice-icecap

Nmap scan report for 10.129.201.50
Host is up (0.13s latency).
Not shown: 991 closed ports
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server
5357/tcp open  wsdapi
8000/tcp open  http-alt
8080/tcp open  http-proxy
8089/tcp open  unknown
```

Looking at the results, we can see that there are several subdomains that we have enumerated. It is also important to note that they are dev subdomains, so there may be untested versions of apps that we can exploit. 

Now that we have our targets of interest, let us run a service nmap scan to identify the applications running. 

```shell-session
realCustampin@htb[/htb]$ sudo nmap --open -sV 10.129.201.50

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-07 21:58 EDT
Nmap scan report for 10.129.201.50
Host is up (0.13s latency).
Not shown: 991 closed ports
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5357/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
8000/tcp open  http          Splunkd httpd
8080/tcp open  http          Indy httpd 17.3.33.2830 (Paessler PRTG bandwidth monitor)
8089/tcp open  ssl/http      Splunkd httpd (free license; remote login disabled)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.63 seconds
```

As we can see from the scan above, we have an IIS Server running on port 80. And then the application Splunk on port 8000/8089. PRTG Network Monitor is also present on port 8080.  

**Using Eyewitness for Web Screenshotting**
- We can utilize the default --web option to take screenshots using the Nmap XML output from the discovery scan as input. 
```shell-session
realCustampin@htb[/htb]$ eyewitness --web -x web_discovery.xml -d inlanefreight_eyewitness

################################################################################
#                                  EyeWitness                                  #
################################################################################
#           FortyNorth Security - https://www.fortynorthsecurity.com           #
################################################################################

Starting Web Requests (26 Hosts)
Attempting to screenshot http://app.inlanefreight.local
Attempting to screenshot http://app-dev.inlanefreight.local
Attempting to screenshot http://app-dev.inlanefreight.local:8000
Attempting to screenshot http://app-dev.inlanefreight.local:8080
Attempting to screenshot http://gitlab-dev.inlanefreight.local
Attempting to screenshot http://10.129.201.50
Attempting to screenshot http://10.129.201.50:8000
Attempting to screenshot http://10.129.201.50:8080
Attempting to screenshot http://dev.inlanefreight.local
Attempting to screenshot http://jenkins-dev.inlanefreight.local
Attempting to screenshot http://jenkins-dev.inlanefreight.local:8000
Attempting to screenshot http://jenkins-dev.inlanefreight.local:8080
Attempting to screenshot http://support-dev.inlanefreight.local
Attempting to screenshot http://drupal-dev.inlanefreight.local
[*] Hit timeout limit when connecting to http://10.129.201.50:8000, retrying
Attempting to screenshot http://jenkins.inlanefreight.local
Attempting to screenshot http://jenkins.inlanefreight.local:8000
Attempting to screenshot http://jenkins.inlanefreight.local:8080
Attempting to screenshot http://support.inlanefreight.local
[*] Completed 15 out of 26 services
Attempting to screenshot http://drupal-qa.inlanefreight.local
Attempting to screenshot http://web01.inlanefreight.local
Attempting to screenshot http://web01.inlanefreight.local:8000
Attempting to screenshot http://web01.inlanefreight.local:8080
Attempting to screenshot http://inlanefreight.local
Attempting to screenshot http://drupal-acc.inlanefreight.local
Attempting to screenshot http://drupal.inlanefreight.local
Attempting to screenshot http://blog-dev.inlanefreight.local
Finished in 57.859838008880615 seconds

[*] Done! Report written in the /home/mrb3n/Projects/inlanfreight/inlanefreight_eyewitness folder!
Would you like to open the report now? [Y/n]
```

**Using Aquatone**
```shell-session
realCustampin@htb[/htb]$ wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
```

Application Discovery & Enumeration

```shell-session
realCustampin@htb[/htb]$ unzip aquatone_linux_amd64_1.7.0.zip 

Archive:  aquatone_linux_amd64_1.7.0.zip
  inflating: aquatone                
  inflating: README.md               
  inflating: LICENSE.txt 
```

Using this tool, we can pass the same xml file that we provided in the EyeWitness scan. 

```shell-session
realCustampin@htb[/htb]$ cat web_discovery.xml | ./aquatone -nmap

aquatone v1.7.0 started at 2021-09-07T22:31:03-04:00

Targets    : 65
Threads    : 6
Ports      : 80, 443, 8000, 8080, 8443
Output dir : .

http://web01.inlanefreight.local:8000/: 403 Forbidden
http://app.inlanefreight.local/: 200 OK
http://jenkins.inlanefreight.local/: 403 Forbidden
http://app-dev.inlanefreight.local/: 200 
http://app-dev.inlanefreight.local/: 200 
http://app-dev.inlanefreight.local:8000/: 403 Forbidden
http://jenkins.inlanefreight.local:8000/: 403 Forbidden
http://web01.inlanefreight.local:8080/: 200 
http://app-dev.inlanefreight.local:8000/: 403 Forbidden
http://10.129.201.50:8000/: 200 OK

<SNIP>

http://web01.inlanefreight.local:8000/: screenshot successful
http://app.inlanefreight.local/: screenshot successful
http://app-dev.inlanefreight.local/: screenshot successful
http://jenkins.inlanefreight.local/: screenshot successful
http://app-dev.inlanefreight.local/: screenshot successful
http://app-dev.inlanefreight.local:8000/: screenshot successful
http://jenkins.inlanefreight.local:8000/: screenshot successful
http://app-dev.inlanefreight.local:8000/: screenshot successful
http://app-dev.inlanefreight.local:8080/: screenshot successful
http://app.inlanefreight.local/: screenshot successful

<SNIP>

Calculating page structures... done
Clustering similar pages... done
Generating HTML report... done

Writing session file...Time:
 - Started at  : 2021-09-07T22:31:03-04:00
 - Finished at : 2021-09-07T22:31:36-04:00
 - Duration    : 33s

Requests:
 - Successful : 65
 - Failed     : 0

 - 2xx : 47
 - 3xx : 0
 - 4xx : 18
 - 5xx : 0

Screenshots:
 - Successful : 65
 - Failed     : 0

Wrote HTML report to: aquatone_report.html
```

**Interpreting the Results**
![[Pasted image 20251204191444.png]]
- We can see that we have a "High Value Targets" section which is where we want to start looking. 

