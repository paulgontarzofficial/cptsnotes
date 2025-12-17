- We are bound to encounter legacy Operating Systems, we must know how we can take advantage of these and use them to our advantage. 

**End of Life Systems (EOL)**

Windows Desktop: 

|Version|Date|
|---|---|
|Windows XP|April 8, 2014|
|Windows Vista|April 11, 2017|
|Windows 7|January 14, 2020|
|Windows 8|January 12, 2016|
|Windows 8.1|January 10, 2023|
|Windows 10 release 1507|May 9, 2017|
|Windows 10 release 1703|October 9, 2018|
|Windows 10 release 1809|November 10, 2020|
|Windows 10 release 1903|December 8, 2020|
|Windows 10 release 1909|May 11, 2021|
|Windows 10 release 2004|December 14, 2021|
|Windows 10 release 20H2|May 10, 2022|

Windows Server: 

|Version|Date|
|---|---|
|Windows Server 2003|April 8, 2014|
|Windows Server 2003 R2|July 14, 2015|
|Windows Server 2008|January 14, 2020|
|Windows Server 2008 R2|January 14, 2020|
|Windows Server 2012|October 10, 2023|
|Windows Server 2012 R2|October 10, 2023|
|Windows Server 2016|January 12, 2027|
|Windows Server 2019|January 9, 2029|

**Impact**
- There are plenty of downsides when it comes to Operating Systems EOL. 

|Issue|Description|
|---|---|
|Lack of support from software companies|Certain applications (such as web browsers and other essential applications) may cease to work once a version of Windows is no longer officially supported.|
|Hardware issues|Newer hardware components will likely stop working on legacy systems.|
|Security flaws|This is the big one with a few notable exceptions (such as [CVE-2020-1350](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2020-1350) (SIGRed) or EternalBlue ([CVE-2017-0144](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2017-0144))) which were easily exploitable and "wormable" security flaws which affected thousands of systems worldwide (including critical infrastructure such as hospitals). Microsoft will no longer release security updates for end-of-life systems. This could leave the systems open to remote code execution and privilege escalation flaws that will remain unpatched until the system is upgraded or retired.|
As penetration testers, we will often come across legacy operating systems. Though I do not see many hosts running server 2000 or Windows XP workstations vulnerable to [MS08-067](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-067), they exist, and I come across them on occasion. It is more common to see a few Server 2003 hosts and 2008 hosts. When we come across these systems, they are often vulnerable to one or multiple remote code execution flaws or local privilege escalation vectors. They can be a great foothold into the environment. However, when attacking them, we should always check with the client to ensure they are not fragile hosts running mission-critical applications that could cause a massive outage. There are several security protections in newer Windows operating system versions that do not exist in legacy versions, making our privilege escalation tasks much more straightforward.

There are some notable differences among older and newer versions of Windows operating system versions. While this module aims to teach local privilege escalation techniques that can be used against modern Windows OS versions, we would be remiss in not going over some of the key differences between the most common versions. The core of the module focuses on various versions of Windows 10, Server 2016, and 2019, but let's take a trip down memory lane and analyze both a Windows 7 and a Server 2008 system from the perspective of a penetration tester with the goal of picking out key differences that are crucial during assessments of large environments.