**File Share Services:**

- Most companies previously used only internal services for file sharing, such as AMB, NFS, FTP, TFTP, SFTP
- Nowadays, companies are using third-party cloud services such as Dropbox, Google Drive, OneDrive, Sharepoint, or other forms of file storage such as AWS S3, Azure Blob Storage, or Google Cloud Storage.

**Server Message Block:**

- Commonly used within Windows Networks.
- We can interact with the SMB Share using a few different ways:
    - GUI
    - CLI
    - Tools

Windows Gui:

- We can press [winkey] + [R]
- and then in the run dialog, put in the IP and the Share, \\192.168.220.133\Finance\
- If the folder allows for anonymous authentication, or we are authenticated with a user who has privilege over that shared folder. This will display the content of the shared folder.
- If we do not have access, we will receive an authentication request.

Windows CMD - DIR

- We can use the ‘dir’ command followed by the IP and sharename to view the contents of it:

```bash
C:\\htb> dir \\\\192.168.220.129\\Finance\\

Volume in drive \\\\192.168.220.129\\Finance has no label.
Volume Serial Number is ABCD-EFAA

Directory of \\\\192.168.220.129\\Finance

02/23/2022  11:35 AM    <DIR>          Contracts
               0 File(s)          4,096 bytes
               1 Dir(s)  15,207,469,056 bytes free
```

Windows CMD - Net use

- Next we can mount the share onto one of our drives on the local system using the ‘net use’ command.

```bash
C:\\htb> net use n: \\\\192.168.220.129\\Finance

The command completed successfully.
```

- We can also pass a username and password to authenticate to the share.

```bash
C:\\htb> net use n: \\\\192.168.220.129\\Finance /user:plaintext Password123

The command completed successfully.
```

Windows CMD - DIR

- Now that we have that share mounted, let us now find how many files the shared folder and its subdirectories contain:

```bash
C:\\htb> dir n: /a-d /s /b | find /c ":\\"

29302
```

Breakdown of Syntax:

|**Syntax**|**Description**|
|---|---|
|`dir`|Application|
|`n:`|Directory or drive to search|
|`/a-d`|`/a` is the attribute and `-d` means not directories|
|`/s`|Displays files in a specified directory and all subdirectories|
|`/b`|Uses bare format (no heading information or summary)|

We can use dir command to search for different names, file types, and other attributes of files.

```bash
C:\\htb>dir n:\\*cred* /s /b

n:\\Contracts\\private\\credentials.txt

C:\\htb>dir n:\\*secret* /s /b

n:\\Contracts\\private\\secret.txt
```

Windows CMD - Findstr

```bash
c:\\htb>findstr /s /i cred n:\\*.*

n:\\Contracts\\private\\secret.txt:file with all credentials
n:\\Contracts\\private\\credentials.txt:admin:SecureCredentials!
```

- We can also use external resources for more examples on what we can find using the ‘findstr’ command
    - [https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/findstr#examples](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/findstr#examples)

Windows Powershell

- Powershell utilizes cmdlets to run powershell commands.

```powershell
PS C:\\htb> Get-ChildItem \\\\192.168.220.129\\Finance\\

    Directory: \\\\192.168.220.129\\Finance

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         2/23/2022   3:27 PM                Contracts
```

Instead of using the net use command, we can use the New-PSDrive cmdlet to mount the shared folder to a specific drive.

```powershell-session
PS C:\htb> New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem"

Name           Used (GB)     Free (GB) Provider      Root                                               CurrentLocation
----           ---------     --------- --------      ----                                               ---------------
N                                      FileSystem    \\192.168.220.129\Finance
```

Creating the PSCredential Object on Windows Powershell:

```powershell-session
PS C:\htb> $username = 'plaintext'
PS C:\htb> $password = 'Password123'
PS C:\htb> $secpassword = ConvertTo-SecureString $password -AsPlainText -Force
PS C:\htb> $cred = New-Object System.Management.Automation.PSCredential $username, $secpassword
PS C:\htb> New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem" -Credential $cred

Name           Used (GB)     Free (GB) Provider      Root                                                              CurrentLocation
----           ---------     --------- --------      ----                                                              ---------------
N                                      FileSystem    \\192.168.220.129\Finance
```

**Windows Powershell - GCI (Get-ChildItem)**

```powershell-session
PS C:\htb> N:
PS N:\> (Get-ChildItem -File -Recurse | Measure-Object).Count

29302
```

We can use the -Include property to find specific items from the directory specified by the path parameter: 
```powershell-session
PS C:\htb> Get-ChildItem -Recurse -Path N:\ -Include *cred* -File

    Directory: N:\Contracts\private

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         2/23/2022   4:36 PM             25 credentials.txt
```

**Windows Powershell - Select-String**
```powershell-session
PS C:\htb> Get-ChildItem -Recurse -Path N:\ | Select-String "cred" -List

N:\Contracts\private\secret.txt:1:file with all credentials
N:\Contracts\private\credentials.txt:1:admin:SecureCredentials!
```
- This is used like the 'grep' command within a UNIX system and findstr.exe within Windows. 
- The Terminal allows for us to perform operations more efficiently by using scripts rather than using the GUI. 

## Mounting SMB on Linux
- Linux can be used to browse and mount SMB shares. 
- Prior to mounting, we need to install the cifs-utils package from our Software Distribution. 
```shell-session
realCustampin@htb[/htb]$ sudo mkdir /mnt/Finance
realCustampin@htb[/htb]$ sudo mount -t cifs -o username=plaintext,password=Password123,domain=. //192.168.220.129/Finance /mnt/Finance
```

We can also pass a credential file vice putting our password directly into the command line. 
```shell-session
realCustampin@htb[/htb]$ mount -t cifs //192.168.220.129/Finance /mnt/Finance -o credentials=/path/credentialfile
```

Structure of the credential file is as follows: 
```txt
username=plaintext
password=Password123
domain=.
```

Once that file is mounted, we can go ahead and use the find command to search for anything we need: 

```shell-session
realCustampin@htb[/htb]$ find /mnt/Finance/ -name *cred*

/mnt/Finance/Contracts/private/credentials.txt
```

Searching for a file that contains a string 'cred' 
```shell-session
realCustampin@htb[/htb]$ grep -rn /mnt/Finance/ -ie cred

/mnt/Finance/Contracts/private/credentials.txt:1:admin:SecureCredentials!
/mnt/Finance/Contracts/private/secret.txt:1:file with all credentials
```

## Other Services


**Email**
- Typically we need two protocols in order to send and receive mail. 
- SMTP is an email delivery protocol, and as a supporting protocol we have POP3 and IMAP. 
- In order for us to interact with these services we can download a personal information manager, and mail client for the GNOME Desktop. This program is called evolution. 

**Installation:**
```shell-session
realCustampin@htb[/htb]$ sudo apt-get install evolution
...SNIP...
```

**Databases:**
- Ways that we can interact with Databases: 

|      |                                                                                                                  |
| ---- | ---------------------------------------------------------------------------------------------------------------- |
| `1.` | Command Line Utilities (`mysql` or `sqsh`)                                                                       |
| `2.` | Programming Languages                                                                                            |
| `3.` | A GUI application to interact with databases such as HeidiSQL, MySQL Workbench, or SQL Server Management Studio. |
![[Pasted image 20251031175813.png]]

Some command line utilities that we can use to interact with the SQL Server include: 
- MSSQL (Microsoft SQL Server)
	- With a linux attack host we can use sqsh. 
	- With a windows machine that we have gotten into we can use sqlcmd. 

Using sqsh on Linux:
```shell-session
realCustampin@htb[/htb]$ sqsh -S 10.129.20.13 -U username -P Password123
```

Using sqlcmd on Windows: 

The `sqlcmd` utility lets you enter Transact-SQL statements, system procedures, and script files through a variety of available modes:

- At the command prompt.
- In Query Editor in SQLCMD mode.
- In a Windows script file.
- In an operating system (Cmd.exe) job step of a SQL Server Agent job.

```cmd-session
C:\htb> sqlcmd -S 10.129.20.13 -U username -P Password123
```

**Interacting with MySql:**
- On a linux host we can use the MySQL binaries or on windows we can use the mysql.exe. 

Logging in on Linux: 
```shell-session
realCustampin@htb[/htb]$ mysql -u username -pPassword123 -h 10.129.20.13
```

Logging in on Windows: 
```cmd-session
C:\htb> mysql.exe -u username -pPassword123 -h 10.129.20.13
```

Installing a GUI for Database Management: 

```shell-session
realCustampin@htb[/htb]$ sudo dpkg -i dbeaver-<version>.deb
```

Running dbeaver: 
```shell-session
realCustampin@htb[/htb]$ dbeaver &
```

#### Tools to Interact with Common Services

|**SMB**|**FTP**|**Email**|**Databases**|
|---|---|---|---|
|[smbclient](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html)|[ftp](https://linux.die.net/man/1/ftp)|[Thunderbird](https://www.thunderbird.net/en-US/)|[mssql-cli](https://github.com/dbcli/mssql-cli)|
|[CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)|[lftp](https://lftp.yar.ru/)|[Claws](https://www.claws-mail.org/)|[mycli](https://github.com/dbcli/mycli)|
|[SMBMap](https://github.com/ShawnDEvans/smbmap)|[ncftp](https://www.ncftp.com/)|[Geary](https://wiki.gnome.org/Apps/Geary)|[mssqlclient.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py)|
|[Impacket](https://github.com/SecureAuthCorp/impacket)|[filezilla](https://filezilla-project.org/)|[MailSpring](https://getmailspring.com)|[dbeaver](https://github.com/dbeaver/dbeaver)|
|[psexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py)|[crossftp](http://www.crossftp.com/)|[mutt](http://www.mutt.org/)|[MySQL Workbench](https://dev.mysql.com/downloads/workbench/)|
|[smbexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py)||[mailutils](https://mailutils.org/)|[SQL Server Management Studio or SSMS](https://docs.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms)|
|||[sendEmail](https://github.com/mogaal/sendemail)||
|||[swaks](http://www.jetmore.org/john/code/swaks/)||
|||[sendmail](https://en.wikipedia.org/wiki/Sendmail)|
