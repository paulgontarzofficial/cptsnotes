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

**Windows Powershell - GCI**

```powershell-session
PS C:\htb> N:
PS N:\> (Get-ChildItem -File -Recurse | Measure-Object).Count

29302
```