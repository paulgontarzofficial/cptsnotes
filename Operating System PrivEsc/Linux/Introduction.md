Our target for any linux system should be the root user. This user has full control over everything on the system, in that case, we may gain access to the server with a low-privileged user and would need to conduct some privilege escalation in order for us to gain control of the system. 

**Enumeration**

Key items that we need to check when we get into a linux box are: 
1. OS Version: Knowing the distribution will give you an idea of the types of tool sthat may be available. 
2. Kernel Version: As with the OS, there may be a publicly known vulnerability that exists for the kernel version. 
3. Running Services: Knowing what services are running on the host is important, especially those that are running as the root user. 

**Listing Current Processes**
```shell-session
realCustampin@htb[/htb]$ ps aux | grep root

root         1  1.3  0.1  37656  5664 ?        Ss   23:26   0:01 /sbin/init
root         2  0.0  0.0      0     0 ?        S    23:26   0:00 [kthreadd]
root         3  0.0  0.0      0     0 ?        S    23:26   0:00 [ksoftirqd/0]
root         4  0.0  0.0      0     0 ?        S    23:26   0:00 [kworker/0:0]
root         5  0.0  0.0      0     0 ?        S<   23:26   0:00 [kworker/0:0H]
root         6  0.0  0.0      0     0 ?        S    23:26   0:00 [kworker/u8:0]
root         7  0.0  0.0      0     0 ?        S    23:26   0:00 [rcu_sched]
root         8  0.0  0.0      0     0 ?        S    23:26   0:00 [rcu_bh]
root         9  0.0  0.0      0     0 ?        S    23:26   0:00 [migration/0]

<SNIP>
```

4. Installed Packages and Versions: It is important to check for any out-of-date or vulnerable packages that may be easily leveraged for privilege escalation. 
5. Logged in Users: Knowing which other users are logged into the system and what they are doing can provide greater insight into possible local lateral movement and privilege escalation paths. 

**List Current Terminal-Attached Processes**
```shell-session
realCustampin@htb[/htb]$ ps au

USER       		PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root      		1256  0.0  0.1  65832  3364 tty1     Ss   23:26   0:00 /bin/login --
cliff.moore     1322  0.0  0.1  22600  5160 tty1     S    23:26   0:00 -bash
shared     		1367  0.0  0.1  22568  5116 pts/0    Ss   23:27   0:00 -bash
root      		1384  0.0  0.1  52700  3812 tty1     S    23:29   0:00 sudo su
root      		1385  0.0  0.1  52284  3448 tty1     S    23:29   0:00 su
root      		1386  0.0  0.1  21224  3764 tty1     S+   23:29   0:00 bash
shared     		1397  0.0  0.1  37364  3428 pts/0    R+   23:30   0:00 ps au
```

6. User Home Directories: Are other user's home directories accessible? User home folders may also contain SSH Keys that can be used to access other systems or scripts and config file containing credentials. 
	1. We can check files such as .bash_history to see if there are any interesting commands. 
7. Sudo Priveleges: Can the user run any commands either as another user or root?

```shell-session
realCustampin@htb[/htb]$ sudo -l

Matching Defaults entries for sysadm on NIX02:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User sysadm may run the following commands on NIX02:
    (root) NOPASSWD: /usr/sbin/tcpdump
```

8. Configuration Files: Config files can hold a plethora of information. 
9. Readable Shadow Files: If the shadow file is readable, you will be able to gather password hashes for all users who have a password set. 
10. Password Hashes within the /etc/passwd File: Sometimes there may be an instance where we find some password hashes within our passwd file that is readable for all users.
11. Cron Jobs: These are the scheduled tasks for a linux machine.

**Cron Jobs**
```shell-session
realCustampin@htb[/htb]$ ls -la /etc/cron.daily/

total 60
drwxr-xr-x  2 root root 4096 Aug 30 23:49 .
drwxr-xr-x 93 root root 4096 Aug 30 23:47 ..
-rwxr-xr-x  1 root root  376 Mar 31  2016 apport
-rwxr-xr-x  1 root root 1474 Sep 26  2017 apt-compat
-rwx--x--x  1 root root  379 Aug 30 23:49 backup
-rwxr-xr-x  1 root root  355 May 22  2012 bsdmainutils
-rwxr-xr-x  1 root root 1597 Nov 27  2015 dpkg
-rwxr-xr-x  1 root root  372 May  6  2015 logrotate
-rwxr-xr-x  1 root root 1293 Nov  6  2015 man-db
-rwxr-xr-x  1 root root  539 Jul 16  2014 mdadm
-rwxr-xr-x  1 root root  435 Nov 18  2014 mlocate
-rwxr-xr-x  1 root root  249 Nov 12  2015 passwd
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder
-rwxr-xr-x  1 root root 3449 Feb 26  2016 popularity-contest
-rwxr-xr-x  1 root root  214 May 24  2016 update-notifier-common
```

12. Unmounted File Systems and Additional Drives:  If you discover and can mount an additional drive or unmounted file system, you may find sensitive files, passwords, or backups that can be leveraged to escalate privileges. 

**Listing File Systems**
 ```shell-session
realCustampin@htb[/htb]$ lsblk

NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
sda      8:0    0   30G  0 disk 
├─sda1   8:1    0   29G  0 part /
├─sda2   8:2    0    1K  0 part 
└─sda5   8:5    0  975M  0 part [SWAP]
sr0     11:0    1  848M  0 rom  
```

13. SETUID and SETGID Permissions: Binaries are set with these permissions to allow a user to run a command as root, without having to grant root-level access to the user. Many binaries contain functionality that can be exploited to get a root shell. 
14. Writable Directories: It is important to discover which directories are writeable if you need to download tools to the system. You may discover a writeable directory where a cron job places files, which provides an idea of how often cron job runs and can be used to elevate privileges. 
15. Writeable Files: We could modify the config files or maybe a script that is on the box. 


