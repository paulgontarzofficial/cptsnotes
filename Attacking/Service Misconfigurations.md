This section is aimed at how an administrator should be thinking when setting up some of these new systems, creating user accounts, etc.  

**Authentication:**
- It was typical to leave the default credentials alone when working with system configs in the past, however nowadays, vendors like to ask the user to change those default credentials when it is initially installed. 
- As admins, we need to define a password policy to be used: 

```shell-session
admin:admin
admin:password
admin:<blank>
root:12345678
administrator:Password
```

- Once the service banner has been found, we should go and try to find possible default credentials for that service. 

**Anonymous Authentication:**
- Some services allow for the use of anonymous authentication, for example SMB. 

**Misconfigured Access Rights:**
- This is when we have a user account that is given not the proper permissions when it comes to services. Say we have a user account that was intended for writing to the FTP server, however they now have read permissions and can read anything on the server. 

**Unnecessary Defaults:**
- Unnecessary features are enabled or installed (e.g., unnecessary ports, services, pages, accounts, or privileges).
- Default accounts and their passwords are still enabled and unchanged.
- Error handling reveals stack traces or other overly informative error messages to users.
- For upgraded systems, the latest security features are disabled or not configured securely.

**Preventing Misconfiguration:**
- Admin interfaces should be disabled.
- Debugging is turned off.
- Disable the use of default usernames and passwords.
- Set up the server to prevent unauthorized access, directory listing, and other issues.
- Run scans and audits regularly to help discover future misconfigurations or missing fixes.

