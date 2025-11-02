- When looking at a service, we want to gather up every single piece of information that we can. 

A good example of how we can snowball off of one exposed user account: 

- Let us imagine we are in an engagement with a client, we are targeting email, FTP, databases, and storage, and our goal is to obtain Remote Code Execution (RCE) on any of these services. We started the enumeration and tried anonymous access to all services, and only FTP has anonymous access. We found an empty file within the FTP service, but with the name `johnsmith`, we tried `johnsmith` as the FTP user and password, but it did not work. We try the same against the email service, and we successfully login. With email access, we start searching emails containing the word `password`, we find many, but one of them contains John's credentials for the MSSQL database. We access the database and use the built-in functionality to execute commands and successfully get RCE on the database server. We successfully met our goal.

The following are examples of sensitive information: 
- Usernames.
- Email Addresses.
- Passwords.
- DNS records.
- IP Addresses.
- Source code.
- Configuration files.
- PII.

## Key Elements: 
1. We need to understand the service and how it works.
2. We need to know what we are looking for.