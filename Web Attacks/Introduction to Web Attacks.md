Within this module, we will be focusing on three other web attacks that can be found within any web application, which may lead to compromise. 


-------
### Web Attacks

**HTTP Verb Tampering**
- An HTTP Verb Tampering Attack is an attack that exploits web servers that accept many HTTP verbs and methods. This can be exploited by using unexpected methods, which may lead to bypassing the web applications authorization mechanism or even bypassing its escurity controls against other web attacks. 

**Insecure Direct Object Reference**
- IDOR can lead to accessing data that should not be accessible by attackers. What makes this attack common is the lack of a solid access control system on the back-end. For example, a web application may expose direct references to users files vice having a system in place to obfuscate that information. 

**XML External Entity**
- XXE attacks take advantage of outdated libraries to parse and process XML input data from the front-end user. In that case, it may be possible to send malicious XML data to disclose local files stored on the back-end server. These files may be config files that contain sensitive information.

