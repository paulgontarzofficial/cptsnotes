- The most common type of file upload vulnerability is when an application does not have any form of validation filters on the uploaded files, allowing the upload of any file type by default. 
- In this case, we may be able to directly upload our web or reverse shell script to the web application, just by visiting the shell, we can interact with our web shell or send the reverse shell. 

### Arbitrary File Upload 
- Starting out with the webpage we are served, it allows us to upload a file to the web server. 

![[Pasted image 20251128203949.png]]
- The web app does not mention anything about what file types are allowed, we can drag and drop any file we want, including .php files. 

![[Pasted image 20251128204133.png]]
- All of this basically is telling us that there is no file type restrictions on the front-end, and if no restrictions specified on the back-end, we might be able to upload arbitrary file types to the back-end server to gain complete control over it. 

----
### Identifying Web Frameworks 

A Web Shell provides us with an easy method to interact with the back-end server by accepting shell commands and printing their output back to us within the web browser. A web shell has to be written in the same programming language that runs the web server, as it runs platform-specific functions and commands to execute system commands on the back-end server, making web shells non-cross-platform scripts. So, the first step would be to identify what language runs the web application.

- One easy method to determine what language runs the web application is to visit the `/index.ext` page, where we would swap out `ext` with various common web extensions, like `php`, `asp`, `aspx`, among others, to see whether any of them exist.

**Tools**
- We can utilize tools such as Burp Intruder or Wappalyzer to view the web framework that is being used for the web application. 

![[Pasted image 20251128204953.png]]
- This tells us more than what the web app is running on the front-end, it also tells us the OS that is running on the back-end. 

----
### Vulnerability Identification
- Now that we have identified the web framework running the web application and its programming language, we can test whether we can upload a file with the same extension. 
- We can create a simple Hello World program that will echo hello world to the output. 

To do so, we will write `<?php echo "Hello HTB";?>` to `test.php`, and try uploading it to the web application:

![[Pasted image 20251128205323.png]]
- The file appears to have been uploaded, which basically means that there is no file validation whatsoever on the back-end. Now, we can click the Download FIle button, and the web application will take us to our uploaded file: 

![[Pasted image 20251128205541.png]]
- As we can see, the page prints our `Hello HTB` message, which means that the `echo` function was executed to print our string, and we successfully executed `PHP` code on the back-end server. If the page could not run PHP code, we would see our source code printed on the page.

