In the previous section, we saw several types of attacks that we can use for different types of LFI vulnerabilities. In many cases, we may be facing a web application that applies various protections against file inclusion, so our normal LFI payloads would not work. Still, unless the web application is properly secured against malicious LFI user input, we may be able to bypass the protections in place and reach file inclusion.

**Non-Recursive Path Traversal Filters**
- One of the most basic filters against an LFI is a search and replace filter, which deletes substrings of ../ to avoid a path traversal attack. 

```php
$language = str_replace('../', '', $_GET['language']);
```

- The code above prevents attacks like the following image below from happening: 

http://SERVER:PORT/index.php?language=../../../../etc/passwd
![[Pasted image 20251128075213.png]]
- We notice in the output that the substrings were removed, which resulted in a final path being ./languages/etc/passwd. This filter however is insecure as it is not recursively removing the ../ substring, as it runs a single time on the input string and does not apply the filter on the output string. 

http://SERVER_IP:PORT/index.php?language=....//....//....//....//etc/passwd
![[Pasted image 20251128075438.png]]
- For example, if we use `....//` as our payload, then the filter would remove `../` and the output string would be `../`, which means we may still perform path traversal. Let's try applying this logic to include `/etc/passwd`
- As we can see, the inclusion was successful this time, and we're able to read `/etc/passwd` successfully. The `....//` substring is not the only bypass we can use, as we may use `..././` or `....\/` and several other recursive LFI payloads. Furthermore, in some cases, escaping the forward slash character may also work to avoid path traversal filters (e.g. `....\/`), or adding extra forward slashes (e.g. `....////`)

### Encoding
- Some filters may not allow us to use certain LFI characters ie '/' or a '.' 
- If that is the case then we can bypass this by using URL Encoding for our input. 


!!!!IMPORTANT!!!!
Core PHP filters on versions 5.3.4 and earlier were specifically vulnerable to this bypass, but even on newer versions we may find custom filters that may be bypassed through URL encoding.


![[Pasted image 20251128075738.png]]

http://SERVER_IP:PORT/index.php?language=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64

![[Pasted image 20251128075818.png]]
- We may also use Burp Decoder to encode the encoded string once again to have a double encoded string which may bypass filters also. 

### Approved Paths
- Some web apps may use Regular Expressions to ensure that the file being included is under a specific path. For example, the web application we have been dealing with may only accept paths that are under the ./languages directory:

```php
if(preg_match('/^\.\/languages\/.+$/', $_GET['language'])) {
    include($_GET['language']);
} else {
    echo 'Illegal path specified!';
}
```

To find the approved path, we can examine the requests sent by the existing forms, and see what path they use for the normal web functionality. Furthermore, we can fuzz web directories under the same path, and try different ones until we get a match. To bypass this, we may use path traversal and start our payload with the approved path, and then use `../` to go back to the root directory and read the file we specify, as follows:

http://SERVER_IP:PORT/index.php?language=./languages/../../../../etc/passwd
![[Pasted image 20251128080442.png]] 

### Appended Extension
