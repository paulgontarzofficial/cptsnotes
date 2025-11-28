**Local File Inclusion**
![[Pasted image 20251128073144.png]]
- We notice that we are given a website that allows us to change the language to english or spanish. This means that when we select a language, it will then load a different file/table from the back-end to the front-end.
- How can we exploit this vulnerability? Well if we are able to request instead of an es.php file from the back-end, we request the /etc/passwd file and we get output, we know this is vulnerable. 
http://SERVER_IP:PORT/index.php?language=es.php
![[Pasted image 20251128073433.png]]

http://SERVER:PORT/index.php?language=/etc/passwd 

![[Pasted image 20251128073441.png]]

### Path Traversal

In the earlier example, we read a file by specifying its `absolute path` (e.g. `/etc/passwd`). This would work if the whole input was used within the `include()` function without any additions, like the following example:

Code: php

```php
include($_GET['language']);
```

In this case, if we try to read `/etc/passwd`, then the `include()` function would fetch that file directly. However, in many occasions, web developers may append or prepend a string to the `language` parameter. For example, the `language` parameter may be used for the filename, and may be added after a directory, as follows:

Code: php

```php
include("./languages/" . $_GET['language']);
```

In this case, if we attempt to read `/etc/passwd`, then the path passed to `include()` would be (`./languages//etc/passwd`), and as this file does not exist, we will not be able to read anything:

![[Pasted image 20251128073704.png]]

We can bypass this restriction by traversing directories using relative paths. To do so we can add '../' before our file name which refers to the parent directory. If we are sitting in /var/www/html/language/, then using ../index.php would refer to the index.php file on the parent directory /var/www/html/index.php. 

Knowing the location of /etc/passwd, and knowing where we are currently placed on the front-end, we can do '../../../../etc/passwd' to traverse the server and be able to output the passwd file.  

http://SERVER_IP:PORT/index.php?language=../../../../etc/passwd

![[Pasted image 20251128074113.png]]
