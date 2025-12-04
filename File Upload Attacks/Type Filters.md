- With modern day web applications, file content inspection is common. The two most common parameters that are checked within the file are going to be your Content-Type Header and your File Content Header. Let us take a look a look at those parameters so that we are able to exploit them. 

**Content-Type**
- Let's try to upload a file called shell.php.

![[Pasted image 20251130093617.png]]

- We see that we get a message saying `Only images are allowed`. The error message persists, and our file fails to upload even if we try some of the tricks we learned in the previous sections. If we change the file name to `shell.jpg.phtml` or `shell.php.jpg`, or even if we use `shell.jpg` with a web shell content, our upload will fail. As the file extension does not affect the error message, the web application must be testing the file content for type validation. As mentioned earlier, this can be either in the `Content-Type Header` or the `File Content`.

- The following is an example of how a php web application may test for the content-type header. 
```php
$type = $_FILES['uploadFile']['type'];

if (!in_array($type, array('image/jpg', 'image/jpeg', 'image/png', 'image/gif'))) {
    echo "Only images are allowed";
    die();
}
```

The code sets the (`$type`) variable from the uploaded file's `Content-Type` header. Our browsers automatically set the Content-Type header when selecting a file through the file selector dialog, usually derived from the file extension. However, since our browsers set this, this operation is a client-side operation, and we can manipulate it to change the perceived file type and potentially bypass the type filter.

We may start by fuzzing the Content-Type header with SecLists' [Content-Type Wordlist](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-all-content-types.txt) through Burp Intruder, to see which types are allowed. However, the message tells us that only images are allowed, so we can limit our scan to image types, which reduces the wordlist to `45` types only (compared to around 700 originally). We can do so as follows:

```shell-session
realCustampin@htb[/htb]$ wget https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/web-all-content-types.txt
realCustampin@htb[/htb]$ cat web-all-content-types.txt | grep 'image/' > image-content-types.txt
```

- After narrowing down the list we can run Burp Intruder on the POST request to see if there are any file-type contents that are allowed. 
- In this example we notice that the image/jpg file content type is allowed. Let us intercept a POST request and change the Content-Type and insert the PHP Shell to allow for RCE. 

![[Pasted image 20251130094046.png]]

- We are now able to utilize system commands on the remote server. 
![[Pasted image 20251130094051.png]]

-------
### MIME-Type

The second and more common type of file content validation is testing the uploaded file's `MIME-Type`. `Multipurpose Internet Mail Extensions (MIME)` is an internet standard that determines the type of a file through its general format and bytes structure.

This is usually done by inspecting the first few bytes of the file's content, which contain the [File Signature](https://en.wikipedia.org/wiki/List_of_file_signatures) or [Magic Bytes](https://web.archive.org/web/20240522030920/https://opensource.apple.com/source/file/file-23/file/magic/magic.mime). For example, if a file starts with (`GIF87a` or `GIF89a`), this indicates that it is a `GIF` image, while a file starting with plaintext is usually considered a `Text` file. If we change the first bytes of any file to the GIF magic bytes, its MIME type would be changed to a GIF image, regardless of its remaining content or extension.

**Tip:** Many other image types have non-printable bytes for their file signatures, while a `GIF` image starts with ASCII printable bytes (as shown above), so it is the easiest to imitate. Furthermore, as the string `GIF8` is common between both GIF signatures, it is usually enough to imitate a GIF image.

Let's take a basic example to demonstrate this. The `file` command on Unix systems finds the file type through the MIME type. If we create a basic file with text in it, it would be considered as a text file, as follows:

  Type Filters

```shell-session
realCustampin@htb[/htb]$ echo "this is a text file" > text.jpg 
realCustampin@htb[/htb]$ file text.jpg 
text.jpg: ASCII text
```

As we see, the file's MIME type is `ASCII text`, even though its extension is `.jpg`. However, if we write `GIF8` to the beginning of the file, it will be considered as a `GIF` image instead, even though its extension is still `.jpg`:

  Type Filters

```shell-session
realCustampin@htb[/htb]$ echo "GIF8" > text.jpg 
realCustampin@htb[/htb]$ file text.jpg
text.jpg: GIF image data
```

!!! IMPORTANT !!! 

When we are working with URL Extensions, we may want to disable the URL Encoding option when fuzzing for file extensions that are allowed.

![[Pasted image 20251130141254.png]]