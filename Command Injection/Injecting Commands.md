-  We can start with a semi-colon operator to see how our injection acts. 

Using the host checker application, we can pass code that looks something like this: 

```bash
ping -c 1 127.0.0.1; whoami
```

- As you can see, we have added a semi-colon operator and are trying to run the 'whoami' command in addition to the ping command. 

![[Pasted image 20251201193717.png]]
- This is how it would look on the front-end. 

```shell-session
21y4d@htb[/htb]$ ping -c 1 127.0.0.1; whoami

PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=1.03 ms

--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 1.034/1.034/1.034/0.000 ms
21y4d
```
- This is how the output would look on the back-end. 

There is a problem, it says that it needs to match the requested format. In that case, since it hasnt reached out to the server yet, we know that this may be a front-end filter that is restricting the format. 

We can check using firefox devtools

![Developer tools interface showing Network tab. Instructions: Perform a request or click 'Reload' for network activity details. Click stopwatch icon for performance analysis. No requests displayed.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/109/cmdinj_basic_injection_network.jpg)

As we can see, no new network requests were made when we clicked on the `Check` button, yet we got an error message. This indicates that the `user input validation is happening on the front-end`.

This appears to be an attempt at preventing us from sending malicious payloads by only allowing user input in an IP format. `However, it is very common for developers only to perform input validation on the front-end while not validating or sanitizing the input on the back-end.` This occurs for various reasons, like having two different teams working on the front-end/back-end or trusting front-end validation to prevent malicious payloads.

However, as we will see, front-end validations are usually not enough to prevent injections, as they can be very easily bypassed by sending custom HTTP requests directly to the back-end.

----
### Bypassing Front-End Validation
- The easiest method to customize the HTTP requests being sent to the back-end server is to use a web proxy that can intercept the HTTP requests being sent by application. We can intercept the http POST request and then change the data within the request. 

#### Burp POST Request

![HTTP request details in raw format, showing headers like Host, User-Agent, and Content-Type, with IP set to 127.0.0.1.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/109/cmdinj_basic_repeater_1.jpg)

We should also URL encode our data to ensure that it gets processed. 

![[Pasted image 20251201194623.png]]

