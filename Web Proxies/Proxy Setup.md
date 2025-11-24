
In many cases, we may want to use a real browser for pentesting, like Firefox. To use Firefox with our web proxy tools, we must first configure it to use them as the proxy. We can manually go to Firefox preferences and set up the proxy to use the web proxy listening port. Both Burp and ZAP use port `8080` by default, but we can use any available port. If we choose a port that is in use, the proxy will fail to start, and we will receive an error message.


- In case we wanted to serve the web proxy on a different port, we can do that in Burp under (`Proxy>Proxy settings>Proxy listeners`)

### Guided Setup

![[Pasted image 20251124101419.png]]
- First we need to install FoxyProxy in Firefox
- Next, let's click options in the menu. 

![[Pasted image 20251124101455.png]]
- Add the following parameters into the boxes, of course tailor this to your own install, then click save. 

![[Pasted image 20251124101540.png]]
- After that is done, we can then go into our menu and then click our newly created Burp proxy.

--------
### Installing CA Certificate
- Another important step when using Burp Proxy/ZAP with our browser is installing the web proxy's CA Certificates. If we don't do this step, some HTTPS traffic may not get properly routed, or we may need to click `accept` every time Firefox needs to send an HTTPS request.

![[Pasted image 20251124101827.png]]
- Go to http://burp
- Click on CA Certificate box in the top right. 

![[Pasted image 20251124101858.png]]
- Go into firefox settings and go to the "View Certificates" tab in the menu. 

![[Pasted image 20251124101935.png]]
- Once we get to this menu, we can then import the cert we just downloaded. 

![[Pasted image 20251124102005.png]]
- Make sure these settings are checked above and then press OK. 

