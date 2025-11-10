
- In our previous session, we found some basic information that can be rather useful, such as a domain controller, the domains username scheme, among other things. 
- This section we are going to cover a common way t gather credentials and gain an initial foothold during an assessment: A man in the middle attack on Link-Local Multicast Name Resolution and NetBIOS Name Service broadcasts. 
- LLMNR and NBT-NS can provide us with some password hashes that we can then crack offline. 

### LLMNR & NBT-NS Primer

- These services are Microsoft Windows components that serve as an alternate methods of host identification that can be used when DNS fails. If a machine can resolve a host but DNS fails, that machine will then reach out on the local network for the correct host address via LLMNR. 
- LLMNR uses port 5355 over UDP
- If LLMNR fails, then NBT-NS will be used over port 137/UDP. 

How can we use **Responder** to abuse this:

- We can use responder to poison these requests that are sent. Assuming we already have network access, we can spoof an authoritative name resolution source in the broadcast domain by responding to LLMNR and NBT-NS traffic as if they have an answer for the requesting host. 

Let's walk through a quick example of the attack flow at a very high level:

1. A host attempts to connect to the print server at \\\print01.inlanefreight.local, but accidentally types in \\\printer01.inlanefreight.local.
2. The DNS server responds, stating that this host is unknown.
3. The host then broadcasts out to the entire local network asking if anyone knows the location of \\printer01.inlanefreight.local.
4. The attacker (us with `Responder` running) responds to the host stating that it is the \\printer01.inlanefreight.local that the host is looking for.
5. The host believes this reply and sends an authentication request to the attacker with a username and NTLMv2 password hash.
6. This hash can then be cracked offline or used in an SMB Relay attack if the right conditions exist.

