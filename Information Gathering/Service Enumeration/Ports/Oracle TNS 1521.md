Transport Network Substrate (TNS)

- Facilitates the communication between oracle databases and applications over networks. 

## Default Configuration

Location: `$ORACLE_HOME/network/admin`

Listener port = TCP/1521

- Only allows connection from specific hosts and performs basic authentication using a combination of hostnames, IP Addresses, and usernames and passwords. 
- Utilizes Orcale Net Services to encrypt the communications 
- Tnsnames.ora
	- Each database or service name that clients should use when connecting to the service. 
- Listener.ora
	- Defines the listener process's properties and parameters which is responsible for receiving incoming client requests and forwarding them to the Oracle database instance. 
- PL/SQL Execution List
	- User created file that contains the names of the PL/SQL packages or types that should be excluded from execution. 