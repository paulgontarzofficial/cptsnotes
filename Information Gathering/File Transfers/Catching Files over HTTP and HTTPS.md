- This is the most common way to transfer files between hosts just because those protocols are enabled on just about every system and through every firewall.

**Using NGINX:**

Creating a Directory to Handle Uploaded Files: 
`realCustampin@htb[/htb]**$** sudo mkdir -p /var/www/uploads/SecretUploadDirectory`

Change the Owner to www-data: 
`realCustampin@htb[/htb]**$** sudo chown -R www-data:www-data /var/www/uploads/SecretUploadDirectory`

Create Nginx Config File:

- create the file /etc/nginx/sites-available/upload.conf

```bash
server {
    listen 9001;

    location /SecretUploadDirectory/ {
        root    /var/www/uploads;
        dav_methods PUT;
    }
}
```

Create a Symlink to the sites-enabled Directory:

`realCustampin@htb[/htb]**$** sudo ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/`

Start Nginx:

`realCustampin@htb[/htb]**$** sudo systemctl restart nginx.service`

Now that we have a server, we can now create our PUT request using cURL:

`realCustampin@htb[/htb]**$** curl -T /etc/passwd <http://localhost:9001/SecretUploadDirectory/users.txt`>

- We use the -T argument to specify that we are uploading a file.