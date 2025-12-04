If we capture the upload request with `Burp`, we see the following request being sent by the web application:

![HTTP POST request to /upload.php with file HTB.png, content type image/png.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/136/file_uploads_image_upload_request.jpg)

The web application appears to be sending a standard HTTP upload request to `/upload.php`. This way, we can now modify this request to meet our needs without having the front-end type validation restrictions. If the back-end server does not validate the uploaded file type, then we should theoretically be able to send any file type/content, and it would be uploaded to the server.

The two important parts in the request are `filename="HTB.png"` and the file content at the end of the request. If we modify the `filename` to `shell.php` and modify the content to the web shell we used in the previous section; we would be uploading a `PHP` web shell instead of an image.

So, let's capture another image upload request, and then modify it accordingly:

![HTTP POST request to /upload.php with file shell.php, response 200 OK, file successfully uploaded.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/136/file_uploads_modified_upload_request.jpg)

### Disabling Front-end Validation
