- Many web apps employ custom login forms as their primary authentication mechanism. These forms often share common underlying mechanics that make them targets for brute forcing. 

**Understanding Login Forms**
- While login forms may appear as simple boxes soliciting your username and password, they represent a complex interplay of client-side and server-side technologies. At their core, login forms are essentially HTML forms embedded within a webpage. These forms typically include input fields (`<input>`) for capturing the username and password, along with a submit button (`<button>` or `<input type="submit">`) to initiate the authentication process.

### A Basic Login Form Example

```html
<form action="/login" method="post">
  <label for="username">Username:</label>
  <input type="text" id="username" name="username"><br><br>
  <label for="password">Password:</label>
  <input type="password" id="password" name="password"><br><br>
  <input type="submit" value="Submit">
</form>
```
- This form, when submitted, sends a POST request to the /login endpoint on the server, including the entered username and password as form data. 

```http
POST /login HTTP/1.1
Host: www.example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 29

username=john&password=secret123
```
- The `POST` method indicates that data is being sent to the server to create or update a resource.
- `/login` is the URL endpoint handling the login request.
- The `Content-Type` header specifies how the data is encoded in the request body.
- The `Content-Length` header indicates the size of the data being sent.
- The request body contains the username and password, encoded as key-value pairs.