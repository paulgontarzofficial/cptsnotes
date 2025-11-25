
![[Pasted image 20251125060121.png]]

Many types of injection vulnerabilities are possible within web applications, such as HTTP injection, code injection, and command injection. The most common example, however, is SQL injection. A SQL injection occurs when a malicious user attempts to pass input that changes the final SQL query sent by the web application to the database, enabling the user to perform other unintended SQL queries directly against the database.

There are many ways to accomplish this. To get a SQL injection to work, the attacker must first inject SQL code and then subvert the web application logic by changing the original query or executing a completely new one. First, the attacker has to inject code outside the expected user input limits, so it does not get executed as simple user input. In the most basic case, this is done by injecting a single quote (`'`) or a double quote (`"`) to escape the limits of user input and inject data directly into the SQL query.

Once an attacker can inject, they have to look for a way to execute a different SQL query. This can be done using SQL code to make up a working query that executes both the intended and the new SQL queries. There are many ways to achieve this, like using [stacked](https://www.sqlinjection.net/stacked-queries/) queries or using [Union](https://www.mysqltutorial.org/sql-union-mysql.aspx/) queries. Finally, to retrieve our new query's output, we have to interpret it or capture it on the web application's front end.

--- 
### Databases

Before we learn about SQL injections, we need to learn more about databases and Structured Query Language (SQL), which databases will perform the necessary queries. Web applications utilize back-end databases to store various content and information related to the web application. This can be core web application assets like images and files, content like posts and updates, or user data like usernames and passwords.

There are many different types of databases, each of which fits a particular type of use. Traditionally, an application used file-based databases, which was very slow with the increase in size. This led to the adoption of `Database Management Systems` (`DBMS`).

|**Feature**|**Description**|
|---|---|
|`Concurrency`|A real-world application might have multiple users interacting with it simultaneously. A DBMS makes sure that these concurrent interactions succeed without corrupting or losing any data.|
|`Consistency`|With so many concurrent interactions, the DBMS needs to ensure that the data remains consistent and valid throughout the database.|
|`Security`|DBMS provides fine-grained security controls through user authentication and permissions. This will prevent unauthorized viewing or editing of sensitive data.|
|`Reliability`|It is easy to backup databases and rolls them back to a previous state in case of data loss or a breach.|
|`Structured Query Language`|SQL simplifies user interaction with the database with an intuitive syntax supporting various operations.|
**Architecture**![[Pasted image 20251125060656.png]]

-------
### Types of Databases

A relational database is the most common type of database. It uses a schema, a template, to dictate the data structure stored in the database. For example, we can imagine a company that sells products to its customers having some form of stored knowledge about where those products go, to whom, and in what quantity. However, this is often done in the back-end and without obvious informing in the front-end. Different types of relational databases can be used for each approach. For example, the first table can store and display basic customer information, the second the number of products sold and their cost, and the third table to enumerate who bought those products and with what payment data.

![[Pasted image 20251125061048.png]]

A non-relational database (also called a `NoSQL` database) does not use tables, rows, and columns or prime keys, relationships, or schemas. Instead, a NoSQL database stores data using various storage models, depending on the type of data stored. Due to the lack of a defined structure for the database, NoSQL databases are very scalable and flexible. Therefore, when dealing with datasets that are not very well defined and structured, a NoSQL database would be the best choice for storing such data. There are four common storage models for NoSQL databases:

- Key-Value
- Document-Based
- Wide-Column
- Graph

![[Pasted image 20251125061102.png]]

This would be represented in JSON format: 
```json
{
  "100001": {
    "date": "01-01-2021",
    "content": "Welcome to this web application."
  },
  "100002": {
    "date": "02-01-2021",
    "content": "This is the first post on this web app."
  },
  "100003": {
    "date": "02-01-2021",
    "content": "Reminder: Tomorrow is the ..."
  }
}
```

