## SELECT Statement

Now that we have inserted data into tables let us see how to retrieve data with the [SELECT](https://dev.mysql.com/doc/refman/8.0/en/select.html) statement. This statement can also be used for many other purposes, which we will come across later. The general syntax to view the entire table is as follows:

Code: sql

```sql
SELECT * FROM table_name;
```

The asterisk symbol (*) acts as a wildcard and selects all the columns. The `FROM` keyword is used to denote the table to select from. It is possible to view data present in specific columns as well:

Code: sql

```sql
SELECT column1, column2 FROM table_name;
```

The query above will select data present in column1 and column2 only.

  SQL Statements

```shell-session
mysql> SELECT * FROM logins;

+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  1 | admin         | p@ssw0rd   | 2020-07-02 00:00:00 |
|  2 | administrator | adm1n_p@ss | 2020-07-02 11:30:50 |
|  3 | john          | john123!   | 2020-07-02 11:47:16 |
|  4 | tom           | tom123!    | 2020-07-02 11:47:16 |
+----+---------------+------------+---------------------+
4 rows in set (0.00 sec)


mysql> SELECT username,password FROM logins;

+---------------+------------+
| username      | password   |
+---------------+------------+
| admin         | p@ssw0rd   |
| administrator | adm1n_p@ss |
| john          | john123!   |
| tom           | tom123!    |
+---------------+------------+
4 rows in set (0.00 sec)
```

The first query in the example above looks at all records present in the logins table. We can see the four records which were entered before. The second query selects just the username and password columns while skipping the other two.

## DROP Statement

We can use [DROP](https://dev.mysql.com/doc/refman/8.0/en/drop-table.html) to remove tables and databases from the server.

  SQL Statements

```shell-session
mysql> DROP TABLE logins;

Query OK, 0 rows affected (0.01 sec)


mysql> SHOW TABLES;

Empty set (0.00 sec)
```

As we can see, the table was removed entirely.

## ALTER Statement

Finally, We can use [ALTER](https://dev.mysql.com/doc/refman/8.0/en/alter-table.html) to change the name of any table and any of its fields or to delete or add a new column to an existing table. The below example adds a new column `newColumn` to the `logins` table using `ADD`:

  SQL Statements

```shell-session
mysql> ALTER TABLE logins ADD newColumn INT;

Query OK, 0 rows affected (0.01 sec)
```

To rename a column, we can use `RENAME COLUMN`:

  SQL Statements

```shell-session
mysql> ALTER TABLE logins RENAME COLUMN newColumn TO newerColumn;

Query OK, 0 rows affected (0.01 sec)
```

We can also change a column's datatype with `MODIFY`:

  SQL Statements

```shell-session
mysql> ALTER TABLE logins MODIFY newerColumn DATE;

Query OK, 0 rows affected (0.01 sec)
```

Finally, we can drop a column using `DROP`:

  SQL Statements

```shell-session
mysql> ALTER TABLE logins DROP newerColumn;

Query OK, 0 rows affected (0.01 sec)
```

We can use any of the above statements with any existing table, as long as we have enough privileges to do so.

## UPDATE Statement

While `ALTER` is used to change a table's properties, the [UPDATE](https://dev.mysql.com/doc/refman/8.0/en/update.html) statement can be used to update specific records within a table, based on certain conditions. Its general syntax is:

Code: sql

```sql
UPDATE table_name SET column1=newvalue1, column2=newvalue2, ... WHERE <condition>;
```

We specify the table name, each column and its new value, and the condition for updating records. Let us look at an example:

  SQL Statements

```shell-session
mysql> UPDATE logins SET password = 'change_password' WHERE id > 1;

Query OK, 3 rows affected (0.00 sec)
Rows matched: 3  Changed: 3  Warnings: 0


mysql> SELECT * FROM logins;

+----+---------------+-----------------+---------------------+
| id | username      | password        | date_of_joining     |
+----+---------------+-----------------+---------------------+
|  1 | admin         | p@ssw0rd        | 2020-07-02 00:00:00 |
|  2 | administrator | change_password | 2020-07-02 11:30:50 |
|  3 | john          | change_password | 2020-07-02 11:47:16 |
|  4 | tom           | change_password | 2020-07-02 11:47:16 |
+----+---------------+-----------------+---------------------+
4 rows in set (0.00 sec)
```

The query above updated all passwords in all records where the id was more significant than 1.