# Structured Query Language Injection (SQLi)

An attack on web application database servers that cause malicious queries to be executed. When a web application communicates with a database using input from a user that hasn't properly validated, there runs the potential of an attacker being able to steal, delete, or alter private and customer data and attack web app authentication methods to private or customer areas. This is why as well as SQLi being one of the oldest vulnerabilities, it is also one of the most damaging.

# Whats a database?

Some useful terminology.

## What is a database?

A way of electronically storing collections of data in an organised manner. A database is controlled by a **Database Managment System (DBMS)**. DBMS's fall into two catigories:
**Relational** and **Non-Relational**. These notes focuse on **Relational** databases. 

Common Relational Databases:
- MySQL
- Microsoft SQL Server
- Access
- PostgreSQL
- SQLite

With a DBMS, you can have multiple databases, each containing its own set of related data. For example, you may have a database called **"Shop"**. Within the database you'll want to store products that are available to **purchase**, **users** who have signed up to your online shop, and information about the **orders** you've recieved. You'd store this info in seprate databases using something called `tables`, which are identified with a unique name for each one. You can see this structure in the diagram below, but you can also see how buisness might have separate databases to store staff info or the accounts team.


!["Image not found"](images/database1.png)

## What are tables?

A table is made up of columns and rows:
!["image not found"](images/db2.png)

## Columns:

Each column, better referred to as a field has a unique name per table. When you create a column, you set the type of data it'll contain, like integers, strings or dates. Some databases can contain more complex data like geospatial (location information). Setting data type helps ensure incorrect info isn't stored. 

A column may also contain an auto-increment feature, which gives each row of data a unique number that grows with each subsequent row,  which creates a **key** feild, a key feild has to be unique for every  row of data which can be used to find that exact row in SQL queries.

## Rows:

Rows or record are what contains the individual lines of data. When you add data to the table, a new row/record is created, and removed when deleted.

## Relational vs. Non-Reational Databases:

Relational database: 

Stores information in tables and often the tables have shared information between them, they use columns to specify and define the data being stored and rows to actually store data. The tables will often contain a column that has a unique ID (Primary Key) which will then be used in other tables to refrence it and cause a relationship between the tables, hence the **relational** database.

Non-relational databases:

Sometimes called NoSQL, any sort of databse that doesn't use tables, columns and rows to store the data, a specific database layout doesn't need to be constructed so each row of data can contain different info, which allows for more flexibility than Relational Databases.

# What is SQL?

SQL (Structured Query Language) is a feature-rich language used for querying databases, then SQL queries are better referred to as statements.

Although somewhat similar, some databases servers have their own syntax and slight changes to how things work. All of these examples are based on a MySQL datbase, but it'll be easy to search for alternative syntax online for the different servers. It's worth noting that SQL syntax is not case sensitive.

## SELECT
The SELECT query is used to retrieve data from the database:

```
select * from users;
```

|id|username|password|
|--|--------|--------|
|1|jon|pass123|
|2|admin|p4ssword|
|3|martin|secret123|


**select** tells the database we want to retrieve some data

**\*** tells the database we want all columns from the table.

**from users** tells the database we want to retrieve the data from the table named users. 

Finally, the semicolon **;** at the end tells the database that this is the end of the query.

If we instead said:

```
select username,password from users;
```
We'd get:
|username|password|
|--------|--------|
|jon|pass123|
|admin|p4ssword|
|martin|secret123|

If we added `LIMIT 1` to our query, it'll only return 1 row of data. `LIMIT 1,1` forces the query to skip the first result, and `LIMIT 2,1` skips the first two results, etc:

```
select * from users LIMIT 1;
```
Returns:

|username|password|
|--------|--------|
|jon|pass123|

If we wanted to search for exact data, we could use **where:**

```
select * from users where username='admin';
```
Returns:
|username|password|
|--------|--------|
|admin|p4ssword|

If we wanted the opposite:
```
select * from users where username!='admin';
```
|username|password|
|--------|--------|
|jon|pass123|
|martin|secret123|

We can also use OR:
```
select * from users where username='admin' or username='jon';
```
|username|password|
|--------|--------|
|jon|pass123|
|admin|p4ssword|

Or we can use AND:
```
select * from users where username='admin' and password='p4ssword';
```

|username|password|
|--------|--------|
|admin|p4ssword|

Using the **like** cause we can find data that isn't an exact match, but either starts, contains or ends with certain characters by choosing where to place the wildcard character represented by a percent sign.

Lets say we wanted to return any row where the username starts with the letter a:

```
select * from users where username like 'a%';
```

|id|username|password|
|--|--------|--------|
|2|admin|p4ssword|


Lets say we want any any username that contains the letter n:
```
select * from users where username like '%n';
```
|id|username|password|
|--|--------|--------|
|1|jon|pass123|
|2|admin|p4ssword|
|3|martin|secret123|

Or we wanted any row containing **mi** within them:
```
select * from users where username like '%mi%';
```
|id|username|password|
|--|--------|--------|
|2|admin|p4ssword|


## UNION

The UNION statement combines the results of two or more SELECT statements to retrieve data from either single or multiple tables; the rules to this query are that the UNION statemnts must retrieve the same number of columns in each SELECT statement, and collumns have to be of similar data type and the column order has to be the same.

Lets say we want to select the results from Customers table and Suppliers table with one command. we could use UNION:

```
SELECT name,address,city,postcode from customers UNION SELECT company,address,city,postcode from suppliers;
```

## INSERT

The **INSERT** statement tells the database we wish to insert a new row of data into the table. **"into users** tells the database which table we wish to insert the data into, **"(username, password)"** provides the columns we are providing data for and the **"values('bob','password');"** provides the data for the previously specified column:
```
insert into users (username,password) values ('bob','password123');
```
|id|username|password|
|--|--------|--------|
|1|jon|pass123|
|2|admin|p4ssword|
|3|martin|secret123|
|4|bob|password123|

## UPDATE

The **UPDATE** statement tells the database we want to update one or more rows of data within a table. You specify the table you wish to update using **"update %tablename% SET"** and then select the field or fields you wish to update as a comma-separated list such as **"username='root',password='pass123'"** then finally you can specify exactly which row to update using the where clause such as **"where username=
'admin';"**.

```
update users SET username='root',password='pass123' where username='admin';
```
|id|username|password|
|--|--------|--------|
|1|jon|pass123|
|2|admin|p4ssword|
|3|martin|secret123|
|4|bob|password123|

## DELETE 
The **DELETE** statements tells the database we want to delete one or more rows of data. Apart from missing the columns you wish to be returned, the format of this query is very similar to SELECT. You can specify precisely which data to delete using **where** and the number of rows to delete using the **LIMIT** clause.

```
delete from users where username='martin';
```
|id|username|password|
|--|--------|--------|
|1|jon|pass123|
|2|admin|p4ssword|
|4|bob|password123|

To delete everything from users, we can run:

```
delete from users;
```


# What is an SQL injection

A point of entry where a web application using SQL can turn into SQL Injection is when user-provided data gets included in the SQL query.

## What does it look like?

Take this URL for a blog entry:

https://website.thm/blog?id=1

From the URL you can tell the blog entry has been selected comes from the id parameter in the query string. The web application needs to retrieve the article from the database and may use an SQL statement that looks something like the following:

```
SELECT * from blog where id=1 and private=0 LIMIT 1;
```

`private=0` tells us that the entry may be accessed by the public.

Lets say article id 2 is private. we could now instead call the URL:
```
https://website.thm/blog?id=2;--
```
Which produces the SQL statement:
```
SELECT * from blog where id=2;-- and private=0 LIMIT 1;
```
**The semicolon in the URL signifies the end of the SQL statement, and the two dashes causes everything after to be treated as a column** By doing this, you're just asking:

```
SELECT * from blog where id=2;--
```
Which will return aricle id=2 wether or not it's public or private.

## In-Band SQLi

In-Band SQL Injection is the easiest type of SQLi to detect and exploit. 
In-Band means that the same method we use to exploit we also use to recieve the results, like extracting data from a database using SQL on a certian page and displaying it on the same page.

## Union-Based SQL

Uses the SQL UNION operator alongside a SELECT statement to return additional results to the page, this being the most common way to extract large amounts of data via an SQL Injection vulnerbility. 

## Error-Based SQL 

This type of injection is useful for easily obtaining information about the database structure as error messages from the database are printed directly to the browsers screen. 

# Blind SQLi- Authentication Bypass

Blind SQLi means no feedback from the server, likely because the devolper disabled error messages, yet we're still able to do SQL injections.

## Authentication Bypass 

SQL doesn't always have to be getting data, we can sometimes use it to get passed logins.

Often login forms connected to databases dont care about the contents of the username and password feild, but do care about there being a matching password/username feild. Depending on what's returned, we get access.

This means we dont care about getting a username/password match, we just need to create a database that returns yes/true.

We could say sum like:

```
select * from users where username='' and password='' OR 1=1;
```

by putting `' OR 1=1;--` in the password feild, we'll return a login thats true because 1=1.


## Blind SQLi - Boolean Based

Boolean based SQL Injection refers to the response we get from our SQL injections, which may be true/false, yes/no, on/off, 1/0, or any response where 1=1. This could allow us to enumerate a whole database structure and contents.

Just reveiw the unit for this.

## Blind SQLi - Time Based

This is like Boolean Based SQLi, we enumerate the database by seeing what works and what doesnt, but instead of figuring it out by error messages, we measure how long responses take. 

We can add a SLEEP(5) to our query, and if theres an instant response, we know our request was invalid. 

# Remediation

As impactful as SQL Injection vulnerabilities are, we can still prevent them.

## Prepared Statements (W/ parameterized Queries)

A prepared query means a devolper writes an SQL query that user data is added to afterwords, thus the database can tell the difference between the query and the input data.

## Input Validation

Input validation can go a long way to protecting what gets put into an SQL query. Employing an allow list can restrict input to only certain strings, or a string replacement method in the programming language can filter the characters you wish to allow or disallow. 

## Escaping User Input

Allowing user input containing characters such as ' " $ \ can cause SQL Queries to break or, even worse, as we've learnt, open them up for injection attacks. Escaping user input is the method of prepending a backslash (\) to these characters, which then causes them to be parsed just as a regular string and not a special character.
