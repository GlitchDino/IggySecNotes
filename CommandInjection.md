# Command Injection (RCE)

Command Injection is abuse of an application's behaviors to execute commands on the operating system, using the same privileges that the application on a device has.

For example, command injection on a server running as user names `joe  ` will execute commands under the   `joe` user, giving us all his privledges.


Remote Code Execution (RCE) is the formal name for command injection, as attacker tricks the application into executing a series of payloads that they provide, without actual acces to the machine itself. 

# Discovering Command Injection

This vulnerability exists becuuse applicaitons often use functions in programming languages such as PHP< Python and NodeJS to pass data to and make system calls on a machine's OS. For example, taking input from a feild and seraching for an entry into a file.

In this example, the app takes data that a user enters into the `$title` feild to search a directory for a song title:

!["Image not found"](images/cmdinject1.png)

Step breakdown:

1. The application stores MP3 files in a directory contained on the operating system.
2. The user inputs the song title they want to find. The application stores the input into the `$title` variable.
3. The data within this `$title` variable is passed to the command `grep` to search a text file named *songtitle.txt* for the entry of whatever the user wants to search for.
4. The output of this search of songtitle.txt will determine whether the application informs the user that the song exists or not.

Typically this shit would be stored in a database, this is just an example of user input turning into commands. 

Abusing applications in this way can be possible regardless of the programming language used. As long as the application processes and executes it, it can result in command injection. For example, this code snippet below is a python application:

!["Image not found"](images/cmdinject2.png)

Explination:

1. The "flask" package is used to set up a web server
2. A function that uses the "subprocess" package to execute a command on the device.
3. We use a route in the webserver that will execute whatever is provided. For example, to execute `whoami`, we'd need  to visit http://flaskapp.thm/whoami

# Exploiting Command Injection

You can often tell if command injection will or will not occure by the behavior of the application. 

Application that use user input to populate system commands with data can often be combined with unintented behavior. **For example, the shell operators `;`, `&` and `&&`**. 

Command Injection can be detected in two ways:

1. Blind command injection
2. Verbose command injection

|Method| Description|
|------|------------|
|Blind| No direct output from the application when testing payloads. You will have to investigate the behaviours of the application to determine wether or not the payload was succesful.|
|Verbose| This type of injection gives direct feedback when testing payloads, like running `whoami` command to see what user the app is running under. The web application will output the username on the page directly.|


## Detecting Blind Command Injection

Blind command injection is when command injection occurs; however, there is no output visible, so it is not immediately noticeable. For example, a command is executed, but the web application outputs no message.


For Blind injection, we will need to use payloads that will cause some time delay. For example, the `ping` and `sleep` commands are significant payloads to test with. Using `ping` as an example, the application will hang for *x* second in relation to the *pings* we specified.

Another method of detecting blind command injection is by forcing some output. This can be done by using redirection operations like `>`. For example, we can tell the app to execute a command like `whoami` and redirect that to a file, then we can use a command like `cat` to read this newly created file's contents.

Testing command injection like this is complicated and takes lots of expirementing, as sytax changes between Linux and Windows.

The `curl` command is a great way to test for command injection. This is because you are able to use `curl` to deliver data to and from an application in your payload. Take this as an example:
```
curl http://vulnerable.app/process.php%3Fsearch%3DThe%20Beatles%3B%20whoami

```

## Detecting Verbose Command Injection

Detecting command injection this way is arguably the easiest method of the two. Verbose command injection is when the application gives you feedback or output as to whats happening.

For example, the output of `ping` or `whoami` would be directly displayed on the web app.

### Useful Payloads

|Payload| Description|
|-------|------------|
|whoami| See what user the application is running under|
|dir| List the contents of the current directory. You may be able to find files such as configuration files, environment files (tokens and application keys), and many more valuable things.|
|ping| This command will invoke the application to hang. This will be useful in testing an application for blind command injection|
|timeout| This command will also invoke the application to hang. It is also useful for testing an application for blind command injection if the ping command is not installed.|

# Remediating Command Injection

Command injection can be prevented in a number of ways. Everything from minimal use of dangerous functions or libaries in a programming langauge to filtering input without relying on a user's input. 

## Vulnerable Functions

In PHP. many functions interact with the operating system to execute commands by shell, including:

- Exec
- Passthru
- System

Also, filtering input to only accept expected input helps. If you're asking for a number input, only accept numbers so `whoami` won't run. 

**Any application that uses these functions without proper sanitation will be vulnerable to Command Injection.**

## Input sanitisation

Sanitising any input from a user that an application uses is a great way to prevent command injection. This is a process of specifying formats or types of data which users can submit.

In this eample, the `filter_input` PHP function is used to check whether or not any data submitted via an input form is a number or not. If it's not a number, the input must be invalid:

!["Image not found"](images/cmdinject3.png)

## Bypassing Filters

Applications use allot of techinques in filtering/sanitising data that is taken from a user input. These filters will restrict you to speficic payloads, but we can abuse the logic behind an application to bypass these filters. For example, an application may strip out quoation marks; we can instead use the hexadecimal value of this to acheive the same result.

When executed, while the formate is changed, it can still be interpeted and executed:

!["Image not found"](images/cmdinject4.png)

