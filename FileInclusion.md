# File Inclusion 

We're about to cover all kinds of Inclusion Vulnerabilties, such as:
- Local File Inclusion (LFI)
- Remote File Inclusion (RFI)
- Directory Traversal

Some websites request access to files on a system depending on parametes. If not carefully sanatized, PHP requests can be used to access files we shouldn't be allowed to.

## Path Traversal

Vulnerabilities that lets us navigate/traverse sensitive directories.
This can be done with:

- `file_get_contents`

### Dot-dot-slash vulnerability:
takes advantage of moving the directory one step up using the double dots ../ 

If the attacker finds the entry point, which in this case get.php?file=, then the attacker may send something as follows, http://webapp.thm/get.php?file=../../../../etc/passwd

Some common OS files to check while testing:

| location | Description |
|----------|-------------|
| /etc/issue| contains a message or system identification to be printed before the login prompt.|
|/etc/profile| controls system-wide default variables, such as Export variables, File creation mask (umask), Terminal types, Mail messages to indicate when new mail has arrived |
|/proc/version | specifies the verion of the Linux Kernal| 
|/etc/passwd| has all registered user that has access to a system|
|/etc/shadow| contains information about the system's user's passwords|
|/root/.bash_history/ | contains the history commands for `root` users|
|/var/log/dmessage|contains global system messages, including the messages that are logged during system startup|
|/var/mail/root| all emails for `root` user|
|/root/.ssh/id_rsa| Private SSH keys for a root or any known valid user on the server| 
|/var/log/apache2/access.log| The accessed requests for `Apache` webserver| 
| C:\boot.ini| contains the boot options for computers with BIOS firmware| 

# Local File Inclusion

Typically happen when the devolper has a lack of web security awarness. In PHP functions such as `include`, `require`, `include_once`, and `require_once` contribute to vulnerabilites. 

Languages that are effected by LFI:

- `PHP`
- `ASP`
- `JSP`
- `Node.js`

Same concept as directory traversal.

## Example 1:
Lets say we have a web app that supports two languages, EN and AR:

``` 
<?PHP
    include($_GET["lang"])
>
```
This PHP code uses a `GET` request via the URL paramater `lang` to include the page file. This call can be done by sending a HTTP request. If we wanted EN:

`http://webapp.thm/index.php?lang=EN.php`

If we wanted AR:

`http://webapp.thm/index.php?lang=EN.php`

AR and EN files exist in the same directory.

If there isn't any *`input validation`*, we can access *any* readable file on the server. 
If we wanted the `/etc/passwd` file, we could send a request like:

`http://webapp.thm/index.php?file=/etc/passwd`


## Example 2

In this example, the devolper specified the directory inside the function:
```
<?PHP 
	include("languages/". $_GET['lang']); 
?>
```

The above snippet uses the `include` function to call `PHP` pages in the `languages` directory only via the `lang` parameter.

If there is no input validation, the attacker can manipulate the URL by replacing the `lang` input with other OS-senstive files such as `/etc/passwd`. 

Remeber the dot-dot-slash vulnerability? its like that. We need to navigate back in directories to find our sweet `/etc/passwd` file:

`http://webapp.thm/index.php?lang=../../../../etc/passwd`

Fucking clever.

## Example 3

In Example 1 and Example 2, we checked the web app code, then knew how to exploit it. However if we're in a black box enviroment and don't have access to source code, we can use errors to understand how data gets passed around. 


We have the entry point `http://webapp.thm/index.php?lang=EN`. 

If we enter the invalid input of "THM", we get the following error:

`
Warning: include(languages/THM.php): failed to open stream: No such file or directory in /var/www/html/THM-4/index.php on line 12
`

not only did we learn that "THM" isn't a real directory, but we also learned that the source code contains the function `include(languages/THM.php)`. 

This error also showed us information about the full web application directory path which is `/var/ww/html/THM-4`

To exploit, we can use the dot-dot-slash trick (`../`), except this time we know directory structure, so we know the correct number of `../`'s needed to get to root folder, in this case 4:

`http://webapp.thm/index.php?lang=../../../../etc/passwd`


Fuck! We still get errors:

`Warning: include(languages/../../../../../etc/passwd.php): failed to open stream: No such file or directory in /var/www/html/THM-4/index.php on line 12`

The `include` function reads the input with `.php` at the end! This tells us the devolper specified the type of files (php) allowed to pass in the `include()` function.

To bypass this, we can use the NULL BYTE, which is `%00`. 

Using null bytes is an injection techinque where URL-encoded representation such as `%00` or `0x00` in hex with user-supplied data to terminate strings. Basically its a trick that makes the web app disregards whetever comes after the Null Byte.

This may look like
Fucking cool.

- *The `%00` trick is fixed and not working with PHP 5.3.4 and above*


`include("languages/../../../../../etc/passwd%00").".php");` which is the same as `include("languages/../../../../../etc/passwd");`

/var/ww

## Example 4:

Lets say the develpor decided to filter keywords to avoid disclosing senstive information like `/etc/passwd/`

There are two ways to bypass this filter, either using NullByte `%00` or the current directory trick at the end of the filtered keyword `/.`

We could say `http://webapp.thm/index.php?lang=/etc/passwd/.` or `http://webapp.thm/index.php?lang=/etc/passwd%00`

You know how `cd ..` goes back one directory and `cd .` stays in the same directory? Its like that. `/etc/passwd/.` = `/etc/passwd`. 


## Example 5:

Now its getting real, the devolper is filtering by keywords. Lets say we try:

`http://webapp.thm/index.php?lang=../../../../etc/passwd`

We get the following error!

`Warning: include(languages/etc/passwd): failed to open stream: No such file or directory in /var/www/html/THM-5/index.php on line 15`

If we check the warning message in the `include(languages/etc/passwd)` section, we know the web application replaces `../` with an empty string. There are a couple ways to fuck with it.

First, try this one out: 

`....//....//....//....//....//etc/passwd`

### *Why did this work?*
PHP filter only matches and replaces the first subset string `../`. , so 
....//....//....//....//....//etc/passwd = ../../../../etc/passwd


## Example 6:

What if the devolper forces the `include()` function to read from a defined dictory?

EFor example, if the app asks to supply input that asks to supply input that *has* to include a directory such as: http://webapp.thm/index.php?lang=langues/EN.ph

Thats fine, we'll include it in our input string, and just go back more directories!

`?lang=languages/../../../../../etc/passwd`

Hackers ruin everything :)

# Remote File Inclusion (RFI)

Remote File inclusion is including remote files into vulnerable applications. Like LFI, this happens when user request arnt sanatized correctly, and attackers are able to inject an external URL into `include` function. 

One requirement for RFI is that the `allow_url_fopen` option needs to be `on`.

RFI risk is higher than LFI because RFI vulnerabilities allow  an attacker to gain Remote Command Execution on the server, instead of just reading sensetive files.

Other consequences of a successful RFI attack include:

- Sensitive Information Disclosure
- Cross-site Scripting (XSS)
- Denial of Service (DoS)
  
  An external server must communicate with the application server RFI attack where the attacker hosts they're malicious file. Then the malicious file is injected into the include function via HTTP request and the content of the exploit execute on the application server.


# Prevention

Common preventive steps to prevent inclusion vulnerabilities:

1. Keep system and services, including web application frameworks, updated with the latest version.
2. Turn off PHP errors to avoid leaking the path of the application and other potentially revealing information.
3. A Web Application Firewall (WAF) is a good option to help mitigate web application attacks.
4. Disable some PHP features that cause file inclusion vulnerabilities if your web app doesn't need them, such as allow_url_fopen on and allow_url_include.
5. Carefully analyze the web application and allow only protocols and PHP wrappers that are in need.
6. Never trust user input, and make sure to implement proper input validation against file inclusion.
7. Implement whitelisting for file names and locations as well as blacklisting.