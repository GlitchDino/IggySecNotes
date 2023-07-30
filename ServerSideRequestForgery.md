# Server Side Request Forgery (SSRF)

SSRF is a vulnerability that allows attacker to cause a webserver to make additional or edited HTTP requested to any resources the attacker wants.

There are two types of SSRF vulnerabilities:

1. Regular SSRF: Data is returned to the attacker's screen
2. Blind SSRF: SSRF occurs, but no information is returned to the attacker's screen.

Impact:
- Access to unauthorized areas
- Acces to customer/orginizational data
- Ability to Scale to internal networks
- Reveal authentication tokens/creditials
  
When requesting URLs, we can use `&x=` to ignore the rest of the URL, its like `%00`


# Finding an SSRF

There are many ways to spot SSRF vulnerabilities. Here are 4 common places to look:

### When a full url is used in a parameter in the address bar:

https://website.thm/form?server=<mark>http://server.website.thm/store</mark>

### A hidden field in a form:

![Image not loading, you such](images/hidden_feild_ex.png)

### A partial URL such as just the hostname:

https://website.thm/form?server=<mark>api</mark>

### Or only the path of the URL:

https://website.thm/form?dst=<mark>/forms/contact</mark>

Some of these examples are easier to fuck than others, trial and error is to be expected. 

When working a blind SSRF, there is no output to be reflected back. An external HTTP logging tool will be required to monitor requests, such as:
- requestbin.com
- Personal HTTP server
- Burp Suite's Collaborator Client


# Defeating Common SSRF Defenses

Devs may impliment 2 types of checks to make sure request resources meets specific rules:

## Deny List

Def: All requests are accepted apart from resources specified in a list or matching a particular pattern. This may be used over a Allow List because an Allow List might include senstive endpoints/IP addresses/Domains. 

Often localhost/127.0.0.1 domains are on deny lists. Attackers may bypass Deny Lists by using alternative localhost refrences such as 0, 0.0.0.0, 0000, 127.1, 127.*.*.*, 2130706433, 017700000001, or subdomains that have a DNS record which resolves to the IP Address 127.0.0.1 such as 127.0.0.1.nip.io

In a cloud enviroment, it would be beneficial to block access to the IP address 169.254.169.254, which contains metadata for the deployed cloud server, including possibly sensitive information. An attacker could bypass this by registering a subdomain on their own domain with a DNS record that points to the IP address 169.254.169.254

## Allow list

Allow list is where every request is denied unless they appear on a list or match a particular pattern, like every url must begin with `https://website.thm`

A hacker could bypass this by creating a subdomain on a hacker's domain name, such as `https://website.thm.evil-domain.thm`

## Open Redirct

If the above bypasses dont work, there's open redirect. An open redirct is an endpoint on the server where the vistor automatically gets redirected to another website address. Take for example: `https://website.thm/link?url=https://tryhackme.com`
This endpoint was created to record the number of times visitors have clicked on this link for advertising/markteting purposes. But imagine stricks rules which only allow urls begining with https://website.thm/, a attacker could use this feature to redirct the HTTP request to a malicous domain.

### Little trick:

Lets say have a button that sends a URL request to a `/img/whatever` and we change it to our protected `/private` URL we're trying to hit. 

If it doesn't work, its fair to assume `/private` is on a deny list. To bypass this, we could do:

`x/../private`

background-image: url(data:image/png;base64,)