# Recon (WEB)

## Manual

### Robot.txt

The robots.txt file is a document that tells search engines which pages they are and aren't allowed to show on their search engine results or ban specific search engines from crawling the website altogether. It can be common practice to restrict certain website areas so they aren't displayed in search engine results. These pages may be areas such as administration portals or files meant for the website's customers. This file gives us a great list of locations on the website that the owners don't want us to discover as penetration testers.

### Sitemap.xml

Unlike the robots.txt file, which restricts what search engine crawlers can look at, the sitemap.xml file gives a list of every file the website owner wishes to be listed on a search engine. These can sometimes contain areas of the website that are a bit more difficult to navigate to or even list some old webpages that the current site no longer uses but are still working behind the scenes.

## OSINT

#### Wappalyzer

Wappalyzer (https://www.wappalyzer.com/) is an online tool and browser extension that helps identify what technologies a website uses, such as frameworks, Content Management Systems (CMS), payment processors and much more, and it can even find version numbers as well.

### Wayback Machine

The Wayback Machine (https://archive.org/web/) is a historical archive of websites that dates back to the late 90s. You can search a domain name, and it will show you all the times the service scraped the web page and saved the contents. This service can help uncover old pages that may still be active on the current website.

### Github

You can use GitHub's search feature to look for company names or website names to try and locate repositories belonging to your target. Once discovered, you may have access to source code, passwords or other content that you hadn't yet found.

### S3 Buckets

S3 Buckets are a storage service provided by Amazon AWS, allowing people to save files and even static website content in the cloud accessible over HTTP and HTTPS. The owner of the files can set access permissions to either make files public, private and even writable. Sometimes these access permissions are incorrectly set and inadvertently allow access to files that shouldn't be available to the public. The format of the S3 buckets is http(s)://{name}.s3.amazonaws.com where {name} is decided by the owner, such as tryhackme-assets.s3.amazonaws.com. S3 buckets can be discovered in many ways, such as finding the URLs in the website's page source, GitHub repositories, or even automating the process. One common automation method is by using the company name followed by common terms such as {name}-assets, {name}-www, {name}-public, {name}-private, etc.

### Google Dorking

## Automation

Basically brute-forcing useful web domains of a website. A couple useful tools:

- ffuf
- dirb (better)
- gobuster


# Subdomain enumartion

Finding valid subdomains to find more potential security holes.
This can be done through Brute Force, OSINT and Virtual Hosting.

## OSINT

### SSL/TLS Certificates

When SSL/TLS certifaces are created for a domain by a CA (Certificate Authority), CA's record Certifacte Transparency (CT) logs. These logs are publically accesable, to prevent malicous or accidental certs being used.

Some sites offer searchable databases of certificates with current/historical results, which may be used to find sub-domains.

- https://crt.sh
- https://ui.ctsearch.entrust.com/ui/ctsearchui



### Search Engines

Search engines contain trillions of links to more than a billion websites, which can be an excellent resource for finding new subdomains. Using advanced search methods on websites like Google, such as the site: filter, can narrow the search results. For example, "-site:www.domain.com site:*.domain.com" would only contain results leading to the domain name domain.com but exclude any links to www.domain.com; therefore, it shows us only subdomain names belonging to domain.com.

- -site:www.example.com
- site:*.example.com

### Automate with Sublist3r

Sublist3r is a tool that automates the previous OSINT methods of discovering host domains. Very useful, very quick, but doesn't always capture everything, so be sure to do due-diligence on other methods.

## Brutforce

### DNS Bruteforce

Brute-forcing common subdomains.
Tools:
- dnsrecon