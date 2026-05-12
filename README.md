Typosquatting drew attention by making its “big comeback" through the news: TeamPCP utilized typosquatted domains to mimic legitimate vendor identities, facilitating seamless blending into CI/CD logs. Here is the recommended reading from [Crowdstrike](https://www.crowdstrike.com/en-us/blog/the-art-of-deception-how-threat-actors-master-typosquatting-campaigns-to-bypass-detection/) and [Proofpoint](https://www.proofpoint.com/us/threat-reference/typosquatting). There is an opinion among some cybersecurity professionals that typosquats are a low level cyber impersonation attack that “nothing we can do about”. I strongly disagree (please refer to my [Investigating Phishing Incidents)](https://github.com/lizfrenz/Investigating-Phishing-Incidents): we can report typosquats, we can block them for enterprise email users, we can monitor typosquats for malicious behavior, in some cases we can initiate a takedown, and tracking typosquats could be a way to track adversary activity. 

## Types of Typosquats

The categories of typosquatting for **domain\[.\]com** would be:

1. Character Omission **doman\[.\]com**  
2. Character Substitution (homoglyph/homograph attack) **d0main\[.\]com**   
3. Character Duplication **doomain\[.\]com**  
4. Letter Transposition **domian\[.\]com**  
5. Adjacent Key Substitution **donain\[.\]com**  
6. Incorrect TLDs **domain\[.\]cm**

## Information Collection 

You can use the tools you are comfortable with to collect information you need. I prefer to use a blend of bash commands and OSINT tools in my investigations. There are some useful commands you can use on your terminal to determine the origin of a domain.

| Bash | Explanation |
| ----- | ----- |
| whois | Display domain Registrar and Registrant information |
| nslookup | Translates a website name into its actual IP address |
| openssl s\_client \-connect yourexample.tld:443 \-servername yourexample.tld  | This will print a successful TLS handshake and valid certificate chain. CTRL+C/CTRL+ D to close the session |
| echo | openssl s\_client \-connect yourexample.tld:443 \-servername yourexample.tld 2\>/dev/null | \\ openssl x509 \-noout \-subject \-issuer \-nameopt multiline | \\ grep \-E "organizationName"  | This would print the certificate issuer organization. Watch out for self-signed certs.  |
| DOMAIN="yourexample.tld"; echo | openssl s\_client \-connect $DOMAIN:443 \-servername $DOMAIN 2\>/dev/null | openssl x509 \-noout \-subject \-issuer | sed \-e 's/subject=/Issued to: /' \-e 's/issuer=/Issued by: /' | This should print the organization name that issued the cert and whom the cert was issued to. |
| amass enum \-d yourexample.tld \> output.txt  | This will print hidden subdomains. Warning, this might take time, hence my preference would be dnsdumpster.com  |

## Analysis

It should be noted that at the end of this exercise you might not be able to attribute a typosquatting to its owner or a threat actor, however by collecting and recording this information repeatedly, you would start have a very clear picture what tools the adversary that target your org may use trying to impersonate your organization. 

Imagine you are creating the blueprint for your future typosquat automated investigation. What data would be useful? How would you score signals? For now let’s add \+1 if there is a “grey” signal. Let start with the spreadsheet – header is the information categories you’d like to collect. What would go in there? 

| Header | Signal |
| ----- | ----- |
| Domain Name | Potential typosquat |
| Updated Date | Extensions, changes in the dns and other records  |
| Creation Date \+1 | Is it new? If yes, could be a signal, add a score for the typosquat. |
| Expiry Date \+1 | How soon is it set to expire? If it’s 60 or 90 days, I would consider it as a red flag. When using for legitimate needs, you want to avoid abrupt expiration and probably tend to buy/renew every year. |
| Registrant  Name  | Although “REDACTED FOR PRIVACY” is not that uncommon, especially in the EU, this would be a sign of owner identity obfuscation. |
| Registrant Organization \+1 | “REDACTED FOR PRIVACY”. When you are analyzing a typosquat for a potential impersonation of the US entity (financial or tech) this is a big red flag.   |
| Registrant Address | The same as above. Be aware if the identity is protected by a privacy provider, the provider’s address may appear here. |
| Registrar  \+1 | Here we are looking at how thorough the Registrar is with the identity verification. Would they require a credit card or would they accept crypto? Consult the Registrar list below for potential red flags (Add \+1). |
| IP  \+2 | Nslookup output, alternatively you can use [abuseipdb.com](http://abuseipdb.com) that automatically convert domain names into an IP address. Now when you have the IP, what is the verdict: Malicious, Suspicious, Benign, or Unknown.  Add \+2 for Malicious and \+1 for Suspicious. |
| ISP  \+1 | Is the ISP a Bulletproof hosting provider? If the ISP is privacy oriented and maintains a low level of identity verification? If yes, add \+1. |
| Domain | Is it the same or different?  |
| Country/City   \+1 | Is the location unusual for this organization? Add \+1 |
| TLS Certificate Issuer  \+1 | Also known as a Certificate Authority (CA), is a trusted third-party that verifies the identity of website owners and issues digital certificates to enable encrypted HTTPS connections. If the CA circumvents the identity vetting process, it may result in abuse. Please consult with the Certificate Authorities List, add \+1 for those that are on the list. |
| TLS Certificate CN  \+1 | CN or a Common Name is a specific field in an X.509 certificate that identifies the primary domain name or server hostname. Cross-reference the CN and domain, and host-name. Are they different or the same? Add \+1 if different. |
| Footprint A,NS, MX,TXT records  \+1 | The core DNS records defining a domain's internet infrastructure:  **"A" Records** (Servers): map a domain name to a specific IP address. **"MX" Records** (Mail):  Mail exchange records direct email traffic for a domain to the appropriate mail servers. **"TXT" Records** (Policies): Text records are used to hold machine-readable data, commonly for security and verification purposes. **"NS" Records** (Traffic Directors): Nameserver records identify the authoritative servers that store a domain's A, MX, and TXT records. For continuous analysis you would need to document each record separately. In time you would be able to track if the adversaries who target your organization (or your customers) reuse infrastructure.  The immediate benefits of DNSdumpster\_DOT\_com: you can see if there is a well developed infrastructure or not; if there is a danger of a phishing campaign or not; if the infrastructure is geographically dispersed; you can infer how adversary plans using this infrastructure based of the subdomains reading. For example: adminDOTgrayserverDASH\_aws\[.\]com or huggingface\[.\]grayserver-cloud\[.\]net. |
| Sandbox Analysis \+2 | You can use a sandbox of your choice. I prefer Hybrid Analysis, because HA compares data from several vendors, analyzes artifacts from multiple submissions, maps threats to TTPs, and supplies a screenshot of the analyzed URL. And, most importantly, it’s free\! If the verdict is malicious, add \+2 into your qualitative analysis. If there are red flags, but the verdict is Unknown, feel free to add \+1. |

After you document the signals, you can calculate certainty by adding the score. A score of 11 to 13 indicates the highest certainty. Scores from 7 to 10 represent high certainty, 4 to 6 indicate moderate certainty, and 1 to 3 reflect low certainty. A score of 0 denotes the least certainty, meaning it is certain that it is not.

## 🚩Registrars Lists 🚩

Note, that this list doesn’t take under consideration local provider that may grant promotional credits for domain registration: 

* **Hostinger:** Includes a free domain for the first year with annual Premium and Business hosting plans, covering extensions such as “com”,”net”, “ai”, and “io”.  
* **Wix**: Provides a free domain for one year when purchasing a premium website builder plan of 12 months or longer.  
* **IONOS**: Offers a free domain for the first 12 months with its annual hosting subscriptions.  
* **Bluehost**: Gives users a free domain for the first year when signing up for their web hosting packages.  
* **Squarespace**: Includes a free domain name for the first year with their annual website builder plans.  
* **Name.com and Namecheap**: Both registrars partner with the GitHub Student Developer Pack to offer verified students a free domain for one year on select extensions (such as “rocks”, “ninja", and “me").  
* **Ecwid**: Provides a free domain name with any of its paid annual e-commerce plans.

## 🚩Certificate Authorities List 🚩

Here is a list of **Primary Certificate Authorities** (CAs) and digital infrastructure providers that offer free TLS/SSL certificates as of 2026:

* **Let's Encrypt:** The largest and most popular non-profit CA, providing completely free 90-day Domain Validation (DV) certificates. It supports wildcards, allows up to 100 subject names per certificate, and is widely automated across the internet using the ACME protocol.  
* **Google Trust Services (GTS):** Google offers free, publicly-trusted 90-day TLS certificates via its ACME API. It supports wildcards and up to 100 Subject Alternative Names (SANs) per certificate. To use this service, you must use a Google Cloud Platform (GCP) account to generate the required External Account Binding (EAB) credentials.  
* **ZeroSSL:** Operated by HID Global, ZeroSSL provides free 90-day certificates with wildcard and multi-domain support. While generating certificates manually through their web UI is limited to just 3 manual certificates, users who automate the process via the ZeroSSL ACME API can generate an unlimited amount of free 90-day certificates.  
* **Actalis:** An Italian CA that provides free 90-day DV certificates covering a single domain plus its "www" variant. It supports unlimited issuance via ACME, but unlike Let's Encrypt or Google, it does not support wildcard certificates on its free tier.  
* **SSL.com:** Offers a free 90-day DV certificate option covering one domain and its "www" subdomain. These certificates can be ordered using the ACME protocol and require EAB for registration.

**Infrastructure Provider:**

* **Cloudflare:** Offers free "Universal SSL" which encrypts traffic strictly between website visitors and Cloudflare's CDN. Cloudflare also provides free "Origin CA" certificates to encrypt traffic between their network and your origin server, though it is important to note that these origin certificates are not inherently trusted by standard web browsers on their own.  
* **FreeSSL.org & SSLForFree:** These are web-based platforms that provide an easy-to-use interface to generate free 90-day certificates without needing extensive command-line knowledge. Rather than being independent CAs, they act as user-friendly wrappers powered by backend ACME CAs like ZeroSSL or Let's Encrypt.

## 🚩Bulletproof Hosting List 🚩

Here is a recommended reading about bulletproof hosting (BPH). Most providers are based in regions outside of US/EU jurisdiction to ignore takedown requests. BPH offers advanced DDOS protection, anonymity/privacy-oriented server management.

* **Ultahost**: Top-rated for high-speed, secure, and user-friendly hosting with robust, flexible, and often anonymous service options.  
* **AbeloHost**: Known for its strict offshore hosting in the Netherlands, providing excellent protection for sensitive content.  
* **KoDDoS**: Specializes in high-end, premium, and reliable DDoS mitigation and secure hosting.  
* **OrangeWebsite**: An Icelandic host that prioritizes privacy, often used for legal but sensitive content.  
* **Njalla**: A privacy-focused, anonymous hosting service.  
* **CooliceHost**: Offers, based on reports, secure hosting solutions in Europe.  
* **Vsys.host**: Operates from Ukraine, providing high-anonymity hosting services

## 

## Examples

To be continued

## Automation

To be continued   
