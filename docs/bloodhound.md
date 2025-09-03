
---

### 📝 `docs/bloodhound.md`

```markdown
# BloodHound Analysis

```bash
sudo nxc ldap dc01.fluffy.htb -u '<USERNAME>' -p '<PASSWORD>' \
  --bloodhound --collection All --dns-tcp --dns-server <TARGET_IP>


Observations

User <USER> had GenericWrite permissions over the Service Accounts group.

Potential for Shadow Credentials attack