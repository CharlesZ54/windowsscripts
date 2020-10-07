iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
$programs = Get-Content .\programs.txt
choco install -y $programs