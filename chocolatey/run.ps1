Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
choco feature enable -n allowGlobalConfirmation
$programs = Get-Content $PSScriptRoot\programs.txt
$prerelease = Get-Content $PSScriptRoot\prerelease.txt
choco install $programs
choco install -pre $prerelease
Set-ExecutionPolicy Default -Scope Process -Force
