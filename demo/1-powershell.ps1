$r = $PSScriptRoot
$s = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

Start-Process "$r\..\iEDR.exe" -Args "-a $s"

$_= Read-Host "Wait for iEDR startup, then press ENTER to start $s"
Start-Process $s