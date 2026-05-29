$r = $PSScriptRoot
$s = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
$p = "C:\Users\Public\Downloads\powershell.exe"
Start-Process "$r\..\iEDR.exe" -Args "-a $p -d -l 1"

$_= Read-Host "Wait for iEDR startup..."

if (Test-Path $p) {
	rm $p -Force
}
cp $s $p
Write-Host "Copied EXE"
Read-Host "Press ENTER to start EXE"
Start-Process $p