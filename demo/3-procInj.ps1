$r = $PSScriptRoot
$s = "$PSScriptRoot\ProcInject\ProcInject.exe"
$p = "C:\Users\Public\Downloads\ProcInject.exe"
Start-Process "$r\..\iEDR\x64\Release\iEDR.exe" -Args "-a $p"

$_= Read-Host "Wait for iEDR startup..."

if (Test-Path $p) {
	rm $p -Force
}
cp $s $p
Write-Host "Copied EXE"
Read-Host "Press ENTER to start EXE"
Start-Process $p -NoNewWindow -Wait