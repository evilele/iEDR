Start-Process ".\iEDR\x64\Release\iEDR.exe" -Args "-a C:\Users\Public\Downloads\cmd.exe -d -l 1"

$_= Read-Host "Wait for iEDR startup..."

$s = "C:\Windows\System32\cmd.exe"
$p = "C:\Users\Public\Downloads\cmd.exe"
if (Test-Path $p) {
	rm $p -Force
}
cp $s $p
Write-Host "Copied EXE"
Read-Host "Press ENTER to start EXE"
Start-Process $p -NoNewWindow