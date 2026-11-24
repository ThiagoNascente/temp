# temp
```bash
$out = Join-Path $env:USERPROFILE 'AuditoriaMaquina0'
New-Item -ItemType Directory -Path $out -Force | Out-Null
Start-Transcript -Path "$out\diagnostico.txt" -Force
whoami /groups
Get-LocalGroupMember -SID 'S-1-5-32-544'
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' | Select-Object EnableLUA,LocalAccountTokenFilterPolicy,FilterAdministratorToken | Format-List
foreach ($nome in 'aluno','suporte') {
  $sid = (Get-LocalUser -Name $nome).SID.Value
  reg.exe export "HKU\$sid\Software\Policies" "$out\$nome-policies.reg" /y
  reg.exe export "HKU\$sid\Software\Microsoft\Windows\CurrentVersion\Policies" "$out\$nome-currentversion-policies.reg" /y
  reg.exe export "HKU\$sid\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" "$out\$nome-userassist.reg" /y
  gpresult /user "$env:COMPUTERNAME\$nome" /h "$out\gpresult-$nome.html" /f
}
secedit /export /mergedpolicy /cfg "$out\seguranca.inf" /areas USER_RIGHTS SECURITYPOLICY
Get-AppLockerPolicy -Effective -Xml | Set-Content "$out\applocker.xml" -Encoding UTF8
Get-WinEvent -ListLog 'Security','Microsoft-Windows-Sysmon/Operational','Microsoft-Windows-AppLocker/EXE and DLL' -ErrorAction SilentlyContinue | Select-Object LogName,IsEnabled,RecordCount,LogMode | Format-Table -AutoSize
Stop-Transcript
Write-Host 'COLETA CONCLUIDA'
```
