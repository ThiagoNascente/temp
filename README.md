# temp

```bash
Get-Service sshd
Get-NetTCPConnection -LocalPort 22 -State Listen

$regra = Get-NetFirewallRule -PolicyStore ActiveStore -Name 'OpenSSH-Server-In-TCP'
$regra | Select-Object Enabled, Direction, Action, Profile
$regra | Get-NetFirewallAddressFilter | Select-Object RemoteAddress
```

```bash
$cap = 'OpenSSH.Server~~~~0.0.1.0'
if ((Get-WindowsCapability -Online -Name $cap).State -ne 'Installed') {
    Add-WindowsCapability -Online -Name $cap -ErrorAction Stop
}

$regra = @{
    Name          = 'OpenSSH-Server-In-TCP'
    Enabled       = 'True'
    Direction     = 'Inbound'
    Action        = 'Allow'
    Protocol      = 'TCP'
    LocalPort     = 22
    RemoteAddress = '192.168.30.190'
}
if (Get-NetFirewallRule -Name $regra.Name -ErrorAction SilentlyContinue) {
    Set-NetFirewallRule @regra -ErrorAction Stop
} else {
    New-NetFirewallRule @regra -DisplayName 'OpenSSH Server (sshd)' -ErrorAction Stop
}

Set-Service -Name sshd -StartupType Automatic
Start-Service -Name sshd -ErrorAction Stop
Get-NetTCPConnection -LocalPort 22 -State Listen
```


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

```bash
$out = Join-Path $env:USERPROFILE 'AuditoriaMaquina0'
foreach ($nome in 'GroupPolicy','GroupPolicyUsers') {
  $origem = Join-Path "$env:WINDIR\System32" $nome
  Get-ChildItem $origem -File -Recurse -Force -ErrorAction SilentlyContinue | Where-Object Name -in 'Registry.pol','gpt.ini','GptTmpl.inf','scripts.ini','psscripts.ini' | ForEach-Object {
    $dest = Join-Path "$out\politicas-originais\$nome" $_.FullName.Substring($origem.Length + 1)
    New-Item -ItemType Directory -Path (Split-Path $dest) -Force | Out-Null
    Copy-Item -LiteralPath $_.FullName -Destination $dest -Force
  }
}
$uninstall = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
foreach ($nome in 'aluno','suporte') { $sid = (Get-LocalUser -Name $nome).SID.Value; $uninstall += "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" }
Get-ItemProperty -Path $uninstall -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and $_.SystemComponent -ne 1 } | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate | Export-Csv "$out\inventario-win32.csv" -NoTypeInformation -Encoding UTF8
Get-AppxPackage -AllUsers -PackageTypeFilter Main | Select-Object Name,Version | Export-Csv "$out\inventario-appx.csv" -NoTypeInformation -Encoding UTF8
$inicio = (Get-Date).AddMonths(-12)
$events = @(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688;StartTime=$inicio} -ErrorAction SilentlyContinue)
$oldest = Get-WinEvent -LogName Security -Oldest -MaxEvents 1 -ErrorAction SilentlyContinue
"Security mais antigo: $($oldest.TimeCreated.ToString('o'))`nEventos 4688 no período: $($events.Count)" | Set-Content "$out\cobertura-eventos.txt" -Encoding UTF8
$events | ForEach-Object {
  $data = @{}; ([xml]$_.ToXml()).Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.InnerText }
  if ($data.NewProcessName) { [pscustomobject]@{ Executavel = Split-Path $data.NewProcessName -Leaf; SID = if ($data.TargetUserSid -and $data.TargetUserSid -ne 'S-1-0-0') { $data.TargetUserSid } else { $data.SubjectUserSid }; Horario = $_.TimeCreated.ToString('o') } }
} | Group-Object Executavel,SID | ForEach-Object { $_.Group | Sort-Object Horario -Descending | Select-Object -First 1 } | Export-Csv "$out\execucoes-security.csv" -NoTypeInformation -Encoding UTF8
Write-Host 'COLETA FINAL CONCLUIDA'
```
