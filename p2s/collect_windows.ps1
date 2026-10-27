<#
php2shell-scanner Windows collector (read-only). Writes php2shell.local/1 JSON for `php2shell.pyz --import-local`.

Run on the Windows host (PowerShell 5.1+, as Administrator for complete results):
  powershell -NoProfile -ExecutionPolicy Bypass -File p2s-collect.ps1 -Out web01.json [-Ioc] [-Since 2026-09-21]

What it does: finds PHP builds (PATH, C:\php*, Program Files, XAMPP/WAMP/Laragon, Plesk, IIS FastCGI applications),
runs each `php -v` / `php-cgi -v`, reads php.ini values that matter for interim mitigation, lists IP addresses, and flags
running php-cgi/php processes whose binary changed after they started. With -Ioc it also lists PHP files changed since
-Since in IIS site roots (path, time, size, SHA-256), webshell patterns in them, PHP code in session/temp files, and
cmd/powershell/script hosts spawned by w3wp/php-cgi. It creates or changes nothing except the -Out file; no file
content is copied into the result. NOT YET TESTED ON A REAL WINDOWS HOST (syntax and output format are tested).
#>
param(
  [Parameter(Mandatory = $true)][string]$Out,
  [switch]$Ioc,
  [string]$Since = ""
)
$ErrorActionPreference = "SilentlyContinue"
$lines = New-Object System.Collections.Generic.List[string]
function Emit([string]$k, [string]$v) { $lines.Add("$k=$($v -replace "[\r\n]", " ")") }

$os = Get-CimInstance Win32_OperatingSystem
Emit "HOST" $env:COMPUTERNAME
Emit "OS" "$($os.Caption) $($os.Version)"

# PHP binaries: PATH, common install roots, IIS FastCGI applications
$cands = New-Object System.Collections.Generic.HashSet[string]
foreach ($c in (Get-Command php.exe, php-cgi.exe -All)) { [void]$cands.Add($c.Source) }
$roots = @("C:\php*", "C:\tools\php*", "$env:ProgramFiles\PHP\*", "${env:ProgramFiles(x86)}\PHP\*", "C:\xampp\php",
           "C:\wamp64\bin\php\*", "C:\wamp\bin\php\*", "C:\laragon\bin\php\*", "${env:ProgramFiles(x86)}\Plesk\Additional\PleskPHP*",
           "$env:ProgramFiles\Plesk\Additional\PleskPHP*")
foreach ($r in $roots) {
  foreach ($d in (Get-Item $r)) {
    foreach ($n in @("php.exe", "php-cgi.exe")) { $p = Join-Path $d.FullName $n; if (Test-Path $p) { [void]$cands.Add($p) } }
  }
}
$appHost = "$env:windir\System32\inetsrv\config\applicationHost.config"
if (Test-Path $appHost) {
  [xml]$cfg = Get-Content $appHost -Raw
  foreach ($app in $cfg.configuration.'system.webServer'.fastCgi.application) {
    if ($app.fullPath -and (Test-Path $app.fullPath)) { [void]$cands.Add($app.fullPath); Emit "IIS_FASTCGI" $app.fullPath }
  }
}
$bins = @($cands | Sort-Object | Select-Object -First 300)
if ($cands.Count -gt 300) { Emit "TRUNCATED" "binaries" }
foreach ($b in $bins) {
  $v = ""
  $job = Start-Job -ScriptBlock { param($x) & $x -n -v 2>$null | Select-Object -First 1 } -ArgumentList $b
  if (Wait-Job $job -Timeout 5) { $v = [string](Receive-Job $job) }
  Remove-Job $job -Force
  Emit "BIN" "$b|$v"
}

# replaced binary still running: the file changed after the process started
foreach ($p in (Get-Process php, php-cgi)) {
  $f = $p.Path
  if ($f -and (Test-Path $f) -and (Get-Item $f).LastWriteTime -gt $p.StartTime) { Emit "STALE" "$($p.Id):$f (replaced after start)" }
}

# addresses (the scanner maps this file onto the scanned asset by IP)
foreach ($a in (Get-NetIPAddress | Where-Object { $_.IPAddress -notmatch '^(127\.|::1$|fe80:)' })) { Emit "IP" $a.IPAddress }

# interim-mitigation inputs: php.ini next to every build (php-cgi under IIS reads that one)
$inik = '^\s*(session\.upload_progress\.enabled|file_uploads|enable_post_data_reading|session\.use_strict_mode|session\.save_handler|display_errors|display_startup_errors)\s*='
foreach ($dir in ($bins | ForEach-Object { Split-Path $_ -Parent } | Sort-Object -Unique)) {
  $ini = Join-Path $dir "php.ini"
  if (-not (Test-Path $ini)) { continue }
  Emit "INISET" $ini
  foreach ($l in (Select-String -Path $ini -Pattern $inik)) { Emit "INI" "$ini|$($l.Line.Trim())" }
}

if ($Ioc) {
  if (-not $Since) { $Since = (Get-Date).AddDays(-60).ToString("yyyy-MM-dd") }
  $sinceDate = [datetime]::ParseExact($Since, "yyyy-MM-dd", $null)
  $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
  Emit "IOC_PRIV" $(if ($admin) { "root" } else { "user" })
  Emit "IOC_SINCE" $Since
  $webRoots = New-Object System.Collections.Generic.HashSet[string]
  if (Test-Path "C:\inetpub\wwwroot") { [void]$webRoots.Add("C:\inetpub\wwwroot") }
  if ($cfg) {
    foreach ($site in $cfg.configuration.'system.applicationHost'.sites.site) {
      foreach ($vd in $site.application.virtualDirectory) {
        $pp = [Environment]::ExpandEnvironmentVariables($vd.physicalPath)
        if ($pp -and (Test-Path $pp)) { [void]$webRoots.Add($pp) }
      }
    }
  }
  foreach ($r in $webRoots) { Emit "IOC_ROOT" $r }
  $recent = @(foreach ($r in $webRoots) {
      Get-ChildItem -Path $r -Recurse -File -Force -Include *.php, *.phtml, *.php5, *.php7, *.phar, .user.ini, web.config |
        Where-Object { $_.LastWriteTime -ge $sinceDate -or $_.CreationTime -ge $sinceDate }
    }) | Sort-Object FullName -Unique
  if ($recent.Count -gt 500) { Emit "TRUNCATED" "ioc_recent" }
  $recent = @($recent | Select-Object -First 500)
  foreach ($f in $recent) {
    $h = (Get-FileHash -Algorithm SHA256 -Path $f.FullName).Hash.ToLower()
    Emit "IOC_RECENT" "$($f.FullName)|$($f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))|$($f.Length)|$h"
  }
  $shellRe = '(eval|assert)\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|\$_(POST|GET|REQUEST|COOKIE|SERVER))|(system|passthru|shell_exec|popen|proc_open)\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)|preg_replace\s*\([^)]*/e'
  foreach ($f in $recent) { if (Select-String -Path $f.FullName -Pattern $shellRe -Quiet) { Emit "IOC_SHELL" $f.FullName } }
  $sessDirs = @("$env:windir\Temp", $env:TEMP) + @($bins | ForEach-Object { Join-Path (Split-Path $_ -Parent) "tmp" })
  $sessHits = 0
  foreach ($sd in ($sessDirs | Where-Object { $_ -and (Test-Path $_) } | Sort-Object -Unique)) {
    foreach ($f in (Get-ChildItem -Path $sd -File -Force -Include sess_*, *.php -Recurse -Depth 1 | Where-Object { $_.Length -lt 1MB } | Select-Object -First 5000)) {
      if ($sessHits -lt 50 -and (Select-String -Path $f.FullName -Pattern '<\?php|<\?=|eval\s*\(|base64_decode\s*\(' -Quiet)) {
        Emit "IOC_SESS" $f.FullName; $sessHits++
      }
    }
  }
  $workers = @(Get-CimInstance Win32_Process | Where-Object { $_.Name -in @("w3wp.exe", "php-cgi.exe", "php.exe", "httpd.exe") })
  $wids = @($workers | ForEach-Object { $_.ProcessId })
  $tools = @("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "certutil.exe",
             "bitsadmin.exe", "net.exe", "whoami.exe", "nc.exe", "ncat.exe", "curl.exe", "wget.exe", "python.exe", "perl.exe")
  foreach ($c in (Get-CimInstance Win32_Process | Where-Object { $wids -contains $_.ParentProcessId -and $tools -contains $_.Name.ToLower() } | Select-Object -First 50)) {
    $cmd = [string]$c.CommandLine
    Emit "IOC_CHILD" "$($c.ParentProcessId) $($c.ProcessId) $($c.Name) $($cmd.Substring(0, [Math]::Min(150, $cmd.Length)))"
  }
}
Emit "DONE" "1"

$doc = [ordered]@{
  format       = "php2shell.local/1"
  tool_version = "@VERSION@"
  collected_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss+00:00")
  ioc_since    = $(if ($Ioc) { $Since } else { $null })
  platform     = "windows"
  output       = ($lines -join "`n") + "`n"
}
$json = $doc | ConvertTo-Json -Depth 3
[System.IO.File]::WriteAllText($Out, $json, (New-Object System.Text.UTF8Encoding $false))
Write-Host "[*] $Out written ($($bins.Count) PHP build(s)); import with: php2shell.pyz ... --import-local $Out"
