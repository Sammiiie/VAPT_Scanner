<#
.SYNOPSIS
  Convenience wrapper for Windows: builds the scanner (first run only) and scans a project.

.EXAMPLE
  .\scan.ps1 -Path "C:\Source\MyShop"
  .\scan.ps1 -Path "C:\Source\MyShop" -FailOn Medium -Open
  .\scan.ps1 -Path "C:\Source\MyShop" -Graph "C:\Reports\security-graph.html"
  .\scan.ps1 -Url "https://staging.myshop.com" -Authorized
#>
param(
    [string]$Path = ".",
    [string]$Url,
    [switch]$Authorized,
    [ValidateSet("Critical","High","Medium","Low","None")][string]$FailOn = "None",   # None = report only; any other value fails on findings at/above it
    [string]$Graph,
    [switch]$Open
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$out  = Join-Path $root "src\VaptScanner\bin\Release\net8.0"
$exe  = Join-Path $out "vapt.dll"

if (-not (Test-Path $exe)) {
    Write-Host "Building scanner..." -ForegroundColor DarkGray
    dotnet build (Join-Path $root "src\VaptScanner") -c Release | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Build failed. Is the .NET 8 SDK (or newer) installed?" }
}

$reports = Join-Path (Get-Location) "vapt-reports"
if ($Url) {
    $cliArgs = @("dast", $Url, "--format", "console,html,json,sarif", "--out", $reports, "--fail-on", $FailOn)
    if ($Authorized) { $cliArgs += "--authorized" }
    if ($Graph) { $cliArgs += @("--graph", $Graph) }
    dotnet $exe @cliArgs
    $report = Join-Path $reports "vapt-dast-report.html"
} else {
    $cliArgs = @("scan", $Path, "--format", "console,html,json,sarif", "--out", $reports, "--fail-on", $FailOn)
    if ($Graph) { $cliArgs += @("--graph", $Graph) }
    dotnet $exe @cliArgs
    $report = Join-Path $reports "vapt-report.html"
}
$code = $LASTEXITCODE
if ($Open -and (Test-Path $report)) { Start-Process $report }
exit $code
