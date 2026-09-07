<#
.SYNOPSIS
    Copy a plugin directory's entry files and packages into IDA's user plugins dir.

.DESCRIPTION
    IDA 9.0 loads user plugins from %APPDATA%\Hex-Rays\IDA Pro\plugins. An entry
    .py file and its sibling support package must land there side by side, or the
    entry file's sys.path shim has nothing to import.

    Deploy copies every top-level .py file plus every package directory (one
    containing __init__.py) from the source plugin folder. __pycache__ is never
    copied -- a stale one shadowing an edited module is a classic phantom bug.

.EXAMPLE
    pwsh tools/deploy.ps1 cfs5-transfer
    pwsh tools/deploy.ps1 cfs5-transfer -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Source,

    [string]$PluginsDir = (Join-Path $env:APPDATA 'Hex-Rays\IDA Pro\plugins')
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Source -PathType Container)) {
    throw "Source plugin directory not found: $Source"
}
if (-not (Test-Path -LiteralPath $PluginsDir -PathType Container)) {
    throw "IDA plugins directory not found: $PluginsDir"
}

$src = (Resolve-Path -LiteralPath $Source).Path
Write-Host "Deploying $src -> $PluginsDir"

foreach ($file in Get-ChildItem -LiteralPath $src -Filter *.py -File) {
    if ($PSCmdlet.ShouldProcess($file.Name, 'copy entry file')) {
        Copy-Item -LiteralPath $file.FullName -Destination $PluginsDir -Force
        Write-Host "  + $($file.Name)"
    }
}

foreach ($dir in Get-ChildItem -LiteralPath $src -Directory) {
    if ($dir.Name -eq '__pycache__') { continue }
    if (-not (Test-Path -LiteralPath (Join-Path $dir.FullName '__init__.py'))) { continue }

    $dest = Join-Path $PluginsDir $dir.Name
    if ($PSCmdlet.ShouldProcess($dir.Name, 'copy package')) {
        if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Recurse -Force }
        Copy-Item -LiteralPath $dir.FullName -Destination $dest -Recurse -Force
        Get-ChildItem -LiteralPath $dest -Recurse -Directory -Filter '__pycache__' |
            ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force }
        Write-Host "  + $($dir.Name)/ (package)"
    }
}

Write-Host 'Done. Restart IDA, or reload the plugin, to pick the change up.'
