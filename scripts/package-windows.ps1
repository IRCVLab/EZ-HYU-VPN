[CmdletBinding()]
param(
    [ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version = '0.2.0',
    [string]$OutputDirectory = '',
    [string]$OpenConnectArtifactZip = '',
    [string]$PatchedOpenConnectDirectory = '',
    [switch]$SkipRustBuild
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) { $OutputDirectory = Join-Path $Root 'dist\windows' }
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
$Stage = Join-Path $Root 'target\windows-package-staging'
$Cache = Join-Path $Root 'target\windows-package-cache'
if ([string]::IsNullOrWhiteSpace($PatchedOpenConnectDirectory)) { $PatchedOpenConnectDirectory = Join-Path $Root 'target\openconnect-windows-patched' }
$PatchedOpenConnectDirectory = [System.IO.Path]::GetFullPath($PatchedOpenConnectDirectory)
$OpenConnectUrl = 'https://gitlab.com/api/v4/projects/2335175/jobs/14877945030/artifacts'
$OpenConnectZipSha256 = '4e314f8c37c42995f87d530ce59497c6bcfd94e8dbc0a267d971cc6112294736'
$OpenConnectInstallerName = 'openconnect-installer-MinGW64-GnuTLS-v9.21.exe'
$OpenConnectInstallerSha256 = '6ee9e8eb9bc59ef70bb0717df7f99703f8a2ccd11d8e45d58a61f9a2e6ef7d00'
$WixVersion = '5.0.2'
$OpenConnectFiles = @(
    'iconv.dll',
    'libgcc_s_seh-1.dll',
    'libgmp-10.dll',
    'libgnutls-30.dll',
    'libhogweed-6.dll',
    'libintl-8.dll',
    'liblz4.dll',
    'libnettle-8.dll',
    'libopenconnect-5.dll',
    'libstoken-1.dll',
    'libtasn1-6.dll',
    'libwinpthread-1.dll',
    'libxml2-2.dll',
    'list-system-keys.exe',
    'openconnect.exe',
    'vpnc-script-win.js',
    'wintun.dll',
    'zlib1.dll'
)
function Assert-Sha256([string]$Path, [string]$Expected) {
    $Actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
    if ($Actual -ne $Expected) { throw "SHA-256 mismatch for $Path (expected $Expected, got $Actual)" }
}
function Assert-PatchedOpenConnect([string]$Directory) {
    $ManifestPath = Join-Path $Directory 'SHA256SUMS'
    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) { throw "Missing patched OpenConnect manifest: $ManifestPath" }
    $ExpectedNames = @('openconnect.exe', 'libopenconnect-5.dll')
    $Entries = @{}
    foreach ($Line in Get-Content -LiteralPath $ManifestPath) {
        if ($Line -notmatch '^([0-9a-fA-F]{64})  ([A-Za-z0-9.-]+)$') { throw "Invalid patched OpenConnect manifest line" }
        $Entries[$Matches[2]] = $Matches[1].ToLowerInvariant()
    }
    if ($Entries.Count -ne $ExpectedNames.Count) { throw 'Patched OpenConnect manifest has unexpected entries' }
    foreach ($Name in $ExpectedNames) {
        if (-not $Entries.ContainsKey($Name)) { throw "Patched OpenConnect manifest is missing $Name" }
        $Path = Join-Path $Directory $Name
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Missing patched OpenConnect binary: $Path" }
        Assert-Sha256 $Path $Entries[$Name]
    }
}
foreach ($Path in @($Stage, $OutputDirectory)) {
    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Recurse -Force }
    New-Item -ItemType Directory -Path $Path | Out-Null
}
New-Item -ItemType Directory -Path $Cache -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $Stage 'runtime') | Out-Null
if (-not $SkipRustBuild) {
    & cargo build --locked --release -p hyu-vpn-windows-service -p hyu-vpn-windows-tray -p hyu-vpn-hip
    if ($LASTEXITCODE -ne 0) { throw 'Rust release build failed' }
}
$Release = Join-Path $Root 'target\release'
$ApplicationFiles = @('hyu-vpn-windows-service.exe','hyu-vpn-windows-tray.exe','hyu-vpn-hip.exe')
foreach ($Name in $ApplicationFiles) {
    $Source = Join-Path $Release $Name
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) { throw "Missing Windows application binary: $Source" }
    Copy-Item -LiteralPath $Source -Destination (Join-Path $Stage $Name)
}
if ([string]::IsNullOrWhiteSpace($OpenConnectArtifactZip)) {
    $OpenConnectArtifactZip = Join-Path $Cache 'openconnect-v9.21-mingw64-gnutls-artifacts.zip'
    if (-not (Test-Path -LiteralPath $OpenConnectArtifactZip -PathType Leaf)) {
        Invoke-WebRequest -Uri $OpenConnectUrl -OutFile $OpenConnectArtifactZip -UseBasicParsing
    }
}
$OpenConnectArtifactZip = [System.IO.Path]::GetFullPath($OpenConnectArtifactZip)
Assert-Sha256 $OpenConnectArtifactZip $OpenConnectZipSha256
$ArtifactContents = Join-Path $Stage 'openconnect-artifact'
Expand-Archive -LiteralPath $OpenConnectArtifactZip -DestinationPath $ArtifactContents -Force
$OpenConnectInstaller = Join-Path $ArtifactContents $OpenConnectInstallerName
Assert-Sha256 $OpenConnectInstaller $OpenConnectInstallerSha256
$SevenZip = Get-Command 7z.exe -ErrorAction SilentlyContinue
if ($null -eq $SevenZip) { $SevenZip = Get-Command 7z -ErrorAction SilentlyContinue }
if ($null -eq $SevenZip) { throw '7-Zip is required to extract the pinned OpenConnect installer' }
$Extracted = Join-Path $Stage 'openconnect-extracted'
New-Item -ItemType Directory -Path $Extracted | Out-Null
& $SevenZip.Source x '-y' "-o$Extracted" $OpenConnectInstaller | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'OpenConnect installer extraction failed' }
foreach ($Name in $OpenConnectFiles) {
    $Source = Join-Path $Extracted $Name
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) { throw "Pinned OpenConnect payload is incomplete: $Name" }
    Copy-Item -LiteralPath $Source -Destination (Join-Path $Stage "runtime\$Name")
}
Assert-PatchedOpenConnect $PatchedOpenConnectDirectory
foreach ($Name in @('openconnect.exe', 'libopenconnect-5.dll')) {
    Copy-Item -LiteralPath (Join-Path $PatchedOpenConnectDirectory $Name) -Destination (Join-Path $Stage "runtime\$Name") -Force
}
Copy-Item -LiteralPath (Join-Path $PatchedOpenConnectDirectory 'SHA256SUMS') -Destination (Join-Path $Stage 'OPENCONNECT-PATCHED-SHA256SUMS.txt')
Copy-Item -LiteralPath (Join-Path $Root 'packaging\windows\hyu-vpn.ico') -Destination (Join-Path $Stage 'hyu-vpn.ico')
Copy-Item -LiteralPath (Join-Path $Root 'LICENSE') -Destination (Join-Path $Stage 'LICENSE.txt')
Copy-Item -LiteralPath (Join-Path $Root 'packaging\windows\THIRD_PARTY_NOTICES.txt') -Destination (Join-Path $Stage 'THIRD_PARTY_NOTICES.txt')
Copy-Item -LiteralPath (Join-Path $Root 'packaging\windows\openconnect-windows-hip.patch') -Destination (Join-Path $Stage 'openconnect-windows-hip.patch')
$Manifest = Get-ChildItem -LiteralPath $Stage -File -Recurse |
    Where-Object { $_.FullName -notlike "$ArtifactContents*" -and $_.FullName -notlike "$Extracted*" } |
    Sort-Object FullName |
    ForEach-Object {
        $Relative = [System.IO.Path]::GetRelativePath($Stage, $_.FullName).Replace('\', '/')
        "$((Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant())  $Relative"
    }
$Manifest | Set-Content -LiteralPath (Join-Path $Stage 'artifact-manifest.sha256') -Encoding ascii
$ToolDirectory = Join-Path $Root 'target\wix-tool'
$Wix = Get-Command wix.exe -ErrorAction SilentlyContinue
if ($null -eq $Wix) {
    New-Item -ItemType Directory -Path $ToolDirectory -Force | Out-Null
    $WixPath = Join-Path $ToolDirectory 'wix.exe'
    if (-not (Test-Path -LiteralPath $WixPath -PathType Leaf)) {
        & dotnet tool install wix --version $WixVersion --tool-path $ToolDirectory
        if ($LASTEXITCODE -ne 0) { throw 'WiX Toolset installation failed' }
    }
} else { $WixPath = $Wix.Source }
& $WixPath extension add "WixToolset.Util.wixext/$WixVersion" --global
if ($LASTEXITCODE -ne 0) { throw 'WiX Util extension installation failed' }
$Msi = Join-Path $OutputDirectory "HYU-VPN-$Version-x64.msi"
& $WixPath build (Join-Path $Root 'packaging\windows\Product.wxs') -arch x64 -ext WixToolset.Util.wixext -d "PayloadDir=$Stage" -d "Version=$Version" -pdbtype none -out $Msi
if ($LASTEXITCODE -ne 0) { throw 'MSI build failed' }
& $WixPath msi validate $Msi
if ($LASTEXITCODE -ne 0) { throw 'MSI validation failed' }
$MsiHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Msi).Hash.ToLowerInvariant()
$MsiName = [System.IO.Path]::GetFileName($Msi)
$ChecksumEncoding = [System.Text.UTF8Encoding]::new($false)
[System.IO.File]::WriteAllText("$Msi.sha256", "$MsiHash  $MsiName`n", $ChecksumEncoding)
Write-Host "Built $Msi"
Write-Host "SHA256 $MsiHash"
