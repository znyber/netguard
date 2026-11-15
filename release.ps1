# =============================================================================
# NetGuard GitHub Release Script
# Usage: .\release.ps1 -Version "1.1.0" -Token "ghp_xxxxxxxxxxxx"
#        .\release.ps1 -Version "1.1.0" -Token "ghp_xxxxxxxxxxxx" -Draft
#        .\release.ps1 -Version "1.1.0" -Token "ghp_xxxxxxxxxxxx" -Prerelease
# =============================================================================

param(
    [Parameter(Mandatory=$false)]
    [string]$Version = "1.1.0",

    [Parameter(Mandatory=$true)]
    [string]$Token,

    [switch]$Draft,
    [switch]$Prerelease,

    [string]$RepoOwner = "znyber",
    [string]$RepoName  = "netguard",

    # Paths (relative to this script's directory)
    [string]$BuildDir     = "build",
    [string]$InstallerDir = "installer\Output",
    [string]$SourceDir    = $PSScriptRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Step([string]$msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-Ok([string]$msg)   { Write-Host "    OK: $msg" -ForegroundColor Green }
function Write-Fail([string]$msg) { Write-Host "    FAIL: $msg" -ForegroundColor Red; exit 1 }

$Root    = $PSScriptRoot
$TmpDir  = Join-Path $Root "_release_tmp"
$TagName = "v$Version"
$ApiBase = "https://api.github.com/repos/$RepoOwner/$RepoName"
$Headers = @{
    Authorization  = "Bearer $Token"
    Accept         = "application/vnd.github+json"
    "X-GitHub-Api-Version" = "2022-11-28"
}

# ---------------------------------------------------------------------------
# 0. Git executable (bundled with GitHub Desktop if standalone git not found)
# ---------------------------------------------------------------------------
Write-Step "Locating git"
$GitExe = $null
foreach ($candidate in @(
    "git",
    "C:\Users\$env:USERNAME\AppData\Local\GitHubDesktop\app-3.6.11\resources\app\git\cmd\git.exe",
    "C:\Users\$env:USERNAME\AppData\Local\GitHubDesktop\app-3.6.10\resources\app\git\cmd\git.exe",
    "C:\Program Files\Git\cmd\git.exe"
)) {
    if (Get-Command $candidate -ErrorAction SilentlyContinue) { $GitExe = $candidate; break }
    if ($candidate -ne "git" -and (Test-Path $candidate)) { $GitExe = $candidate; break }
}
if (-not $GitExe) { Write-Fail "git not found. Install Git for Windows." }
Write-Ok "git: $GitExe"

# ---------------------------------------------------------------------------
# 1. Resolve asset paths
# ---------------------------------------------------------------------------
Write-Step "Resolving asset paths"

$BuildPath     = Join-Path $Root $BuildDir
$InstallerPath = Join-Path $Root $InstallerDir

if (-not (Test-Path $BuildPath))     { Write-Fail "Build dir not found: $BuildPath" }
if (-not (Test-Path $InstallerPath)) { Write-Fail "Installer output dir not found: $InstallerPath" }

# Find installer .exe
$InstallerExe = Get-ChildItem $InstallerPath -Filter "*.exe" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $InstallerExe) { Write-Fail "No .exe found in $InstallerPath" }
Write-Ok "Installer: $($InstallerExe.FullName)"

# ---------------------------------------------------------------------------
# 2. Create temp directory
# ---------------------------------------------------------------------------
Write-Step "Preparing temp directory: $TmpDir"
if (Test-Path $TmpDir) { Remove-Item $TmpDir -Recurse -Force }
New-Item -ItemType Directory -Path $TmpDir | Out-Null
Write-Ok "Created $TmpDir"

# ---------------------------------------------------------------------------
# 3. Source tarball  (netguard-v1.1.0-source.tar.gz)
# ---------------------------------------------------------------------------
Write-Step "Creating source tarball"

# Use git archive so only tracked files are included
$SourceTar = Join-Path $TmpDir "netguard-$TagName-source.tar.gz"
& $GitExe -C $Root archive --format=tar.gz --prefix="netguard-$Version/" HEAD -o $SourceTar
if ($LASTEXITCODE -ne 0) { Write-Fail "git archive failed" }
Write-Ok "Source archive: $SourceTar  ($([math]::Round((Get-Item $SourceTar).Length/1KB))KB)"

# ---------------------------------------------------------------------------
# 4. Portable ZIP  (netguard-v1.1.0-portable-win-x64.zip)
#    Contents: everything in the Build directory
# ---------------------------------------------------------------------------
Write-Step "Creating portable ZIP from Build directory"

# Files to include in the portable package
$PortableFiles = @(
    "netguard.exe",
    "netguardc.exe",
    "WinDivert.dll",
    "WinDivert64.sys"
)
$PortableExtras = @("README.md", "netguard.conf")  # from root

$PortableStage = Join-Path $TmpDir "portable_stage\netguard-$Version"
New-Item -ItemType Directory -Path $PortableStage -Force | Out-Null

foreach ($f in $PortableFiles) {
    $src = Join-Path $BuildPath $f
    if (Test-Path $src) {
        Copy-Item $src $PortableStage
        Write-Host "    + $f"
    } else {
        Write-Host "    (skipped, not found): $f" -ForegroundColor Yellow
    }
}
foreach ($f in $PortableExtras) {
    $src = Join-Path $Root $f
    if (Test-Path $src) {
        Copy-Item $src $PortableStage
        Write-Host "    + $f (from root)"
    }
}

$PortableZip = Join-Path $TmpDir "netguard-$TagName-portable-win-x64.zip"
Compress-Archive -Path "$PortableStage\*" -DestinationPath $PortableZip -CompressionLevel Optimal
Write-Ok "Portable ZIP: $PortableZip  ($([math]::Round((Get-Item $PortableZip).Length/1KB))KB)"

# ---------------------------------------------------------------------------
# 5. Copy installer .exe to temp (for consistent naming)
# ---------------------------------------------------------------------------
Write-Step "Preparing installer asset"
$InstallerDest = Join-Path $TmpDir $InstallerExe.Name
Copy-Item $InstallerExe.FullName $InstallerDest
Write-Ok "Installer: $($InstallerExe.Name)  ($([math]::Round($InstallerExe.Length/1KB))KB)"

# ---------------------------------------------------------------------------
# 6. Create git tag and push
# ---------------------------------------------------------------------------
Write-Step "Tagging release as $TagName"

$tagExists = & $GitExe -C $Root tag --list $TagName
if ($tagExists) {
    Write-Host "    Tag $TagName already exists, skipping tag creation." -ForegroundColor Yellow
} else {
    & $GitExe -C $Root tag -a $TagName -m "Release $TagName"
    if ($LASTEXITCODE -ne 0) { Write-Fail "Failed to create tag" }
    & $GitExe -C $Root push origin $TagName
    if ($LASTEXITCODE -ne 0) { Write-Fail "Failed to push tag to origin" }
    Write-Ok "Tag $TagName pushed to origin"
}

# ---------------------------------------------------------------------------
# 7. Create GitHub Release
# ---------------------------------------------------------------------------
Write-Step "Creating GitHub Release"

$ReleaseBody = @{
    tag_name         = $TagName
    name             = "NetGuard $TagName"
    body             = "## NetGuard $TagName`n`n### Downloads`n- **Installer (Windows x64)** — `$($InstallerExe.Name)``n- **Portable (Windows x64)** — `netguard-$TagName-portable-win-x64.zip``n- **Source code** — `netguard-$TagName-source.tar.gz`"
    draft            = [bool]$Draft
    prerelease       = [bool]$Prerelease
    target_commitish = "main"
} | ConvertTo-Json

try {
    $Release = Invoke-RestMethod -Uri "$ApiBase/releases" -Method POST `
        -Headers $Headers -Body $ReleaseBody -ContentType "application/json"
} catch {
    $errBody = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
    if ($errBody.errors -and ($errBody.errors | Where-Object { $_.code -eq "already_exists" })) {
        Write-Host "    Release $TagName already exists on GitHub. Fetching existing release..." -ForegroundColor Yellow
        $Release = Invoke-RestMethod -Uri "$ApiBase/releases/tags/$TagName" -Method GET -Headers $Headers
    } else {
        Write-Fail "Failed to create release: $_"
    }
}

$UploadUrl = $Release.upload_url -replace '\{\?name,label\}', ''
Write-Ok "Release created: $($Release.html_url)"
Write-Ok "Upload URL: $UploadUrl"

# ---------------------------------------------------------------------------
# 8. Upload assets
# ---------------------------------------------------------------------------
function Upload-Asset([string]$FilePath, [string]$MimeType) {
    $FileName = Split-Path $FilePath -Leaf
    Write-Step "Uploading: $FileName"
    $Uri = "${UploadUrl}?name=$([Uri]::EscapeDataString($FileName))"
    $FileBytes = [System.IO.File]::ReadAllBytes($FilePath)
    try {
        $resp = Invoke-RestMethod -Uri $Uri -Method POST -Headers $Headers `
            -Body $FileBytes -ContentType $MimeType
        Write-Ok "Uploaded: $($resp.browser_download_url)"
    } catch {
        Write-Host "    WARN: Upload failed for $FileName : $_" -ForegroundColor Yellow
    }
}

Upload-Asset -FilePath $InstallerDest       -MimeType "application/octet-stream"
Upload-Asset -FilePath $PortableZip         -MimeType "application/zip"
Upload-Asset -FilePath $SourceTar           -MimeType "application/gzip"

# ---------------------------------------------------------------------------
# 9. Cleanup
# ---------------------------------------------------------------------------
Write-Step "Cleaning up temp files"
Remove-Item $TmpDir -Recurse -Force
Write-Ok "Removed $TmpDir"

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
Write-Host "`n========================================" -ForegroundColor Green
Write-Host "  Release $TagName published successfully!" -ForegroundColor Green
Write-Host "  $($Release.html_url)" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Green
