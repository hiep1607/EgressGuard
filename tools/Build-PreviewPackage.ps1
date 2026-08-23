#requires -Version 5.1
<#
.SYNOPSIS
    Builds the unsigned Phase 6A Windows preview package and verifies its layout.

.DESCRIPTION
    Publishes self-contained win-x64 builds of the launcher, service and UI,
    assembles a portable folder plus a Vietnamese quick-start guide and commit
    information, compresses everything into `EgressGuard-Preview-win-x64.zip`
    and validates that no forbidden file (source, PDB, database, log, dump or
    key material) is inside the archive.

    The script never signs anything, never creates an installer, never touches
    firewall/Defender/registry state and never elevates.

.PARAMETER OutputDirectory
    Folder receiving the ZIP and its staging tree. Defaults to
    <repo>\artifacts\preview (Git-ignored).

.PARAMETER VerifyZipPath
    When set, only verifies an existing ZIP and skips building entirely.
#>

[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [string]$VerifyZipPath
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $repoRoot

function Write-Step([string]$message) {
    Write-Host ('[step] ' + $message)
}

$requiredEntries = @(
    'EgressGuard.Launcher.exe',
    'service/EgressGuard.Service.exe',
    'ui/EgressGuard.UI.exe',
    'HUONG-DAN.txt',
    'commit-info.txt'
)

$bannedPatterns = @(
    '*.pdb', '*.dbg', '*.ilk', '*.meta',
    '*.db', '*.sqlite', '*.sqlite3', '*.db-shm', '*.db-wal',
    '*.log', '*.dmp', '*.etl', '*.trace',
    '*.pfx', '*.p12', '*.snk', '*.key',
    '*.cs', '*.csproj', '*.sln', '*.xaml', '*.ps1'
)

function Test-PackageEntryAllowed {
    param(
        [Parameter(Mandatory = $true)][string]$EntryName,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.IList[string]]$Violations
    )

    $normalized = $EntryName.Replace('\', '/')
    foreach ($required in $requiredEntries) {
        if ($normalized.EndsWith($required, [StringComparison]::OrdinalIgnoreCase)) {
            return
        }
    }

    foreach ($banned in $bannedPatterns) {
        $wildcard = '*' + $banned.Substring(1)
        if ($normalized -like $wildcard) {
            [void]$Violations.Add(('forbidden file inside package: ' + $normalized))
            return
        }
    }
}

function Get-PackageViolations {
    param([Parameter(Mandatory = $true)][string]$ZipPath)

    $violations = New-Object System.Collections.Generic.List[string]
    Add-Type -AssemblyName System.IO.Compression.FileSystem | Out-Null
    $archive = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
    try {
        if ($archive.Entries.Count -eq 0) {
            [void]$violations.Add('The package archive is empty.')
        }

        $names = New-Object System.Collections.Generic.List[string]
        foreach ($entry in $archive.Entries) {
            [void]$names.Add($entry.FullName.Replace('\', '/'))
            Test-PackageEntryAllowed -EntryName $entry.FullName -Violations $violations
        }

        foreach ($required in $requiredEntries) {
            $found = $false
            foreach ($name in $names) {
                if ($name.EndsWith($required, [StringComparison]::OrdinalIgnoreCase)) {
                    $found = $true
                    break
                }
            }

            if (-not $found) {
                [void]$violations.Add(('missing required entry: ' + $required))
            }
        }
    }
    finally {
        $archive.Dispose()
    }

    return ,$violations.ToArray()
}

if ($VerifyZipPath) {
    Write-Step "verifying existing package: $VerifyZipPath"
    if (-not (Test-Path -LiteralPath $VerifyZipPath -PathType Leaf)) {
        Write-Host '[fail] package file was not found.'
        exit 3
    }

    $problems = Get-PackageViolations -ZipPath $VerifyZipPath
    if ($problems.Count -gt 0) {
        foreach ($problem in $problems) { Write-Host ('[!]   ' + $problem) }
        Write-Host '[fail] package verification reported problems.'
        exit 4
    }

    Write-Host '[ok  ] package layout verified: required files present, nothing forbidden.'
    exit 0
}

if (-not (Test-Path -LiteralPath (Join-Path $repoRoot 'EgressGuard.sln') -PathType Leaf)) {
    Write-Host '[fail] EgressGuard.sln was not found in the repository root.'
    exit 2
}

if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $repoRoot 'artifacts\preview'
}
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
$stage = Join-Path $OutputDirectory 'stage'
$zipPath = Join-Path $OutputDirectory 'EgressGuard-Preview-win-x64.zip'

Write-Step "cleaning staging folder: $stage"
if (Test-Path -LiteralPath $stage) {
    Remove-Item -LiteralPath $stage -Recurse -Force
}
New-Item -ItemType Directory -Path $stage -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $stage 'service') -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $stage 'ui') -Force | Out-Null

$publishCommon = @(
    '-c', 'Release', '-r', 'win-x64', '--self-contained', 'true',
    '-p:PublishSingleFile=true',
    '-p:IncludeNativeLibrariesForSelfExtract=true',
    '-p:EnableCompressionInSingleFile=true',
    '-p:DebugType=None', '-p:DebugSymbols=false',
    '--nologo'
)

Write-Step 'detaching package lock files for RID-specific publish'
$lockBackups = @()
foreach ($lockRelative in @(git ls-files '*packages.lock.json')) {
    $lockPath = Join-Path $repoRoot $lockRelative
    if (Test-Path -LiteralPath $lockPath) {
        $backupPath = $lockPath + '.preview-backup'
        Copy-Item -LiteralPath $lockPath -Destination $backupPath -Force
        $lockBackups += ,@($lockPath, $backupPath)
    }
}

Write-Step 'publishing launcher (self-contained win-x64)'
& dotnet publish (Join-Path $repoRoot 'src\EgressGuard.Launcher\EgressGuard.Launcher.csproj') @publishCommon -o $stage
if ($LASTEXITCODE -ne 0) { Write-Host '[fail] launcher publish failed.'; exit 10 }

Write-Step 'publishing service (self-contained win-x64)'
& dotnet publish (Join-Path $repoRoot 'src\EgressGuard.Service\EgressGuard.Service.csproj') @publishCommon -o (Join-Path $stage 'service')
if ($LASTEXITCODE -ne 0) { Write-Host '[fail] service publish failed.'; exit 11 }

Write-Step 'publishing UI (self-contained win-x64)'
& dotnet publish (Join-Path $repoRoot 'src\EgressGuard.UI\EgressGuard.UI.csproj') @publishCommon -o (Join-Path $stage 'ui')
if ($LASTEXITCODE -ne 0) { Write-Host '[fail] UI publish failed.'; exit 12 }

Write-Step 'restoring package lock files'
foreach ($pair in $lockBackups) {
    Copy-Item -LiteralPath $pair[1] -Destination $pair[0] -Force
    Remove-Item -LiteralPath $pair[1] -Force
}
Write-Host ("[ok  ] restored " + $lockBackups.Count + " package lock file(s).")

Write-Step 'writing Vietnamese quick-start guide and commit information'
$guideText = @"
EGRESSGUARD - BAN DUNG THU (PREVIEW) - win-x64
==============================================

Cach chay nhanh
---------------
1. Giai nen toan bo tep trong thu muc nay vao mot thu muc bat ky tren may.
2. Mo tep 'EgressGuard.Launcher.exe'.
   Trinh khoi dong se tu:
     - Khoi dong Service va giao dien tu cung thu muc ban giai nen.
     - Tao du lieu rieng tai %LOCALAPPDATA%\EgressGuard-Preview.
     - Dung kenh Named Pipe rieng cho moi lan chay.
   Ban chi can doi giao dien hien len.

Dung chuong trinh
-----------------
- Dong cua so giao dien: trinh khoi dong se tu dung Service ma no da khoi dong.

Luu y quan trong
----------------
- Day la BAN DUNG THU CHUA KY SO. Windows SmartScreen co the hien canh bao;
  day la hanh vi binh thuong voi ung dung chua ky so.
- Khi mo tep theo doi lan dau tien, Windows co the yeu cau quyen quan tri;
  trinh khoi dong KHONG tu nang quyen - ban tu quyet dinh.
- Neu chinh sach Windows chan ung dung, hay bao cao loi ban thay; khong tat
  bat ky tinh nang bao mat nao cua Windows.

Chay nhieu phien
----------------
Chi mot phien dung thu duoc chay cung luc cho mot thu muc du lieu. Neu mo
lan thu hai, trinh khoi dong se bao loi va thoat.

Thong tin ban dung
------------------
Xem tep 'commit-info.txt' de biet dung commit ma ban duoc tao tu do.
"@
[System.IO.File]::WriteAllText((Join-Path $stage 'HUONG-DAN.txt'), $guideText, (New-Object System.Text.UTF8Encoding($true)))

$headSha = (& git rev-parse HEAD)
$headDate = (& git log -1 --format=%cI)
$dirtyCount = @(git status --porcelain).Count
$commitInfo = "commit: $headSha`ncommitted-at: $headDate`nbuilt-from-dirty-worktree: $(if ($dirtyCount -gt 0) { 'yes' } else { 'no' })`npackage-created-utc: $([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))`n"
[System.IO.File]::WriteAllText((Join-Path $stage 'commit-info.txt'), $commitInfo, (New-Object System.Text.UTF8Encoding($false)))

Write-Step 'compressing package'
if (Test-Path -LiteralPath $zipPath) {
    Remove-Item -LiteralPath $zipPath -Force
}
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zipPath -CompressionLevel Optimal
Write-Host ("[ok  ] package written: " + $zipPath)

Write-Step 'verifying package contents'
$problems = Get-PackageViolations -ZipPath $zipPath
if ($problems.Count -gt 0) {
    foreach ($problem in $problems) { Write-Host ('[!]   ' + $problem) }
    Write-Host '[fail] package verification failed.'
    exit 14
}

Write-Host '[ok  ] package verified: required files present, nothing forbidden.'
exit 0