$ErrorActionPreference = "Stop"

$BackupDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SitesDir = Join-Path $HOME "Projects\sites"
$DefaultPhpVersion = "8.4"
$DefaultDbVersion = "11.8"

function Require-Command {
    param([string] $Name)

    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Missing required command: $Name"
    }
}

function Prompt-Default {
    param(
        [string] $Message,
        [string] $Default
    )

    if ($Default -ne "") {
        $inputValue = Read-Host "$Message [$Default]"
        if ($inputValue -eq "") {
            return $Default
        }

        return $inputValue
    }

    return Read-Host $Message
}

function Confirm-DefaultYes {
    param([string] $Message)

    $choice = Read-Host "$Message (Y/n)"
    return ($choice -eq "" -or $choice -match "^[Yy]$")
}

function Confirm-NoDefault {
    param([string] $Message)

    $choice = Read-Host "$Message (y/n)"
    return ($choice -match "^[Yy]$")
}

function Slugify {
    param([string] $Value)

    $slug = $Value.Trim().ToLowerInvariant()
    $slug = $slug -replace "^https?://", ""
    $slug = $slug.Trim("/")
    $slug = $slug -replace "^www\.", ""
    $slug = $slug -replace "[^a-z0-9]+", "-"
    $slug = $slug.Trim("-")

    if ($slug -eq "") {
        return "synchy-site"
    }

    return $slug
}

function Get-ShortProjectName {
    param([string] $Url)

    $value = $Url.Trim().ToLowerInvariant()
    $value = $value -replace "^https?://", ""
    $value = $value.Trim("/")
    $value = ($value -split "/")[0]
    $value = $value -replace "^www\.", ""
    $base = ($value -split "\.")[0]
    $base = $base -replace "[^a-z0-9]+", ""

    foreach ($suffix in @("shoffman", "hoffman")) {
        if ($base.EndsWith($suffix) -and $base.Length -gt $suffix.Length) {
            $base = $base.Substring(0, $base.Length - $suffix.Length)
            break
        }
    }

    if ($base -eq "") {
        return "site"
    }

    return $base
}

function Get-SynchyBackups {
    $rows = @()
    $manifestPaths = Get-ChildItem -Path $BackupDir -Filter "*-manifest.json" -File | Sort-Object FullName

    foreach ($manifestPath in $manifestPaths) {
        try {
            $manifest = Get-Content -LiteralPath $manifestPath.FullName -Raw | ConvertFrom-Json
        } catch {
            continue
        }

        $packageName = [string] $manifest.package_name
        if ($packageName -eq "") {
            $packageName = $manifestPath.Name -replace "-manifest\.json$", ""
        }

        $archiveName = ""
        if ($manifest.artifacts -and $manifest.artifacts.archive) {
            $archiveName = [string] $manifest.artifacts.archive.filename
        }

        $installerName = ""
        if ($manifest.artifacts -and $manifest.artifacts.installer) {
            $installerName = [string] $manifest.artifacts.installer.filename
        }

        if ($archiveName -eq "") {
            $archiveName = "$packageName.zip"
        }

        if ($installerName -eq "") {
            $installerName = "$packageName-installer.php"
        }

        $archivePath = Join-Path $BackupDir $archiveName
        $installerPath = Join-Path $BackupDir $installerName

        if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf)) {
            continue
        }

        if (-not (Test-Path -LiteralPath $installerPath -PathType Leaf)) {
            continue
        }

        $createdRaw = [string] $manifest.created_at_gmt
        $createdDisplay = "Unknown date"
        $sortKey = ""

        if ($createdRaw -ne "") {
            try {
                $createdDate = [DateTimeOffset]::Parse($createdRaw)
                $createdDisplay = $createdDate.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss 'UTC'")
                $sortKey = $createdDate.UtcDateTime.ToString("o")
            } catch {
                $createdDisplay = $createdRaw
                $sortKey = $createdRaw
            }
        }

        $homeUrl = ""
        $dbPrefix = "wp_"
        if ($manifest.site) {
            $homeUrl = [string] $manifest.site.home_url
            if ($homeUrl -eq "") {
                $homeUrl = [string] $manifest.site.site_url
            }
            if ([string] $manifest.site.db_prefix -ne "") {
                $dbPrefix = [string] $manifest.site.db_prefix
            }
        }

        if ($homeUrl -eq "") {
            $homeUrl = "Unknown source URL"
        }

        $size = (Get-Item -LiteralPath $archivePath).Length
        if ($manifest.artifacts -and $manifest.artifacts.archive -and [string] $manifest.artifacts.archive.size_bytes -ne "") {
            $size = [Int64] $manifest.artifacts.archive.size_bytes
        }

        $rows += [PSCustomObject] @{
            SortKey = $sortKey
            Manifest = $manifestPath.FullName
            Archive = $archivePath
            Installer = $installerPath
            Package = $packageName
            Created = $createdDisplay
            Home = $homeUrl
            Prefix = $dbPrefix
            Suggested = Get-ShortProjectName $homeUrl
            Size = $size
        }
    }

    return @($rows | Sort-Object SortKey -Descending)
}

function Select-Backup {
    param([array] $Backups)

    if ($Backups.Count -eq 1) {
        return 0
    }

    $selected = 0

    while ($true) {
        Clear-Host
        Write-Host "Available Synchy/freeSIEM exports"
        Write-Host "Use up/down arrows, Enter to select, q to quit."
        Write-Host ""

        for ($i = 0; $i -lt $Backups.Count; $i++) {
            $backup = $Backups[$i]
            if ($i -eq $selected) {
                Write-Host (" > {0} | {1} | {2}" -f $backup.Package, $backup.Created, $backup.Home)
            } else {
                Write-Host ("   {0} | {1} | {2}" -f $backup.Package, $backup.Created, $backup.Home)
            }
        }

        $key = [Console]::ReadKey($true)

        if ($key.Key -eq [ConsoleKey]::UpArrow -and $selected -gt 0) {
            $selected--
        } elseif ($key.Key -eq [ConsoleKey]::DownArrow -and $selected -lt ($Backups.Count - 1)) {
            $selected++
        } elseif ($key.Key -eq [ConsoleKey]::Enter) {
            return $selected
        } elseif ($key.KeyChar -eq "q" -or $key.KeyChar -eq "Q") {
            Write-Host "Cancelled."
            exit 0
        }
    }
}

function Choose-WordPressSource {
    param([string] $ExtractDir)

    $stagingPath = Join-Path $ExtractDir "staging"
    if (
        (Test-Path -LiteralPath (Join-Path $stagingPath "wp-admin") -PathType Container) -and
        (Test-Path -LiteralPath (Join-Path $stagingPath "wp-content") -PathType Container)
    ) {
        return $stagingPath
    }

    return $ExtractDir
}

function Ensure-WpConfigForDdev {
    param(
        [string] $Docroot,
        [string] $DbPrefix
    )

    $wpConfig = Join-Path $Docroot "wp-config.php"
    $wpConfigSample = Join-Path $Docroot "wp-config-sample.php"

    if ((-not (Test-Path -LiteralPath $wpConfig -PathType Leaf)) -and (Test-Path -LiteralPath $wpConfigSample -PathType Leaf)) {
        Copy-Item -LiteralPath $wpConfigSample -Destination $wpConfig
    }

    if (-not (Test-Path -LiteralPath $wpConfig -PathType Leaf)) {
        throw "wp-config.php was not found and wp-config-sample.php was not available."
    }

    $contents = Get-Content -LiteralPath $wpConfig -Raw
    $contents = $contents -replace "define\(\s*['""]DB_NAME['""]\s*,\s*['""][^'""]*['""]\s*\)\s*;", "define('DB_NAME', 'db');"
    $contents = $contents -replace "define\(\s*['""]DB_USER['""]\s*,\s*['""][^'""]*['""]\s*\)\s*;", "define('DB_USER', 'db');"
    $contents = $contents -replace "define\(\s*['""]DB_PASSWORD['""]\s*,\s*['""][^'""]*['""]\s*\)\s*;", "define('DB_PASSWORD', 'db');"
    $contents = $contents -replace "define\(\s*['""]DB_HOST['""]\s*,\s*['""][^'""]*['""]\s*\)\s*;", "define('DB_HOST', 'db');"
    $escapedPrefix = $DbPrefix.Replace("\", "\\").Replace("'", "\'")
    $contents = $contents -replace "\`$table_prefix\s*=\s*['""][^'""]+['""]\s*;", "`$table_prefix = '$escapedPrefix';"

    Set-Content -LiteralPath $wpConfig -Value $contents -NoNewline
}

function Remove-LocalRuntimeFiles {
    param([string] $Docroot)

    $targets = @(
        "wp-content\cache",
        "wp-content\uploads\cache",
        "wp-content\wflogs"
    )

    foreach ($target in $targets) {
        $path = Join-Path $Docroot $target
        if (Test-Path -LiteralPath $path) {
            Get-ChildItem -LiteralPath $path -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    foreach ($file in @("wp-content\advanced-cache.php", "wp-content\object-cache.php")) {
        $path = Join-Path $Docroot $file
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
    }
}

function Deactivate-BrokenFreesiemPlugin {
    param([string] $Docroot)

    $pluginDir = Join-Path $Docroot "wp-content\plugins\freesiem-sentinel"
    $runtimeFile = Join-Path $pluginDir "includes\synchy\synchy-runtime.php"

    if ((Test-Path -LiteralPath $pluginDir -PathType Container) -and (-not (Test-Path -LiteralPath $runtimeFile -PathType Leaf))) {
        Write-Host "Deactivating freesiem-sentinel because its Synchy runtime file is missing..."
        & ddev wp plugin deactivate freesiem-sentinel --skip-plugins --skip-themes
    }
}

function Ensure-DockerReady {
    & docker info *> $null
    if ($LASTEXITCODE -eq 0) {
        return
    }

    Write-Host "Docker is not ready. Opening Docker Desktop..."
    $dockerDesktop = "C:\Program Files\Docker\Docker\Docker Desktop.exe"
    if (Test-Path -LiteralPath $dockerDesktop -PathType Leaf) {
        Start-Process -FilePath $dockerDesktop
    } else {
        Start-Process "Docker Desktop"
    }

    Write-Host "Waiting for Docker Desktop..."
    for ($i = 0; $i -lt 60; $i++) {
        Start-Sleep -Seconds 2
        & docker info *> $null
        if ($LASTEXITCODE -eq 0) {
            return
        }
    }

    throw "Docker did not become ready within 120 seconds. Start Docker, then rerun this script."
}

Require-Command "ddev"
Require-Command "docker"
Require-Command "robocopy"

$backups = Get-SynchyBackups
if ($backups.Count -eq 0) {
    throw "No complete Synchy/freeSIEM export triplets found in: $BackupDir. Expected files: PACKAGE.zip, PACKAGE-installer.php, PACKAGE-manifest.json"
}

$selectedIndex = Select-Backup $backups
$backup = $backups[$selectedIndex]

Write-Host ""
Write-Host "Selected backup:"
Write-Host "  Package:      $($backup.Package)"
Write-Host "  Exported:     $($backup.Created)"
Write-Host "  Source:       $($backup.Home)"
Write-Host "  Archive:      $($backup.Archive)"
Write-Host ""

$projectName = Slugify (Prompt-Default "New DDEV project/site folder name" (Slugify $backup.Suggested))
$phpVersion = Prompt-Default "PHP version" $DefaultPhpVersion
$dbVersion = Prompt-Default "MariaDB version" $DefaultDbVersion

$projectPath = Join-Path $SitesDir $projectName
$docrootPath = $projectPath
$ddevUrl = "https://$projectName.ddev.site"

if (Test-Path -LiteralPath $projectPath) {
    throw "$projectPath already exists. Stopping without changes."
}

if (-not (Confirm-DefaultYes "Create $projectPath from this export")) {
    Write-Host "Cancelled."
    exit 0
}

New-Item -ItemType Directory -Path $SitesDir -Force | Out-Null
New-Item -ItemType Directory -Path $projectPath | Out-Null
Set-Location $projectPath

Write-Host "Configuring DDEV project..."
& ddev config "--project-name=$projectName" "--project-type=wordpress" "--docroot=" "--php-version=$phpVersion" "--database=mariadb:$dbVersion"
if ($LASTEXITCODE -ne 0) {
    throw "ddev config failed."
}

$importDir = Join-Path $projectPath ".synchy-import"
$extractDir = Join-Path $importDir "extracted"
if (Test-Path -LiteralPath $extractDir) {
    Remove-Item -LiteralPath $extractDir -Recurse -Force
}
New-Item -ItemType Directory -Path $extractDir -Force | Out-Null

Write-Host "Extracting archive..."
Expand-Archive -LiteralPath $backup.Archive -DestinationPath $extractDir -Force

$sourcePath = Choose-WordPressSource $extractDir

Write-Host "Copying WordPress files into the site root..."
& robocopy $sourcePath $docrootPath /MIR /XD (Join-Path $sourcePath "synchy") (Join-Path $projectPath ".synchy-import") (Join-Path $sourcePath ".ddev") (Join-Path $sourcePath ".git") /XF ".DS_Store" | Out-Host
if ($LASTEXITCODE -gt 7) {
    throw "robocopy failed with exit code $LASTEXITCODE."
}

Write-Host "Updating wp-config.php for DDEV..."
Ensure-WpConfigForDdev $docrootPath $backup.Prefix

Ensure-DockerReady

Write-Host "Starting DDEV..."
& ddev start
if ($LASTEXITCODE -ne 0) {
    throw "ddev start failed."
}

$databasePath = Join-Path $extractDir "synchy\database.sql"
if (Test-Path -LiteralPath $databasePath -PathType Leaf) {
    Write-Host "Importing bundled database..."
    & ddev import-db "--file=$databasePath"
    if ($LASTEXITCODE -ne 0) {
        throw "ddev import-db failed."
    }
} else {
    Write-Host "No bundled database found at synchy/database.sql; skipping DB import."
}

Deactivate-BrokenFreesiemPlugin $docrootPath

& ddev wp core is-installed --skip-plugins --skip-themes *> $null
if ($LASTEXITCODE -eq 0) {
    $currentHome = (& ddev wp option get home --skip-plugins --skip-themes 2>$null)
    $currentSiteUrl = (& ddev wp option get siteurl --skip-plugins --skip-themes 2>$null)

    Write-Host "Rewriting WordPress URLs to $ddevUrl ..."

    if ($currentHome -ne "" -and $currentHome -ne $ddevUrl) {
        & ddev wp search-replace $currentHome $ddevUrl --all-tables --skip-columns=guid --skip-plugins --skip-themes
    }

    if ($currentSiteUrl -ne "" -and $currentSiteUrl -ne $currentHome -and $currentSiteUrl -ne $ddevUrl) {
        & ddev wp search-replace $currentSiteUrl $ddevUrl --all-tables --skip-columns=guid --skip-plugins --skip-themes
    }

    if ($backup.Home -ne "Unknown source URL" -and $backup.Home -ne $currentHome -and $backup.Home -ne $currentSiteUrl) {
        & ddev wp search-replace $backup.Home $ddevUrl --all-tables --skip-columns=guid --skip-plugins --skip-themes
        & ddev wp search-replace $backup.Home.TrimEnd("/") $ddevUrl --all-tables --skip-columns=guid --skip-plugins --skip-themes
    }

    & ddev wp option update home $ddevUrl --skip-plugins --skip-themes | Out-Null
    & ddev wp option update siteurl $ddevUrl --skip-plugins --skip-themes | Out-Null
    & ddev wp rewrite flush --hard --skip-plugins --skip-themes
    & ddev wp cache flush --skip-plugins --skip-themes
}

Write-Host "Cleaning cache/runtime files from restored copy..."
Remove-LocalRuntimeFiles $docrootPath

if (Confirm-NoDefault "Launch site in browser now") {
    & ddev launch
}

Write-Host ""
Write-Host "Done."
Write-Host "Project path: $projectPath"
Write-Host "Frontend:     $ddevUrl"
Write-Host "Admin:        $ddevUrl/wp-admin"
