#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Cross-platform Windows forensics automation: summarises the JSON written
    by extract_eventlogs.py and extract_registry.py, builds a timeline and a
    Markdown report.

.DESCRIPTION
    Reads (never changes) the JSON files under:
        <DataPath>/event-logs/*.json      from extract_eventlogs.py
        <DataPath>/registry-hives/*.json  from extract_registry.py
    and writes to <OutputPath>:
        <name>_analysis.json      one per event log (e.g. security_events_analysis.json)
        registry_analysis.json    all registry findings
        forensic_timeline.json    every timestamped finding, oldest first
        forensic_report.md        summary, findings, indicators, recommendations

    It summarises and flags; analyze_activity.py grades the result and writes
    the IOC report.

.EXAMPLE
    pwsh -File forensic_automation.ps1
    pwsh -File forensic_automation.ps1 -DataPath /home/student/forensics-lab/samples -OutputPath ./forensic_output

.NOTES
    Exit status: 0 on success, 1 on an error, 2 if DataPath does not exist.
#>

param(
    [string]$DataPath = "./samples",
    [string]$OutputPath = "./forensic_output",
    [int]$FailedLogonThreshold = 10
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0

# Event IDs the lab asks to watch, plus the "key indicators" it lists.
$SuspiciousEventIds = [ordered]@{
    1102 = "Security audit log cleared"
    104  = "Event log cleared"
    4624 = "Successful logon"
    4625 = "Failed logon"
    4648 = "Logon with explicit credentials"
    4672 = "Special privileges assigned"
    4688 = "Process created"
    4720 = "User account created"
    4732 = "Member added to local group"
    4740 = "Account locked out"
    7040 = "Service start type changed"
    7045 = "New service installed"
}
$EventNames = @{
    1102 = "Security audit log was cleared"; 104 = "Event log was cleared"
    4624 = "Successful logon"; 4625 = "Failed logon"; 4634 = "Logoff"
    4648 = "Logon with explicit credentials"; 4672 = "Special privileges assigned to new logon"
    4688 = "New process created"; 4720 = "User account created"
    4732 = "Member added to a local security group"; 4740 = "User account locked out"
    6005 = "Event Log service started (boot)"; 6006 = "Event Log service stopped (shutdown)"
    6008 = "Unexpected shutdown"; 7036 = "Service changed state"
    7040 = "Service start type changed"; 7045 = "New service installed"
}
# Events worth a line in the timeline (4625 is summarised per source instead).
$NotableIds = @(1102, 104, 4648, 4672, 4688, 4720, 4732, 4740, 6005, 6006, 6008, 7040, 7045)
$LogonTypes = @{ 2 = "interactive"; 3 = "network"; 5 = "service"; 7 = "unlock"; 10 = "RDP"; 11 = "cached" }

# A value name suggesting a stored secret. Plain "key" is deliberately not
# enough: TimeZoneKeyName and KeyboardDelay are not secrets.
$SensitivePattern = '(pass(word|wd|phrase)?|pwd|secret|token|credential|(api|access|private|secret|encryption|license|product)[_-]?key)'
# Folders any user can write to: a service or autostart program there is a red flag.
$UserWritablePattern = '(\\Users\\Public\\|\\AppData\\|\\Temp\\|\\Windows\\Temp\\|\\PerfLogs\\|\\Downloads\\|\\ProgramData\\(?!Microsoft\\))'
$RemoteAccessPattern = '(AnyDesk|TeamViewer|ScreenConnect|ConnectWise Control|RustDesk|Splashtop|Atera|NetSupport|Radmin|RealVNC|TightVNC|UltraVNC|LogMeIn|Ammyy)'
$LolbinPattern = '(mshta(\.exe)?\s|rundll32(\.exe)?\s|regsvr32(\.exe)?\s|certutil(\.exe)?\s.*-urlcache|bitsadmin(\.exe)?\s)'

$script:Processed = [System.Collections.Generic.List[object]]::new()
$script:EventAnalyses = [System.Collections.Generic.List[object]]::new()
$script:RegistryAnalysis = $null
$script:Timeline = $null

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
function ConvertTo-IsoUtc {
    <# ConvertFrom-Json turns ISO strings into [datetime]; turn them back into
       one fixed UTC format so sorting and output never depend on the local
       time zone of the machine running this. #>
    param($Value)
    if ($null -eq $Value -or "$Value" -eq "") { return $null }
    if ($Value -is [datetime]) {
        $dt = $Value
        if ($dt.Kind -eq [DateTimeKind]::Local) { $dt = $dt.ToUniversalTime() }
        elseif ($dt.Kind -eq [DateTimeKind]::Unspecified) { $dt = [datetime]::SpecifyKind($dt, [DateTimeKind]::Utc) }
        return $dt.ToString("yyyy-MM-ddTHH:mm:ss.ffffff'Z'", [Globalization.CultureInfo]::InvariantCulture)
    }
    $parsed = [datetime]::MinValue
    $styles = [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal
    if ([datetime]::TryParse("$Value", [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
        return $parsed.ToString("yyyy-MM-ddTHH:mm:ss.ffffff'Z'", [Globalization.CultureInfo]::InvariantCulture)
    }
    return "$Value"
}

function Get-Prop {
    <# Safe property read under StrictMode: $null when the property is missing. #>
    param($Object, $Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] } else { return $Default }
    }
    $p = $Object.PSObject.Properties["$Name"]
    if ($null -eq $p) { return $Default }
    return $p.Value
}

function Get-Text {
    <# Data field as plain text (dates converted back to ISO). #>
    param($Object, [string]$Name)
    $v = Get-Prop $Object $Name
    if ($v -is [datetime]) { return (ConvertTo-IsoUtc $v) }
    if ($null -eq $v) { return "" }
    return "$v"
}

function Save-Json {
    param($Data, [string]$Path)
    $Data | ConvertTo-Json -Depth 12 | Set-Content -Path $Path -Encoding utf8NoBOM
}

function Read-JsonFile {
    param([string]$Path)
    try {
        return Get-Content -Raw -Path $Path | ConvertFrom-Json -Depth 64
    } catch {
        Write-Warning "Skipping $(Split-Path -Leaf $Path): not valid JSON ($($_.Exception.Message)). Check it with: jq . '$Path'"
        return $null
    }
}

function Format-Cell {
    <# Text from evidence is attacker-controlled: keep it from breaking the Markdown table. #>
    param($Text, [int]$Max = 120)
    $s = "$Text" -replace '[\r\n\t]+', ' ' -replace '\|', '\|' -replace '`', "'" -replace '<', '&lt;' -replace '>', '&gt;'
    if ($s.Length -gt $Max) { $s = $s.Substring(0, $Max - 3) + "..." }
    return $s
}

function Test-PrivateAddress {
    param([string]$Ip)
    if ([string]::IsNullOrWhiteSpace($Ip) -or $Ip -in @("-", "::1", "127.0.0.1", "0.0.0.0")) { return $true }
    return ($Ip -match '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|fe80:|fc|fd)')
}

function Get-DecodedCommand {
    <# Decode a PowerShell -EncodedCommand for display only. Nothing is run. #>
    param([string]$CommandLine)
    if ($CommandLine -match '(?i)-e(nc|ncodedcommand|c)?\s+([A-Za-z0-9+/=]{16,})') {
        try {
            return [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($Matches[2]))
        } catch { return $null }
    }
    return $null
}

# --------------------------------------------------------------------------
# Task 3: event logs
# --------------------------------------------------------------------------
function Analyze-EventLogs {
    param([string]$LogPath)

    if (-not (Test-Path -Path $LogPath -PathType Container)) {
        Write-Warning "No event log folder at $LogPath"
        return
    }
    $files = Get-ChildItem -Path $LogPath -Filter "*.json" -File | Sort-Object Name
    foreach ($file in $files) {
        $doc = Read-JsonFile $file.FullName
        if ($null -eq $doc) { continue }
        $events = @(Get-Prop $doc "events" @())
        if ($null -eq (Get-Prop $doc "events")) {
            Write-Verbose "Skipping $($file.Name): not an extract_eventlogs.py file"
            continue
        }
        Write-Host "  Event log: $($file.Name) ($($events.Count) events)"

        $idCounts = @{}
        $byHour = [int[]]::new(24)
        $byComputer = @{}
        $suspiciousByComputer = @{}
        $suspiciousCounts = [ordered]@{}
        $sources = @{}
        $failedByAccount = @{}
        $notable = [System.Collections.Generic.List[object]]::new()
        $remoteLogons = [System.Collections.Generic.List[object]]::new()
        $first = $null; $last = $null

        foreach ($e in $events) {
            $id = [int](Get-Prop $e "event_id" 0)
            $ts = ConvertTo-IsoUtc (Get-Prop $e "timestamp")
            $computer = Get-Text $e "computer_name"
            $data = Get-Prop $e "event_data"
            $idCounts[$id] = 1 + [int]$idCounts[$id]
            $byComputer[$computer] = 1 + [int]$byComputer[$computer]
            if ($ts) {
                if ($null -eq $first -or $ts -lt $first) { $first = $ts }
                if ($null -eq $last -or $ts -gt $last) { $last = $ts }
                $byHour[[int]$ts.Substring(11, 2)]++
            }

            $isSuspicious = $SuspiciousEventIds.Contains($id) -and $id -ne 4624
            if ($id -eq 4672 -and (Get-Text $data "SubjectUserSid") -eq "S-1-5-18") { $isSuspicious = $false }
            if ($isSuspicious) {
                $suspiciousByComputer[$computer] = 1 + [int]$suspiciousByComputer[$computer]
            }
            if ($SuspiciousEventIds.Contains($id)) {
                $suspiciousCounts["$id"] = 1 + [int]$suspiciousCounts["$id"]
            }

            # Logons per source address: the raw material for brute-force detection.
            if ($id -in 4624, 4625) {
                $ip = Get-Text $data "IpAddress"
                $user = Get-Text $data "TargetUserName"
                $logonType = [int](Get-Prop $data "LogonType" 0)
                if (-not $sources.ContainsKey($ip)) {
                    $sources[$ip] = [ordered]@{
                        Failed = 0; Succeeded = 0; FirstFailure = $null; LastFailure = $null
                        FirstSuccess = $null; FirstSuccessAfterFailure = $null
                        AccountsTried = @{}; SuccessfulAccounts = @{}; LogonTypes = @{}
                    }
                }
                $s = $sources[$ip]
                $s.LogonTypes["$logonType"] = 1 + [int]$s.LogonTypes["$logonType"]
                if ($id -eq 4625) {
                    $s.Failed++
                    $s.AccountsTried[$user] = 1 + [int]$s.AccountsTried[$user]
                    $failedByAccount[$user] = 1 + [int]$failedByAccount[$user]
                    if ($null -eq $s.FirstFailure -or $ts -lt $s.FirstFailure) { $s.FirstFailure = $ts }
                    if ($null -eq $s.LastFailure -or $ts -gt $s.LastFailure) { $s.LastFailure = $ts }
                } else {
                    $s.Succeeded++
                    $s.SuccessfulAccounts[$user] = 1 + [int]$s.SuccessfulAccounts[$user]
                    if ($null -eq $s.FirstSuccess -or $ts -lt $s.FirstSuccess) { $s.FirstSuccess = $ts }
                    if ($logonType -in 3, 10 -and -not (Test-PrivateAddress $ip)) {
                        $remoteLogons.Add([ordered]@{ Timestamp = $ts; User = $user; IpAddress = $ip
                                LogonType = $logonType; RecordId = Get-Prop $e "record_id" })
                    }
                }
            }

            if ($id -in $NotableIds -or ($id -eq 4624 -and [int](Get-Prop $data "LogonType" 0) -in 3, 10)) {
                if ($id -eq 4672 -and (Get-Text $data "SubjectUserSid") -eq "S-1-5-18") { continue }
                $details = [ordered]@{}
                if ($null -ne $data) {
                    foreach ($p in $data.PSObject.Properties) { $details[$p.Name] = Get-Text $data $p.Name }
                }
                $desc = Get-Prop $EventNames $id ("Event $id")
                switch ($id) {
                    4624 { $desc = "Logon ($($LogonTypes[[int]$details['LogonType']])) by $($details['TargetUserName']) from $($details['IpAddress'])" }
                    4648 { $desc = "$($details['SubjectUserName']) used explicit credentials for $($details['TargetUserName']) via $($details['ProcessName'])" }
                    4672 { $desc = "Admin privileges assigned to $($details['SubjectUserName'])" }
                    4688 { $desc = "Process $($details['NewProcessName']) started by $($details['SubjectUserName'])" }
                    4720 { $desc = "User account $($details['TargetUserName']) created by $($details['SubjectUserName'])" }
                    4732 { $desc = "$($details['MemberSid']) added to $($details['TargetUserName']) by $($details['SubjectUserName'])" }
                    1102 { $desc = "Security log cleared by $($details['SubjectUserName'])" }
                    7045 { $desc = "Service '$($details['ServiceName'])' installed: $($details['ImagePath']) ($($details['StartType']), $($details['AccountName']))" }
                    7040 { $desc = "Start type of '$($details['param1'])' changed from $($details['param2']) to $($details['param3'])" }
                }
                $decoded = Get-DecodedCommand ($details['CommandLine'])
                if ($decoded) { $details["DecodedCommand"] = $decoded }
                $notable.Add([ordered]@{
                    Timestamp = $ts; EventID = $id; Description = $desc; Computer = $computer
                    RecordId = Get-Prop $e "record_id"; Details = $details
                })
            }
        }

        $top = @($idCounts.GetEnumerator() | Sort-Object -Property @{ Expression = "Value"; Descending = $true }, @{ Expression = "Key" } |
            Select-Object -First 10 | ForEach-Object {
                [ordered]@{ EventID = [int]$_.Key; Count = $_.Value; Description = (Get-Prop $EventNames ([int]$_.Key) "Event $($_.Key)") }
            })
        # Sort fully (hashtable order differs between runs).
        $sourceList = @($sources.GetEnumerator() |
            Sort-Object -Property @{ Expression = { $_.Value.Failed }; Descending = $true },
                                  @{ Expression = { $_.Value.Succeeded }; Descending = $true },
                                  @{ Expression = { $_.Key } } | ForEach-Object {
                $s = $_.Value
                # Correlate only real remote addresses: "-" lumps together every local logon.
                if ($s.FirstFailure -and -not ($_.Key -in @("", "-", "::1", "127.0.0.1"))) {
                    $after = $null
                    foreach ($e in $events) {
                        if ([int](Get-Prop $e "event_id" 0) -ne 4624) { continue }
                        $d = Get-Prop $e "event_data"
                        if ((Get-Text $d "IpAddress") -ne $_.Key) { continue }
                        $t = ConvertTo-IsoUtc (Get-Prop $e "timestamp")
                        if ($t -ge $s.FirstFailure -and ($null -eq $after -or $t -lt $after.Timestamp)) {
                            $after = [ordered]@{ Timestamp = $t; User = (Get-Text $d "TargetUserName"); RecordId = Get-Prop $e "record_id" }
                        }
                    }
                    $s.FirstSuccessAfterFailure = $after
                }
                [ordered]@{
                    IpAddress = $_.Key; Failed = $s.Failed; Succeeded = $s.Succeeded
                    External = -not (Test-PrivateAddress $_.Key)
                    FirstFailure = $s.FirstFailure; LastFailure = $s.LastFailure
                    FirstSuccessAfterFailure = $s.FirstSuccessAfterFailure
                    AccountsTried = $s.AccountsTried; SuccessfulAccounts = $s.SuccessfulAccounts
                    LogonTypes = $s.LogonTypes
                }
            })

        $name = [IO.Path]::GetFileNameWithoutExtension($file.Name)
        $analysis = [ordered]@{
            AnalysisType          = "EventLog"
            SourceFile            = $file.Name
            OriginalEvidence      = Get-Prop $doc "source_file"
            OriginalSha256        = Get-Prop $doc "source_sha256"
            Channel               = Get-Prop $doc "channel"
            AnalyzedAt            = ConvertTo-IsoUtc ([datetime]::UtcNow)
            TotalEvents           = $events.Count
            ParseErrors           = @(Get-Prop $doc "parse_errors" @()).Count
            UniqueEventIDs        = $idCounts.Count
            TopEventIDs           = $top
            SuspiciousEvents      = $suspiciousCounts
            DateRange             = [ordered]@{ Start = $first; End = $last }
            EventsByHourUTC       = $byHour
            EventsByComputer      = $byComputer
            SuspiciousByComputer  = $suspiciousByComputer
            LogonsBySource        = $sourceList
            FailedLogonsByAccount = $failedByAccount
            RemoteLogonsFromPublicAddresses = $remoteLogons
            NotableEvents         = $notable
        }
        Save-Json $analysis (Join-Path $OutputPath "$($name)_analysis.json")
        $script:EventAnalyses.Add($analysis)
        $script:Processed.Add([ordered]@{ File = $file.Name; Kind = "event log ($($analysis.Channel))"; Items = $events.Count
                Sha256 = $analysis.OriginalSha256; Evidence = $analysis.OriginalEvidence })
    }
}

# --------------------------------------------------------------------------
# Task 3: registry
# --------------------------------------------------------------------------
function Find-SensitiveValues {
    <# Walk any JSON tree; report {name, data} pairs whose name looks like a secret. #>
    param($Node, [string]$Path, $Results, [string]$File)
    if ($null -eq $Node) { return }
    if ($Node -is [System.Collections.IList] -and $Node -isnot [string]) {
        $i = 0
        foreach ($item in $Node) { Find-SensitiveValues $item "$Path[$i]" $Results $File; $i++ }
        return
    }
    if ($Node -isnot [System.Management.Automation.PSCustomObject]) { return }
    $name = Get-Prop $Node "name"
    $data = Get-Prop $Node "data"
    if ($null -ne $name -and $null -ne (Get-Prop $Node "type") -and "$name" -match $SensitivePattern -and
        $data -is [string] -and $data -ne "") {
        $Results.Add([ordered]@{ File = $File; Key = ((Get-Prop $Node "path" $Path) -replace '\.values\[\d+\]$', ''); Name = "$name"
                Keyword = $Matches[1]; Data = $data; Masked = [bool](Get-Prop $Node "masked" $false) })
    }
    foreach ($p in $Node.PSObject.Properties) {
        if ($p.Value -is [System.Management.Automation.PSCustomObject] -or ($p.Value -is [System.Collections.IList] -and $p.Value -isnot [string])) {
            $childPath = $Path
            $keyPath = Get-Prop $Node "path"
            if ($keyPath) { $childPath = $keyPath }
            Find-SensitiveValues $p.Value "$childPath.$($p.Name)" $Results $File
        }
    }
}

function Analyze-RegistryData {
    param([string]$RegistryPath)

    $interesting = [System.Collections.Generic.List[object]]::new()
    $startup = [System.Collections.Generic.List[object]]::new()
    $services = [System.Collections.Generic.List[object]]::new()
    $flaggedServices = [System.Collections.Generic.List[object]]::new()
    $disabledSecurity = [System.Collections.Generic.List[object]]::new()
    $remoteTools = [System.Collections.Generic.List[object]]::new()
    $exclusions = [System.Collections.Generic.List[object]]::new()
    $files = [System.Collections.Generic.List[object]]::new()
    $regTimeline = [System.Collections.Generic.List[object]]::new()
    $system = [ordered]@{}
    $software = [ordered]@{}

    if (-not (Test-Path -Path $RegistryPath -PathType Container)) {
        Write-Warning "No registry folder at $RegistryPath"
    } else {
        foreach ($file in Get-ChildItem -Path $RegistryPath -Filter "*.json" -File | Sort-Object Name) {
            $doc = Read-JsonFile $file.FullName
            if ($null -eq $doc -or $null -eq (Get-Prop $doc "hive_type")) { continue }
            $hiveType = Get-Prop $doc "hive_type"
            Write-Host "  Registry: $($file.Name) ($hiveType)"
            $keyCount = 0; $valueCount = 0

            Find-SensitiveValues $doc "" $interesting $file.Name

            $info = Get-Prop $doc "system_info"
            if ($null -ne $info) {
                $tz = Get-Prop $info "timezone"
                $system = [ordered]@{
                    ComputerName = Get-Prop $info "computer_name"; ControlSet = Get-Prop $info "current_control_set"
                    TimeZone = Get-Prop $tz "name"; UtcOffsetMinutes = Get-Prop $tz "utc_offset_minutes"
                    LastShutdown = ConvertTo-IsoUtc (Get-Prop $info "last_shutdown")
                    Interfaces = @(Get-Prop $info "network_interfaces" @() | Where-Object { $_.ip_address } |
                            ForEach-Object { [ordered]@{ Address = $_.ip_address; Gateway = $_.default_gateway; Dhcp = $_.dhcp_enabled } })
                }
                foreach ($svc in @(Get-Prop $info "services" @())) {
                    $keyCount++
                    $entry = [ordered]@{
                        Name = $svc.name; DisplayName = $svc.display_name; ImagePath = $svc.image_path
                        StartType = $svc.start_type; Account = $svc.account
                        LastWritten = ConvertTo-IsoUtc $svc.last_written; Flags = @()
                    }
                    $services.Add($entry)
                    $flags = @()
                    if ($svc.image_path -match $UserWritablePattern) { $flags += "runs from a user-writable folder" }
                    if ($svc.start -in 0, 1, 2 -and $svc.image_path -match '(?i)\.(exe|dll)"?\s*$' -and
                        $svc.image_path -notmatch '(?i)(\\Windows\\|%SystemRoot%|%windir%|\\Program Files|\\ProgramData\\Microsoft\\|^System32\\|^\\SystemRoot\\)') {
                        $flags += "auto-start program outside Windows and Program Files"
                    }
                    if ($svc.display_name -match '(?i)(windows|microsoft|update)' -and $svc.image_path -match $UserWritablePattern) {
                        $flags += "name imitates a Windows component"
                    }
                    if ($flags) {
                        $entry.Flags = $flags
                        $flaggedServices.Add($entry)
                        $regTimeline.Add([ordered]@{ Timestamp = $entry.LastWritten; Source = "registry:SYSTEM"
                                Category = "persistence"; Description = "Service key $($svc.name) written ($($svc.image_path))" })
                    }
                    if ($svc.name -in @("WinDefend", "Sense", "WdNisSvc", "SecurityHealthService", "EventLog", "wscsvc", "MpsSvc") -and $svc.start -eq 4) {
                        $disabledSecurity.Add([ordered]@{ Name = $svc.name; DisplayName = $svc.display_name
                                LastWritten = ConvertTo-IsoUtc $svc.last_written })
                        $regTimeline.Add([ordered]@{ Timestamp = (ConvertTo-IsoUtc $svc.last_written); Source = "registry:SYSTEM"
                                Category = "defense evasion"; Description = "Security service $($svc.name) set to disabled" })
                    }
                }
            }

            if ($hiveType -eq "SOFTWARE") {
                $os = Get-Prop $doc "os"
                $software = [ordered]@{
                    ProductName = Get-Prop $os "product_name"; Version = Get-Prop $os "display_version"
                    Build = Get-Prop $os "build"; InstallDate = ConvertTo-IsoUtc (Get-Prop $os "install_date")
                    InstalledPrograms = @(Get-Prop $doc "installed_software" @()).Count
                }
                foreach ($app in @(Get-Prop $doc "installed_software" @())) {
                    $keyCount++
                    if ("$($app.name) $($app.publisher)" -match $RemoteAccessPattern) {
                        $remoteTools.Add([ordered]@{ Name = $app.name; Version = $app.version; Publisher = $app.publisher
                                InstallDate = "$($app.install_date)"; InstallLocation = $app.install_location
                                LastWritten = ConvertTo-IsoUtc $app.last_written })
                        $regTimeline.Add([ordered]@{ Timestamp = (ConvertTo-IsoUtc $app.last_written); Source = "registry:SOFTWARE"
                                Category = "remote access"; Description = "$($app.name) $($app.version) installed ($($app.install_location))" })
                    }
                }
                foreach ($s in @(Get-Prop $doc "startup_entries" @())) {
                    $valueCount++
                    $cmd = "$($s.command)"
                    $flags = @()
                    if ($cmd -match '(?i)-e(nc|ncodedcommand|c)?\s+[A-Za-z0-9+/=]{16,}') { $flags += "encoded PowerShell command" }
                    if ($cmd -match '(?i)-w(indowstyle)?\s+hidden') { $flags += "hidden window" }
                    if ($cmd -match '(?i)(downloadstring|invoke-webrequest|iwr |net\.webclient|start-bitstransfer)') { $flags += "downloads content" }
                    if ($cmd -match $UserWritablePattern) { $flags += "runs from a user-writable folder" }
                    if ($cmd -match $LolbinPattern) { $flags += "uses a living-off-the-land binary" }
                    if ($s.name -eq "Shell" -and $cmd.Trim() -ne "explorer.exe") { $flags += "Winlogon Shell is not explorer.exe" }
                    if ($s.name -eq "Userinit" -and $cmd.Trim().TrimEnd(',') -notmatch '(?i)^C:\\Windows\\system32\\userinit\.exe$') { $flags += "Winlogon Userinit has extra programs" }
                    $entry = [ordered]@{ Location = $s.location; Name = $s.name; Command = $cmd
                        LastWritten = ConvertTo-IsoUtc $s.last_written; Flags = $flags }
                    $decoded = Get-DecodedCommand $cmd
                    if ($decoded) { $entry["DecodedCommand"] = $decoded }
                    $startup.Add($entry)
                    if ($flags) {
                        $regTimeline.Add([ordered]@{ Timestamp = $entry.LastWritten; Source = "registry:SOFTWARE"
                                Category = "persistence"; Description = "Autostart '$($s.name)' in $($s.location): $($flags -join ', ')" })
                    }
                }
                $def = Get-Prop $doc "defender"
                foreach ($kind in "paths", "extensions", "processes") {
                    foreach ($x in @(Get-Prop $def "exclusions_$kind" @())) {
                        $when = ConvertTo-IsoUtc (Get-Prop $def "exclusions_$($kind)_last_written")
                        $exclusions.Add([ordered]@{ Kind = $kind; Value = $x; LastWritten = $when })
                        $regTimeline.Add([ordered]@{ Timestamp = $when; Source = "registry:SOFTWARE"
                                Category = "defense evasion"; Description = "Defender exclusion ($kind): $x" })
                    }
                }
            }

            $key = Get-Prop $doc "key"
            if ($null -ne $key) {
                $keyCount += 1 + [int](Get-Prop $key "subkey_count" 0)
                $valueCount += [int](Get-Prop $key "value_count" 0)
            }
            $files.Add([ordered]@{ File = $file.Name; HiveType = $hiveType; Evidence = Get-Prop $doc "source_file"
                    Sha256 = Get-Prop $doc "source_sha256"; KeysSummarised = $keyCount; ValuesSummarised = $valueCount })
            $script:Processed.Add([ordered]@{ File = $file.Name; Kind = "registry ($hiveType)"; Items = $keyCount + $valueCount
                    Sha256 = Get-Prop $doc "source_sha256"; Evidence = Get-Prop $doc "source_file" })
        }
    }

    foreach ($v in $interesting) {
        $regTimeline.Add([ordered]@{ Timestamp = $null; Source = "registry"; Category = "credential exposure"
                Description = "Value '$($v.Name)' looks like a stored secret ($($v.Key))" })
    }
    $script:RegistryAnalysis = [ordered]@{
        AnalysisType = "Registry"
        AnalyzedAt = ConvertTo-IsoUtc ([datetime]::UtcNow)
        Files = $files
        System = $system
        Software = $software
        TotalServices = $services.Count
        InterestingValues = $interesting
        StartupEntries = $startup
        FlaggedServices = $flaggedServices
        DisabledSecurityServices = $disabledSecurity
        DefenderExclusions = $exclusions
        RemoteAccessSoftware = $remoteTools
        RegistryTimeline = @($regTimeline | Where-Object { $_.Timestamp })
    }
    Save-Json $script:RegistryAnalysis (Join-Path $OutputPath "registry_analysis.json")
}

# --------------------------------------------------------------------------
# Timeline and report
# --------------------------------------------------------------------------
function Generate-Timeline {
    $entries = [System.Collections.Generic.List[object]]::new()
    foreach ($a in $script:EventAnalyses) {
        foreach ($n in $a.NotableEvents) {
            $entries.Add([ordered]@{ Timestamp = $n.Timestamp; Source = "eventlog:$($a.Channel)"; EventID = $n.EventID
                    Category = "event"; Description = $n.Description; RecordId = $n.RecordId })
        }
        foreach ($s in $a.LogonsBySource) {
            if ($s.Failed -ge $FailedLogonThreshold) {
                $entries.Add([ordered]@{ Timestamp = $s.FirstFailure; Source = "eventlog:$($a.Channel)"; EventID = 4625
                        Category = "brute force"; Description = "First of $($s.Failed) failed logons from $($s.IpAddress)" })
                $entries.Add([ordered]@{ Timestamp = $s.LastFailure; Source = "eventlog:$($a.Channel)"; EventID = 4625
                        Category = "brute force"; Description = "Last of $($s.Failed) failed logons from $($s.IpAddress)" })
            }
            if ($s.FirstSuccessAfterFailure -and $s.Failed -ge $FailedLogonThreshold) {
                $entries.Add([ordered]@{ Timestamp = $s.FirstSuccessAfterFailure.Timestamp; Source = "eventlog:$($a.Channel)"; EventID = 4624
                        Category = "brute force"; Description = "Successful logon as $($s.FirstSuccessAfterFailure.User) from $($s.IpAddress) after $($s.Failed) failures" })
            }
        }
    }
    if ($script:RegistryAnalysis) {
        foreach ($r in $script:RegistryAnalysis.RegistryTimeline) {
            $entries.Add([ordered]@{ Timestamp = $r.Timestamp; Source = $r.Source; EventID = $null
                    Category = $r.Category; Description = "$($r.Description) (key last written)" })
        }
        $sd = Get-Prop $script:RegistryAnalysis.System "LastShutdown"
        if ($sd) {
            $entries.Add([ordered]@{ Timestamp = $sd; Source = "registry:SYSTEM"; EventID = $null
                    Category = "system"; Description = "Last clean shutdown recorded in the registry" })
        }
    }
    $sorted = @($entries | Where-Object { $_.Timestamp } | Sort-Object -Property @{ Expression = { $_.Timestamp } }, @{ Expression = { "$($_.Description)" } })
    $script:Timeline = [ordered]@{
        Generated = ConvertTo-IsoUtc ([datetime]::UtcNow)
        TimeZone = "UTC"
        EntryCount = $sorted.Count
        Entries = $sorted
    }
    Save-Json $script:Timeline (Join-Path $OutputPath "forensic_timeline.json")
}

function Create-ForensicReport {
    $sb = [System.Text.StringBuilder]::new()
    $null = $sb.AppendLine("# Windows Forensic Analysis Report")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("Generated: $(ConvertTo-IsoUtc ([datetime]::UtcNow)) by forensic_automation.ps1 (PowerShell $($PSVersionTable.PSVersion) on $([Runtime.InteropServices.RuntimeInformation]::OSDescription.Trim()))")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("All times are UTC. The graded IOC report comes from analyze_activity.py.")
    $null = $sb.AppendLine()

    $null = $sb.AppendLine("## Files processed")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("| File | Type | Items | Original evidence | SHA-256 of evidence |")
    $null = $sb.AppendLine("| --- | --- | ---: | --- | --- |")
    foreach ($p in $script:Processed) {
        $null = $sb.AppendLine("| $(Format-Cell $p.File) | $(Format-Cell $p.Kind) | $($p.Items) | $(Format-Cell $p.Evidence) | ``$(Format-Cell $p.Sha256 80)`` |")
    }
    if ($script:Processed.Count -eq 0) { $null = $sb.AppendLine("| (none found) | | | | |") }
    $null = $sb.AppendLine()

    $null = $sb.AppendLine("## Key findings")
    $null = $sb.AppendLine()
    $reg = $script:RegistryAnalysis
    if ($reg -and $reg.System.Count) {
        $sys = $reg.System
        $offset = Get-Prop $sys "UtcOffsetMinutes"
        $null = $sb.AppendLine("- **Computer:** $(Format-Cell $sys.ComputerName), control set $($sys.ControlSet), time zone $(Format-Cell $sys.TimeZone) (UTC$('{0:+0.#;-0.#;+0}' -f ([double]$offset / 60)))")
        foreach ($i in $sys.Interfaces) { $null = $sb.AppendLine("- **Network:** $(Format-Cell $i.Address), gateway $(Format-Cell $i.Gateway)$(if ($i.Dhcp) { ' (DHCP)' })") }
        if ($sys.LastShutdown) { $null = $sb.AppendLine("- **Last clean shutdown:** $($sys.LastShutdown)") }
    }
    if ($reg -and $reg.Software.Count) {
        $sw = $reg.Software
        $null = $sb.AppendLine("- **Windows:** $(Format-Cell $sw.ProductName) $(Format-Cell $sw.Version) (build $($sw.Build)), installed $($sw.InstallDate); $($sw.InstalledPrograms) programs, $($reg.TotalServices) services")
    }
    foreach ($a in $script:EventAnalyses) {
        $topText = ($a.TopEventIDs | Select-Object -First 3 | ForEach-Object { "$($_.EventID) x$($_.Count)" }) -join ", "
        $null = $sb.AppendLine("- **$($a.Channel) log:** $($a.TotalEvents) events from $($a.DateRange.Start) to $($a.DateRange.End); most frequent: $topText")
    }
    $null = $sb.AppendLine()

    $null = $sb.AppendLine("## Suspicious activity indicators")
    $null = $sb.AppendLine()
    $indicators = [System.Collections.Generic.List[string]]::new()
    foreach ($a in $script:EventAnalyses) {
        foreach ($s in $a.LogonsBySource) {
            if ($s.Failed -ge $FailedLogonThreshold) {
                $accounts = ($s.AccountsTried.Keys | Sort-Object -Property @{ Expression = { $s.AccountsTried[$_] }; Descending = $true }, @{ Expression = { $_ } } | Select-Object -First 5) -join ", "
                $indicators.Add("**Brute force:** $($s.Failed) failed logons from $(Format-Cell $s.IpAddress)$(if ($s.External) { ' (public address)' }) between $($s.FirstFailure) and $($s.LastFailure); accounts tried: $(Format-Cell $accounts)")
            }
            if ($s.FirstSuccessAfterFailure -and $s.Failed -ge $FailedLogonThreshold) {
                $indicators.Add("**Brute force succeeded:** logon as $(Format-Cell $s.FirstSuccessAfterFailure.User) from $(Format-Cell $s.IpAddress) at $($s.FirstSuccessAfterFailure.Timestamp)")
            }
        }
        foreach ($n in $a.NotableEvents) {
            switch ($n.EventID) {
                1102 { $indicators.Add("**Anti-forensics:** $(Format-Cell $n.Description) at $($n.Timestamp)") }
                104 { $indicators.Add("**Anti-forensics:** $(Format-Cell $n.Description) at $($n.Timestamp)") }
                7045 { $indicators.Add("**New service:** $(Format-Cell $n.Description 200) at $($n.Timestamp)") }
                7040 { $indicators.Add("**Service change:** $(Format-Cell $n.Description) at $($n.Timestamp)") }
                4720 { $indicators.Add("**Account created:** $(Format-Cell $n.Description) at $($n.Timestamp)") }
                4732 { $indicators.Add("**Group change:** $(Format-Cell $n.Description) at $($n.Timestamp)") }
                4688 {
                    $dc = Get-Prop $n.Details "DecodedCommand"
                    if ($dc -or (Get-Prop $n.Details "CommandLine") -match '(?i)-enc|hidden|downloadstring') {
                        $indicators.Add("**Suspicious process:** $(Format-Cell $n.Description) at $($n.Timestamp)$(if ($dc) { "; decoded command: $(Format-Cell $dc 150)" })")
                    }
                }
            }
        }
    }
    if ($reg) {
        foreach ($s in $reg.StartupEntries) {
            if ($s.Flags) { $indicators.Add("**Autostart:** '$(Format-Cell $s.Name)' in $(Format-Cell $s.Location) ($($s.Flags -join ', '))$(if ($s.Contains('DecodedCommand')) { "; decoded: $(Format-Cell $s.DecodedCommand 150)" })") }
        }
        foreach ($s in $reg.FlaggedServices) { $indicators.Add("**Service in registry:** $(Format-Cell $s.Name) -> $(Format-Cell $s.ImagePath) ($($s.Flags -join ', '))") }
        foreach ($s in $reg.DisabledSecurityServices) { $indicators.Add("**Security service disabled:** $(Format-Cell $s.Name) ($(Format-Cell $s.DisplayName)), key written $($s.LastWritten)") }
        foreach ($x in $reg.DefenderExclusions) { $indicators.Add("**Defender exclusion ($($x.Kind)):** $(Format-Cell $x.Value), written $($x.LastWritten)") }
        foreach ($r in $reg.RemoteAccessSoftware) { $indicators.Add("**Remote access tool:** $(Format-Cell $r.Name) $(Format-Cell $r.Version) installed $(Format-Cell $r.InstallDate) at $(Format-Cell $r.InstallLocation)") }
        foreach ($v in $reg.InterestingValues) { $indicators.Add("**Stored secret:** value '$(Format-Cell $v.Name)' in $(Format-Cell $v.Key) (shown masked: $(Format-Cell $v.Data))") }
    }
    if ($indicators.Count -eq 0) { $null = $sb.AppendLine("No indicators found by the summary rules.") }
    foreach ($i in $indicators) { $null = $sb.AppendLine("- $i") }
    $null = $sb.AppendLine()

    $null = $sb.AppendLine("## Timeline")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("Up to 40 of $($script:Timeline.EntryCount) entries, starting just before the first suspicious one. The full list is in forensic_timeline.json.")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("| Time (UTC) | Source | Description |")
    $null = $sb.AppendLine("| --- | --- | --- |")
    $tl = @($script:Timeline.Entries)
    # Lead with what matters: the suspicious window, then context.
    $firstSuspicious = $tl | Where-Object { $_.Category -ne "event" -or $_.EventID -in 1102, 104, 4720, 4732, 7045, 7040, 4688, 4648 } | Select-Object -First 1
    $startAt = 0
    if ($firstSuspicious) { $startAt = [Math]::Max(0, [Array]::IndexOf($tl, $firstSuspicious) - 5) }
    foreach ($t in $tl | Select-Object -Skip $startAt -First 40) {
        $null = $sb.AppendLine("| $($t.Timestamp) | $(Format-Cell $t.Source) | $(Format-Cell $t.Description 160) |")
    }
    $null = $sb.AppendLine()

    $null = $sb.AppendLine("## Recommendations")
    $null = $sb.AppendLine()
    $recs = [System.Collections.Generic.List[string]]::new()
    $text = $indicators -join "`n"
    if ($text -match 'Brute force') { $recs.Add("Block the attacking addresses at the firewall, enforce account lockout, and do not expose SMB/RDP to the internet.") }
    if ($text -match 'succeeded') { $recs.Add("Treat the compromised account as owned: reset its password, review everything done in its logon session, and check other machines for the same credentials.") }
    if ($text -match 'Account created|Group change') { $recs.Add("Disable and investigate accounts created or added to Administrators during the incident.") }
    if ($text -match 'New service|Service in registry|Autostart') { $recs.Add("Collect and hash the binaries behind the flagged services and autostart entries, then remove the persistence after evidence is preserved.") }
    if ($text -match 'Security service disabled|Defender exclusion') { $recs.Add("Re-enable Microsoft Defender, remove the exclusions, and run a full offline scan.") }
    if ($text -match 'Anti-forensics') { $recs.Add("The log was cleared: recover older events from a log forwarder/SIEM, shadow copies or backups, and enable log forwarding if it is missing.") }
    if ($text -match 'Remote access tool') { $recs.Add("Uninstall unapproved remote access tools and check their own logs for sessions.") }
    if ($text -match 'Stored secret') { $recs.Add("Remove plaintext credentials from the registry (for example Winlogon DefaultPassword) and rotate those passwords.") }
    $recs.Add("Keep the original evidence files read-only and re-check their SHA-256 values above before sharing results.")
    foreach ($r in $recs) { $null = $sb.AppendLine("- $r") }

    $sb.ToString() | Set-Content -Path (Join-Path $OutputPath "forensic_report.md") -Encoding utf8NoBOM
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
if (-not (Test-Path -Path $DataPath -PathType Container)) {
    Write-Host "Error: data folder '$DataPath' does not exist. Pass -DataPath <folder with event-logs/ and registry-hives/>." -ForegroundColor Red
    exit 2
}
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
Write-Host "=== Windows Forensics Automation ===" -ForegroundColor Green

try {
    Analyze-EventLogs -LogPath (Join-Path $DataPath "event-logs")
    Analyze-RegistryData -RegistryPath (Join-Path $DataPath "registry-hives")
    Generate-Timeline
    Create-ForensicReport
    if ($script:Processed.Count -eq 0) {
        Write-Warning "No extracted JSON found. Run extract_eventlogs.py and extract_registry.py first."
    }
    Write-Host "Analysis complete. Check $OutputPath for results." -ForegroundColor Green
} catch {
    Write-Host "Error: $($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))" -ForegroundColor Red
    exit 1
}
