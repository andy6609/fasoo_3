[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Enable', 'Disable', 'Status')]
    [string]$Action
)

$ErrorActionPreference = 'Stop'

$internetSettingsPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$backupPath = 'HKCU:\Software\LocalDLPProxy\WinINetBackup'
$pacUrl = 'http://127.0.0.1:8000/proxy.pac?v=3'
$managedValueNames = @('ProxyEnable', 'ProxyServer', 'ProxyOverride', 'AutoConfigURL', 'AutoDetect')

function Notify-WinInet {
    $signature = @'
[DllImport("wininet.dll", SetLastError=true)]
public static extern bool InternetSetOption(
    IntPtr hInternet,
    int dwOption,
    IntPtr lpBuffer,
    int dwBufferLength
);
'@

    if (-not ('LocalDLP.WinInetNativeMethods' -as [type])) {
        Add-Type -MemberDefinition $signature -Name WinInetNativeMethods -Namespace LocalDLP
    }

    [LocalDLP.WinInetNativeMethods]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null
    [LocalDLP.WinInetNativeMethods]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null
}

function Get-RegistryValueState {
    param([string]$Name)

    $key = Get-Item -LiteralPath $internetSettingsPath
    $exists = $key.GetValueNames() -contains $Name
    [pscustomobject]@{
        Exists = $exists
        Value = if ($exists) { $key.GetValue($Name, $null, 'DoNotExpandEnvironmentNames') } else { $null }
        Kind = if ($exists) { $key.GetValueKind($Name).ToString() } else { $null }
    }
}

function Save-OriginalSettings {
    if (Test-Path -LiteralPath $backupPath) {
        $existingVersion = Get-ItemPropertyValue -LiteralPath $backupPath -Name BackupVersion -ErrorAction SilentlyContinue
        if ($existingVersion -eq 1) {
            return
        }
    }

    New-Item -Path $backupPath -Force | Out-Null
    New-ItemProperty -LiteralPath $backupPath -Name BackupVersion -PropertyType DWord -Value 1 -Force | Out-Null

    foreach ($name in $managedValueNames) {
        $state = Get-RegistryValueState -Name $name
        New-ItemProperty -LiteralPath $backupPath -Name "${name}Exists" -PropertyType DWord -Value ([int]$state.Exists) -Force | Out-Null
        if ($state.Exists) {
            New-ItemProperty -LiteralPath $backupPath -Name $name -PropertyType $state.Kind -Value $state.Value -Force | Out-Null
        }
    }
}

function Restore-OriginalSettings {
    if (-not (Test-Path -LiteralPath $backupPath)) {
        $currentPacUrl = Get-ItemPropertyValue -LiteralPath $internetSettingsPath -Name AutoConfigURL -ErrorAction SilentlyContinue
        $currentProxyEnable = Get-ItemPropertyValue -LiteralPath $internetSettingsPath -Name ProxyEnable -ErrorAction SilentlyContinue
        $currentProxyServer = Get-ItemPropertyValue -LiteralPath $internetSettingsPath -Name ProxyServer -ErrorAction SilentlyContinue
        if ($currentPacUrl -like 'http://127.0.0.1:8000/proxy.pac*') {
            Remove-ItemProperty -LiteralPath $internetSettingsPath -Name AutoConfigURL -ErrorAction SilentlyContinue
        }
        if ($currentProxyEnable -eq 1 -and $currentProxyServer -eq '127.0.0.1:8000') {
            Set-ItemProperty -LiteralPath $internetSettingsPath -Name ProxyEnable -Type DWord -Value 0
            Remove-ItemProperty -LiteralPath $internetSettingsPath -Name ProxyServer -ErrorAction SilentlyContinue
            Remove-ItemProperty -LiteralPath $internetSettingsPath -Name ProxyOverride -ErrorAction SilentlyContinue
        }
        return
    }

    foreach ($name in $managedValueNames) {
        $existed = Get-ItemPropertyValue -LiteralPath $backupPath -Name "${name}Exists" -ErrorAction SilentlyContinue
        if ($existed -eq 1) {
            $backupKey = Get-Item -LiteralPath $backupPath
            $value = $backupKey.GetValue($name, $null, 'DoNotExpandEnvironmentNames')
            $kind = $backupKey.GetValueKind($name).ToString()
            New-ItemProperty -LiteralPath $internetSettingsPath -Name $name -PropertyType $kind -Value $value -Force | Out-Null
        }
        else {
            Remove-ItemProperty -LiteralPath $internetSettingsPath -Name $name -ErrorAction SilentlyContinue
        }
    }

    Remove-Item -LiteralPath $backupPath -Recurse -Force
}

function Test-PacEndpoint {
    $client = New-Object System.Net.WebClient
    try {
        $client.Proxy = [System.Net.GlobalProxySelection]::GetEmptyWebProxy()
        $content = $client.DownloadString($pacUrl)
        if ($content -notmatch 'FindProxyForURL' -or $content -notmatch 'return\s+"DIRECT"') {
            throw 'The local endpoint did not return the expected AI-only PAC file.'
        }
    }
    finally {
        $client.Dispose()
    }
}

function Show-Status {
    $settings = Get-ItemProperty -LiteralPath $internetSettingsPath
    [pscustomobject]@{
        ProxyEnable = $settings.ProxyEnable
        ProxyServer = $settings.ProxyServer
        ProxyOverride = $settings.ProxyOverride
        AutoConfigURL = $settings.AutoConfigURL
        AutoDetect = $settings.AutoDetect
        Mode = if ($settings.ProxyEnable -eq 0 -and $settings.AutoConfigURL -like 'http://127.0.0.1:8000/proxy.pac*') {
            'AI-only PAC: supported AI domains use the proxy; Outlook and all other traffic are DIRECT.'
        }
        elseif ($settings.ProxyEnable -eq 1 -and $settings.ProxyServer -eq '127.0.0.1:8000') {
            'Unsafe global proxy: all WinINet applications, including Outlook, use the proxy.'
        }
        else {
            'Local DLP proxy routing is disabled or another proxy configuration is active.'
        }
    } | Format-List
}

switch ($Action) {
    'Enable' {
        Test-PacEndpoint
        Save-OriginalSettings

        Set-ItemProperty -LiteralPath $internetSettingsPath -Name ProxyEnable -Type DWord -Value 0
        Remove-ItemProperty -LiteralPath $internetSettingsPath -Name ProxyServer -ErrorAction SilentlyContinue
        Remove-ItemProperty -LiteralPath $internetSettingsPath -Name ProxyOverride -ErrorAction SilentlyContinue
        New-ItemProperty -LiteralPath $internetSettingsPath -Name AutoConfigURL -PropertyType String -Value $pacUrl -Force | Out-Null
        New-ItemProperty -LiteralPath $internetSettingsPath -Name AutoDetect -PropertyType DWord -Value 0 -Force | Out-Null
        Notify-WinInet

        Write-Host '[SUCCESS] AI-only proxy routing is enabled.' -ForegroundColor Green
        Write-Host '          ChatGPT, Gemini, and Claude -> 127.0.0.1:8000'
        Write-Host '          Outlook, Microsoft 365, and all other traffic -> DIRECT'
        Show-Status
    }
    'Disable' {
        Restore-OriginalSettings
        Notify-WinInet
        Write-Host '[SUCCESS] The original Windows proxy settings were restored.' -ForegroundColor Green
        Show-Status
    }
    'Status' {
        Show-Status
    }
}
