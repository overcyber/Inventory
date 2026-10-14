param(
    [Parameter(Mandatory=$true)]
    [string]$CaFile,
    [ValidateSet("CurrentUser","LocalMachine")]
    [string]$Scope = "CurrentUser"
)

$ErrorActionPreference = "Stop"
$resolved = (Resolve-Path $CaFile).Path
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($resolved)

$bc = $cert.Extensions | Where-Object {
    $_.Oid.Value -eq "2.5.29.19"
}
if (-not $bc -or -not ($bc.Format($false) -match "CA=True|CA:TRUE")) {
    throw "O arquivo informado não é uma CA X.509."
}

if ($Scope -eq "LocalMachine") {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
    if (-not $isAdmin) {
        throw "Abra o PowerShell como Administrador para usar -Scope LocalMachine."
    }
    $store = "Cert:\LocalMachine\Root"
} else {
    $store = "Cert:\CurrentUser\Root"
}

Write-Host "[TLS] Instalando Inventory Local CA em $store ..."
Import-Certificate -FilePath $resolved -CertStoreLocation $store | Out-Null
Write-Host "[TLS] Instalado. Feche completamente e reabra Chrome/Edge/Firefox."
Write-Host ("SHA256: " + $cert.GetCertHashString([System.Security.Cryptography.HashAlgorithmName]::SHA256))
