[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$OpenSslRoot,
    [string]$OpenSslBin,
    [string]$OpenSslCryptoLibrary,
    [string]$OpenSslConfig,
    [string]$OpenSslModules,
    [string]$BuildDirectory,
    [ValidateSet('Release', 'Debug')][string]$Configuration = 'Release',
    [switch]$MldsaOnly
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
if (-not $BuildDirectory) { $BuildDirectory = Join-Path $repoRoot 'out/windows-tests' }
$BuildDirectory = [IO.Path]::GetFullPath($BuildDirectory)
$OpenSslRoot = (Resolve-Path -LiteralPath $OpenSslRoot).Path
if (-not $OpenSslBin) { $OpenSslBin = Join-Path $OpenSslRoot 'bin' }
$OpenSslBin = (Resolve-Path -LiteralPath $OpenSslBin).Path
$openssl = Join-Path $OpenSslBin 'openssl.exe'
if (-not (Test-Path -LiteralPath $openssl)) { throw "Missing $openssl" }
if (-not (Test-Path -LiteralPath (Join-Path $OpenSslRoot 'include/openssl/evp.h'))) {
    throw 'OpenSslRoot must contain include/openssl and the matching x64 libraries.'
}
$cmake = (Get-Command cmake -ErrorAction Stop).Source
$ctest = (Get-Command ctest -ErrorAction Stop).Source
New-Item -ItemType Directory -Force -Path $BuildDirectory | Out-Null
$log = Join-Path $BuildDirectory ("test-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
$savedPath = $env:PATH
$savedConfig = $env:OPENSSL_CONF
$savedModules = $env:OPENSSL_MODULES
$transcriptStarted = $false
$exitCode = 0
function Invoke-Checked([string]$Program, [string[]]$Arguments) {
    Write-Host ("`n> {0} {1}" -f $Program, ($Arguments -join ' '))
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Program failed with exit code $LASTEXITCODE" }
}
try {
    Start-Transcript -Path $log | Out-Null
    $transcriptStarted = $true
    $env:PATH = "$OpenSslBin;$OpenSslRoot;$savedPath"
    if ($OpenSslConfig) { $env:OPENSSL_CONF = (Resolve-Path -LiteralPath $OpenSslConfig).Path }
    if ($OpenSslModules) { $env:OPENSSL_MODULES = (Resolve-Path -LiteralPath $OpenSslModules).Path }
    Write-Host "Source: $repoRoot"
    Write-Host "Build: $BuildDirectory"
    Write-Host "OPENSSL_CONF: $env:OPENSSL_CONF"
    Write-Host "OPENSSL_MODULES: $env:OPENSSL_MODULES"
    Invoke-Checked $openssl @('version', '-a')
    Invoke-Checked $openssl @('list', '-providers')
    Invoke-Checked $openssl @('list', '-signature-algorithms')
    # Native ML-DSA in OpenSSL 3.5 is sufficient. Optional oqsprovider configuration
    # is inherited (or selected above) and is also applied to the test processes.
    $configure = @('-S', $repoRoot, '-B', $BuildDirectory, '-G', 'Visual Studio 17 2022',
        '-A', 'x64', "-DOPENSSL_ROOT_DIR=$OpenSslRoot", '-DOPENSSL_USE_STATIC_LIBS=FALSE')
    if ($OpenSslCryptoLibrary) {
        $cryptoLib = (Resolve-Path -LiteralPath $OpenSslCryptoLibrary).Path
        $configure += "-DOPENSSL_CRYPTO_LIBRARY=$cryptoLib"
    }
    # Clear cached OpenSSL discovery when changing installations between runs.
    Invoke-Checked $cmake (@('-U', '*OPENSSL*') + $configure)
    Invoke-Checked $cmake @('--build', $BuildDirectory, '--config', $Configuration, '--parallel')
    $testArgs = @('--test-dir', $BuildDirectory, '-C', $Configuration, '--verbose', '--no-tests=error')
    if ($MldsaOnly) { $testArgs += @('-R', '^mldsa$') }
    Invoke-Checked $ctest $testArgs
    Write-Host "`nPASS: requested tests completed. Report: $log"
} catch {
    $exitCode = 1
    Write-Host "`nFAIL: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Report: $log"
} finally {
    $env:PATH = $savedPath
    $env:OPENSSL_CONF = $savedConfig
    $env:OPENSSL_MODULES = $savedModules
    if ($transcriptStarted) { Stop-Transcript | Out-Null }
}
exit $exitCode
