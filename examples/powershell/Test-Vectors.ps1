#Requires -Version 7.2
# Verifies the PowerShell module against the shared protocol test vectors
# (password-less vectors only; .NET has no built-in Argon2id).
# Optionally runs a live round-trip when $env:CIPHERDROP_TEST_SERVER is set.

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'CipherDrop.psm1') -Force

$doc = Get-Content (Join-Path $PSScriptRoot '../../crates/protocol/testdata/vectors.json') -Raw | ConvertFrom-Json
foreach ($v in $doc.vectors) {
    if ($null -ne $v.password) { Write-Host "skip valid    $($v.name) (requires Argon2id)"; continue }
    $key = ConvertFrom-CdBase64Url $v.key 32
    $pt = Unprotect-CdEnvelope -Key $key -Envelope $v.envelope
    if ([Text.Encoding]::UTF8.GetString($pt) -cne $v.plaintext) { throw "$($v.name): plaintext mismatch" }
    $again = Protect-CdPayload -Key $key -Plaintext ([Text.Encoding]::UTF8.GetBytes($v.plaintext)) -Nonce (ConvertFrom-CdBase64Url $v.envelope.nonce 12)
    if ($again.ciphertext -cne $v.envelope.ciphertext) { throw "$($v.name): re-encryption mismatch" }
    Write-Host "ok   valid    $($v.name)"
}
foreach ($v in $doc.invalid) {
    $failed = $false
    try { $null = Unprotect-CdEnvelope -Key (ConvertFrom-CdBase64Url $v.key 32) -Envelope $v.envelope } catch { $failed = $true }
    if (-not $failed) { throw "$($v.name): expected failure" }
    Write-Host "ok   invalid  $($v.name)"
}

if ($env:CIPHERDROP_TEST_SERVER) {
    $secret = ConvertTo-SecureString 'powershell synthetic secret' -AsPlainText -Force
    $share = New-CipherDropSecret -Server $env:CIPHERDROP_TEST_SERVER -Secret $secret -TtlSeconds 600 -MaxReads 1 -AllowInsecureHttp
    $text = Get-CipherDropSecret -Link $share.Url -AllowInsecureHttp
    if ($text -cne 'powershell synthetic secret') { throw 'live round-trip failed' }
    Write-Host "ok   live     round-trip against $($env:CIPHERDROP_TEST_SERVER)"
}
