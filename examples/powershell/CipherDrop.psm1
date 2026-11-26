#Requires -Version 7.2
<#
.SYNOPSIS
    CipherDrop protocol v1 client for PowerShell 7 (.NET 8+).

.DESCRIPTION
    Encrypts locally with System.Security.Cryptography.AesGcm and uploads only
    ciphertext. The key is placed in the URL fragment (#v1.<key>) and never sent.

    Password-protected shares require Argon2id, which .NET does not provide.
    This module therefore creates only password-less shares and refuses to
    decrypt password-protected ones (use the CLI, the Python client or an SDK).

.EXAMPLE
    Import-Module ./CipherDrop.psm1
    $share = New-CipherDropSecret -Server https://paste.example.com -Secret (Read-Host -AsSecureString) -TtlSeconds 3600 -MaxReads 1
    $share.Url
    Get-CipherDropSecret -Link $share.Url
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:AadNone = 'cipherdrop/v1;alg=AES-256-GCM;kdf=none'

function ConvertTo-CdBase64Url([byte[]] $Bytes) {
    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function ConvertFrom-CdBase64Url([string] $Text, [int] $ExpectedLength = -1) {
    if ($Text -notmatch '^[A-Za-z0-9_-]*$' -or ($Text.Length % 4) -eq 1) { throw 'Malformed base64url' }
    $s = $Text.Replace('-', '+').Replace('_', '/')
    $s += '=' * ((4 - $s.Length % 4) % 4)
    $bytes = [Convert]::FromBase64String($s)
    if ((ConvertTo-CdBase64Url $bytes) -cne $Text) { throw 'Non-canonical base64url' }
    if ($ExpectedLength -ge 0 -and $bytes.Length -ne $ExpectedLength) { throw 'Wrong length' }
    , $bytes
}

function Protect-CdPayload {
    <# Encrypts plaintext bytes. -Nonce is for test vectors only. #>
    param([byte[]] $Key, [byte[]] $Plaintext, [byte[]] $Nonce)
    if ($Key.Length -ne 32) { throw 'Key must be 32 bytes' }
    if (-not $Nonce) { $Nonce = [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(12) }
    $aad = [Text.Encoding]::ASCII.GetBytes($script:AadNone)
    $ct = [byte[]]::new($Plaintext.Length)
    $tag = [byte[]]::new(16)
    $gcm = [System.Security.Cryptography.AesGcm]::new($Key, 16)
    try { $gcm.Encrypt($Nonce, $Plaintext, $ct, $tag, $aad) } finally { $gcm.Dispose() }
    [ordered]@{
        version    = 1
        algorithm  = 'AES-256-GCM'
        nonce      = ConvertTo-CdBase64Url $Nonce
        ciphertext = ConvertTo-CdBase64Url ([byte[]]($ct + $tag))
    }
}

function Unprotect-CdEnvelope {
    param([byte[]] $Key, $Envelope)
    if ($Envelope.version -ne 1 -or $Envelope.algorithm -cne 'AES-256-GCM') { throw 'Unsupported envelope' }
    if ($Envelope.PSObject.Properties.Name -contains 'kdf' -and $null -ne $Envelope.kdf) {
        throw 'This share is password protected (Argon2id). Use the cipherdrop CLI, the Python client or an SDK.'
    }
    $nonce = ConvertFrom-CdBase64Url $Envelope.nonce 12
    $data = ConvertFrom-CdBase64Url $Envelope.ciphertext
    if ($data.Length -lt 16) { throw 'Ciphertext too short' }
    $ct = [byte[]]$data[0..($data.Length - 17)]
    if ($data.Length -eq 16) { $ct = [byte[]]::new(0) }
    $tag = [byte[]]$data[($data.Length - 16)..($data.Length - 1)]
    $pt = [byte[]]::new($ct.Length)
    $aad = [Text.Encoding]::ASCII.GetBytes($script:AadNone)
    $gcm = [System.Security.Cryptography.AesGcm]::new($Key, 16)
    try { $gcm.Decrypt($nonce, $ct, $tag, $pt, $aad) }
    catch [System.Security.Cryptography.AuthenticationTagMismatchException] {
        throw 'Decryption failed: wrong key or modified data'
    }
    finally { $gcm.Dispose() }
    , $pt
}

function ConvertFrom-CdSecure([securestring] $s) {
    [System.Net.NetworkCredential]::new('', $s).Password
}

function Invoke-CdApi {
    param([string] $Method, [string] $Uri, $Body, [securestring] $ApiKey, [hashtable] $Headers = @{})
    $h = @{ Accept = 'application/json' } + $Headers
    if ($ApiKey) { $h.Authorization = 'Bearer ' + (ConvertFrom-CdSecure $ApiKey) }
    $params = @{ Method = $Method; Uri = $Uri; Headers = $h; MaximumRedirection = 0 }
    if ($null -ne $Body) {
        $params.Body = ($Body | ConvertTo-Json -Compress -Depth 5)
        $params.ContentType = 'application/json'
    }
    # Invoke-RestMethod validates TLS certificates by default; never pass -SkipCertificateCheck.
    Invoke-RestMethod @params
}

function Assert-CdServer([string] $Server, [switch] $AllowInsecureHttp) {
    if (-not ($Server.StartsWith('https://') -or ($AllowInsecureHttp -and $Server.StartsWith('http://')))) {
        throw 'Refusing non-HTTPS server URL (use -AllowInsecureHttp only for local testing)'
    }
    $Server.TrimEnd('/')
}

function New-CipherDropSecret {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Server,
        [Parameter(Mandatory)] [securestring] $Secret,
        [string] $Title,
        [int] $TtlSeconds,
        [int] $MaxReads,
        [securestring] $ApiKey,
        [switch] $AllowInsecureHttp
    )
    $base = Assert-CdServer $Server -AllowInsecureHttp:$AllowInsecureHttp
    $payload = [ordered]@{ content = (ConvertFrom-CdSecure $Secret) }
    if ($Title) { $payload.title = $Title }
    $json = [Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json -Compress))
    $padded = [byte[]]::new([Math]::Ceiling($json.Length / 256) * 256)
    [Array]::Fill($padded, [byte]0x20)
    [Array]::Copy($json, $padded, $json.Length)
    $key = [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
    try {
        $body = Protect-CdPayload -Key $key -Plaintext $padded
        if ($TtlSeconds) { $body.ttl_seconds = $TtlSeconds }
        if ($MaxReads) { $body.max_reads = $MaxReads }
        $r = Invoke-CdApi -Method Post -Uri "$base/api/v1/shares" -Body $body -ApiKey $ApiKey
        [pscustomobject]@{
            Url             = "$($r.url)#v1.$(ConvertTo-CdBase64Url $key)"
            Id              = $r.id
            ExpiresAt       = $r.expires_at
            MaxReads        = $r.max_reads
            RevocationUrl   = $r.revocation_url
        }
    }
    finally {
        [Array]::Clear($key); [Array]::Clear($json); [Array]::Clear($padded)
    }
}

function Get-CipherDropSecret {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Link,
        [securestring] $ApiKey,
        [switch] $AllowInsecureHttp
    )
    if ($Link -notmatch '^(https?://.+)/s/([A-Za-z0-9_-]{22})#v1\.([A-Za-z0-9_-]{43})$') { throw 'Malformed share link' }
    $base = Assert-CdServer $Matches[1] -AllowInsecureHttp:$AllowInsecureHttp
    $id = $Matches[2]
    $key = ConvertFrom-CdBase64Url $Matches[3] 32
    try {
        # Consume exactly once; never retried.
        $env = Invoke-CdApi -Method Post -Uri "$base/api/v1/shares/$id/consume" -Body @{} -ApiKey $ApiKey
        $pt = Unprotect-CdEnvelope -Key $key -Envelope $env
        ([Text.Encoding]::UTF8.GetString($pt) | ConvertFrom-Json).content
    }
    finally { [Array]::Clear($key) }
}

Export-ModuleMember -Function New-CipherDropSecret, Get-CipherDropSecret, Protect-CdPayload, Unprotect-CdEnvelope, ConvertTo-CdBase64Url, ConvertFrom-CdBase64Url
