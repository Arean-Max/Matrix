param([string]$Out = (Join-Path $env:TEMP "eh-hwtest.log"))

$env:EH_HW_TEST = "1"
Set-Location (Join-Path $PSScriptRoot "..")
go test ./internal/attestation -run TestHardwareAttestation -v *> $Out
Write-Host "log written to $Out"
