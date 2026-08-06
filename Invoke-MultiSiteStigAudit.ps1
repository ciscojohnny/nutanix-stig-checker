#Requires -Version 7.0
# Forwarding wrapper — use Invoke-StigAudit.ps1
& (Join-Path $PSScriptRoot 'Invoke-StigAudit.ps1') @args
