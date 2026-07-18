$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$Assets = Join-Path $Root "assets"
$Output = Join-Path $Assets "Filter-1.txt"
$Sources = @(
    @{ Name = "Filter-2.txt"; Description = "Manual DNS allow/block rules" },
    @{ Name = "Filter-3.txt"; Description = "Karakeep generated allowlist candidates" },
    @{ Name = "Filter-4.txt"; Description = "Browser add-on rules" }
)

$Lines = [System.Collections.Generic.List[string]]::new()
$Lines.Add("! Title: Sick Prodigy Compiled AdGuard List")
$Lines.Add("! Expires: 1 day (update frequency)")
$Lines.Add("! Description: Compiled from Filter-2.txt, Filter-3.txt, and Filter-4.txt.")
$Lines.Add("! Homepage: https://gitea.rcs1.xyz/sickprodigy/adguard-list")
$Lines.Add("! License: https://gitea.rcs1.xyz/sickprodigy/adguard-list/raw/branch/main/LICENSE")
$Lines.Add("! Last modified: $((Get-Date).ToString('MM/dd/yyyy'))")
$Lines.Add("! Version: generated")
$Lines.Add("!")
$Lines.Add("! Source files:")
foreach ($Source in $Sources) {
    $Lines.Add("! - $($Source.Name): $($Source.Description)")
}

foreach ($Source in $Sources) {
    $Path = Join-Path $Assets $Source.Name
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Missing source filter: $Path"
    }

    $Lines.Add("")
    $Lines.Add("! =============================================================================")
    $Lines.Add("! Begin $($Source.Name): $($Source.Description)")
    $Lines.Add("! =============================================================================")
    foreach ($Line in Get-Content -LiteralPath $Path) {
        $Lines.Add($Line)
    }
    $Lines.Add("")
    $Lines.Add("! End $($Source.Name)")
}

[System.IO.File]::WriteAllText($Output, (($Lines -join "`n") + "`n"), [System.Text.UTF8Encoding]::new($false))
Write-Host "Wrote assets/Filter-1.txt"

