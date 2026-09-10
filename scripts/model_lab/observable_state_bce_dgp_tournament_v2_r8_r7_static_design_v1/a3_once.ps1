$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$LauncherSourceIdentity = 'a3_once.ps1'

$OneShotPrefix = 'C:\Users\minsu\Documents\EPS\build\pc_r8r7_a3_freeze_actual_once_20260822'
$OutputsRoot = 'C:\Users\minsu\Documents\EPS\PE_Regime_Engine_v0.4.0_Bottleneck_Overlay\outputs'
$FinalName = 'model_zoo_observable_state_bce_dgp_tournament_v2_r8_r7_static_design_source_freeze_v1_a3_no_go_20260822'
$StagingName = ".$FinalName.stg"
$FailureName = ".$FinalName.fail"
$FailureStagingName = ".$FinalName.fstg"
$PinnedPython = 'C:\Users\minsu\Documents\EPS\.venv_pe_model_lab_py310\Scripts\python.exe'
$PinnedPythonHash = '2de63ce9ee584123173a0c96e68b54be74f7ad17c21a343e63ac12a4790cb21d'
$PinnedRuff = 'C:\Users\minsu\anaconda3\Scripts\ruff.exe'
$PinnedRuffHash = '3e6622f4ca670a20eacb5a2e9f25b9511b255f6153582252ee1838a6c29beb5f'
$Builder = 'C:\Users\minsu\Documents\EPS\PE_Regime_Engine_v0.4.0_Bottleneck_Overlay\scripts\model_lab\observable_state_bce_dgp_tournament_v2_r8_r7_static_design_v1\freeze_static_design.py'
$BuilderHash = '9aea031765dc367d658cea8fa18b3db7bfbd3ef14841314bca6905654570a10f'
$QuoteFreeBootstrap = 'import base64,sys;exec(base64.b64decode(sys.argv[1]))'
$InvocationSourceBase64 = 'aW1wb3J0IHJ1bnB5LHN5cwpwcm9qZWN0PXInQzpcVXNlcnNcbWluc3VcRG9jdW1lbnRzXEVQU1xQRV9SZWdpbWVfRW5naW5lX3YwLjQuMF9Cb3R0bGVuZWNrX092ZXJsYXknCnNjcmlwdD1yJ0M6XFVzZXJzXG1pbnN1XERvY3VtZW50c1xFUFNcUEVfUmVnaW1lX0VuZ2luZV92MC40LjBfQm90dGxlbmVja19PdmVybGF5XHNjcmlwdHNcbW9kZWxfbGFiXG9ic2VydmFibGVfc3RhdGVfYmNlX2RncF90b3VybmFtZW50X3YyX3I4X3I3X3N0YXRpY19kZXNpZ25fdjFcZnJlZXplX3N0YXRpY19kZXNpZ24ucHknCnN5cy5wYXRoLmluc2VydCgwLHByb2plY3QpCnN5cy5hcmd2PVtzY3JpcHQsJy0tZnJlZXplLXI4LXI3LXN0YXRpYy1kZXNpZ24tc291cmNlLW5vLXNpZ25lci1uby1waGFzZTItbm8tZnJlc2gnXQpydW5weS5ydW5fcGF0aChzY3JpcHQscnVuX25hbWU9J19fbWFpbl9fJykK'

function Assert-A3OutputIdentitiesAbsent {
    $Collisions = @(
        Get-ChildItem -LiteralPath $OutputsRoot -Force -ErrorAction Stop |
            Where-Object {
                [StringComparer]::OrdinalIgnoreCase.Equals($_.Name, $FinalName) -or
                [StringComparer]::OrdinalIgnoreCase.Equals($_.Name, $StagingName) -or
                [StringComparer]::OrdinalIgnoreCase.Equals($_.Name, $FailureName) -or
                [StringComparer]::OrdinalIgnoreCase.Equals($_.Name, $FailureStagingName)
            }
    )
    if ($Collisions.Count -ne 0) {
        throw 'An a3 final/staging/failure identity already exists.'
    }
}

Assert-A3OutputIdentitiesAbsent
if (
    (Test-Path -LiteralPath $OneShotPrefix) -or
    [IO.File]::Exists($OneShotPrefix) -or
    [IO.Directory]::Exists($OneShotPrefix)
) {
    throw 'The a3 one-shot prefix was already consumed; builder launch count is zero.'
}

$CreatedPrefix = New-Item -ItemType Directory -Path $OneShotPrefix -ErrorAction Stop
if (
    -not $CreatedPrefix.PSIsContainer -or
    $CreatedPrefix.FullName -cne $OneShotPrefix -or
    (($CreatedPrefix.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
    @(Get-ChildItem -LiteralPath $OneShotPrefix -Force -ErrorAction Stop).Count -ne 0
) {
    throw 'The atomically created a3 one-shot prefix is not exact, empty, and reparse-free.'
}

$PythonItem = Get-Item -LiteralPath $PinnedPython -Force -ErrorAction Stop
$RuffItem = Get-Item -LiteralPath $PinnedRuff -Force -ErrorAction Stop
$BuilderItem = Get-Item -LiteralPath $Builder -Force -ErrorAction Stop
if (
    $PythonItem.PSIsContainer -or $RuffItem.PSIsContainer -or $BuilderItem.PSIsContainer -or
    (($PythonItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
    (($RuffItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
    (($BuilderItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
    (Get-FileHash -LiteralPath $PinnedPython -Algorithm SHA256).Hash.ToLowerInvariant() -cne $PinnedPythonHash -or
    (Get-FileHash -LiteralPath $PinnedRuff -Algorithm SHA256).Hash.ToLowerInvariant() -cne $PinnedRuffHash -or
    (Get-FileHash -LiteralPath $Builder -Algorithm SHA256).Hash.ToLowerInvariant() -cne $BuilderHash
) {
    throw 'A pinned a3 launcher tool or builder source identity drifted.'
}

Assert-A3OutputIdentitiesAbsent
if (@(Get-ChildItem -LiteralPath $OneShotPrefix -Force -ErrorAction Stop).Count -ne 0) {
    throw 'The a3 one-shot prefix changed before dispatch.'
}

$env:PYTHONHOME = $null
$env:PYTHONSTARTUP = $null
$env:PYTHONINSPECT = $null
$env:PYTHONWARNINGS = $null
$env:PYTEST_ADDOPTS = $null
$env:PYTEST_PLUGINS = $null
$env:PYTHONDONTWRITEBYTECODE = '1'
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD = '1'
$env:PYTHONNOUSERSITE = '1'
$env:PYTHONPATH = ''
$env:PYTHONPYCACHEPREFIX = $OneShotPrefix

$childArgs = [string[]]@(
    '-I',
    '-B',
    '-X',
    "pycache_prefix=$OneShotPrefix",
    '-c',
    $QuoteFreeBootstrap,
    $InvocationSourceBase64
)
$BuilderSourceLaunchCount = 0
$BuilderSourceLaunchCount += 1
if ($BuilderSourceLaunchCount -ne 1) {
    throw 'The a3 launcher source dispatch count drifted.'
}
& $PinnedPython @childArgs
$BuilderExitCode = $LASTEXITCODE
if ($BuilderSourceLaunchCount -ne 1) {
    throw 'The a3 launcher source dispatch count drifted after child exit.'
}
exit $BuilderExitCode
