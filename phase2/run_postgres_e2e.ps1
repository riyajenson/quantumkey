param(
    [string]$PythonPath = ".\.venv\Scripts\python.exe"
)

$ErrorActionPreference = 'Stop'

$python = (Resolve-Path $PythonPath).Path
$scripts = Split-Path $python -Parent
$containerName = "qk-phase2-pg-$([guid]::NewGuid().ToString('N').Substring(0, 8))"
$password = [guid]::NewGuid().ToString('N')
$image = 'postgres:17@sha256:b8faeff7712663c2773a190181e1246e37e364b887611c04658c28b44e2408fe'
$previousTestDatabaseUrl = $env:QK_TEST_DATABASE_URL
$previousPath = $env:PATH
$containerStarted = $false
$testExit = 1

try {
    docker info *> $null
    if ($LASTEXITCODE -ne 0) {
        throw 'Docker Desktop is not available. Start its Linux engine and retry.'
    }

    $null = docker run --rm --detach `
        --name $containerName `
        --env 'POSTGRES_USER=qk_test_phase2' `
        --env "POSTGRES_PASSWORD=$password" `
        --env 'POSTGRES_DB=qk_test_phase2' `
        --publish '127.0.0.1::5432' `
        $image
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not start the temporary PostgreSQL container.'
    }
    $containerStarted = $true

    $ready = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        docker exec $containerName pg_isready -U qk_test_phase2 -d qk_test_phase2 *> $null
        if ($LASTEXITCODE -eq 0) {
            $ready = $true
            break
        }
        Start-Sleep -Milliseconds 500
    }
    if (-not $ready) {
        throw 'PostgreSQL did not become ready within 30 seconds.'
    }

    $port = [int]((docker port $containerName 5432/tcp).Split(':')[-1])
    $env:QK_TEST_DATABASE_URL = "postgresql+psycopg://qk_test_phase2:$password@127.0.0.1:$port/qk_test_phase2"
    $env:PATH = "$scripts;$previousPath"

    $serverVersion = docker exec $containerName psql -U qk_test_phase2 -d qk_test_phase2 -Atc 'SHOW server_version'
    Write-Output "PostgreSQL server version: $serverVersion"

    & $python -m pytest phase2/tests/e2e/test_authenticator_to_api.py -q
    $testExit = $LASTEXITCODE
}
finally {
    $env:PATH = $previousPath
    if ($null -eq $previousTestDatabaseUrl) {
        Remove-Item Env:QK_TEST_DATABASE_URL -ErrorAction SilentlyContinue
    }
    else {
        $env:QK_TEST_DATABASE_URL = $previousTestDatabaseUrl
    }
    if ($containerStarted) {
        docker stop $containerName *> $null
    }
}

exit $testExit
