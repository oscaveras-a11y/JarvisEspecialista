[CmdletBinding()]
param(
    [ValidateSet('auto', 'gemma4:e4b', 'gemma4:e2b')][string]$Model = 'auto',
    [switch]$SkipWeb,
    [switch]$SkipVoiceTest
)
$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot
if ([Environment]::OSVersion.Platform -ne 'Win32NT') {
    throw 'Este instalador e para Windows; no Mac use bash install.sh.'
}
function Step([string]$Text) { Write-Host "`n$Text" -ForegroundColor Cyan }
function Run([string]$Exe, [string[]]$Arguments) {
    & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Falhou ($LASTEXITCODE): $Exe $($Arguments -join ' ')" }
}
function Refresh-Path {
    $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' +
        [Environment]::GetEnvironmentVariable('Path', 'User') + ';' + $env:Path
}
function Ensure([string]$Command, [string]$Package) {
    if (-not (Get-Command $Command -ErrorAction SilentlyContinue)) {
        if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
            throw 'winget ausente. Instale/atualize App Installer da Microsoft e execute novamente.'
        }
        Step "Vou instalar $Command pelo winget."
        Run 'winget' @('install', '-e', '--id', $Package, '--source', 'winget',
            '--accept-source-agreements', '--accept-package-agreements')
        Refresh-Path
    }
    if (-not (Get-Command $Command -ErrorAction SilentlyContinue)) {
        throw "$Command ainda nao esta no PATH. Abra um terminal novo e execute este instalador novamente."
    }
}
Step 'Vou verificar uv, Git, Node e Ollama no Windows.'
Ensure 'uv' 'astral-sh.uv'
Ensure 'git' 'Git.Git'
Ensure 'node' 'OpenJS.NodeJS.LTS'
Ensure 'ollama' 'Ollama.Ollama'
$NodeVersion = [version]((& node --version).Trim().TrimStart('v'))
if ($NodeVersion -lt [version]'22.22.0') {
    Step 'Vou atualizar o Node para a versao LTS atual.'
    Run 'winget' @('upgrade', '-e', '--id', 'OpenJS.NodeJS.LTS', '--source', 'winget',
        '--accept-source-agreements', '--accept-package-agreements')
    Refresh-Path
    if ([version]((& node --version).Trim().TrimStart('v')) -lt [version]'22.22.0') {
        throw 'Node ainda e antigo. Abra um terminal novo antes de continuar.'
    }
}
Step 'Vou trazer o codigo oficial fixado no submodulo jarvis.'
Push-Location $Root
try { Run 'git' @('submodule', 'update', '--init', '--recursive') }
finally { Pop-Location }
$env:OPENJARVIS_HOME = Join-Path $Root '.state'
$env:DO_NOT_TRACK = '1'
$env:OPENJARVIS_NO_UPDATE_CHECK = '1'
$env:JARVIS_SKIP_MODEL_PICK = '1'
Push-Location (Join-Path $Root 'jarvis')
try {
    Step 'Vou instalar as dependencias de desktop e voz, deixando o uv escolher Python entre 3.10 e 3.13.'
    Run 'uv' @('sync', '--extra', 'desktop', '--extra', 'voice', '--no-dev')
    Step 'Vou verificar se o servidor local do Ollama esta pronto.'
    try { $null = Invoke-RestMethod 'http://127.0.0.1:11434/api/tags' -TimeoutSec 2 }
    catch {
        $OllamaExe = (Get-Command ollama).Source
        Start-Process -FilePath $OllamaExe -ArgumentList 'serve' -WindowStyle Hidden | Out-Null
        $Ready = $false
        for ($i = 0; $i -lt 30; $i++) {
            Start-Sleep -Seconds 1
            try {
                $null = Invoke-RestMethod 'http://127.0.0.1:11434/api/tags' -TimeoutSec 2
                $Ready = $true; break
            } catch { }
        }
        if (-not $Ready) { throw 'Ollama nao respondeu na porta 11434. Abra o aplicativo Ollama e execute novamente.' }
    }
    if ($Model -eq 'auto') {
        $Model = 'gemma4:e4b'
        try {
            $Ram = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory
            if ($Ram -lt 16GB) {
                $Model = 'gemma4:e2b'
                Write-Warning 'Menos de 16 GB de RAM: usando gemma4:e2b para reduzir o consumo.'
            }
        } catch { Write-Warning 'Nao foi possivel medir a RAM; mantendo gemma4:e4b.' }
    }
    Step "Vou baixar o modelo local $Model; o tamanho varia conforme a versao publicada pelo Ollama."
    Run 'ollama' @('pull', $Model)
    Step 'Vou configurar Ollama, perfil personal, Whisper em portugues e a voz brasileira pf_dora.'
    Run 'uv' @('run', '--no-sync', 'jarvis', '_bootstrap', '--write-config', '--engine', 'ollama', '--model', $Model)
    foreach ($Setting in @(
        @('security.profile', 'personal'), @('speech.voice_id', 'pf_dora'),
        @('speech.language', 'pt'), @('speech.backend', 'faster-whisper'),
        @('speech.tts_backend', 'kokoro'), @('speech.device', 'cpu'),
        @('speech.compute_type', 'int8'), @('telemetry.enabled', 'false'),
        @('analytics.enabled', 'false'),
        @('agent.default_agent', 'none'), @('server.host', '127.0.0.1')
    )) { Run 'uv' @('run', '--no-sync', 'jarvis', 'config', 'set', $Setting[0], $Setting[1]) }
    if (-not $SkipWeb) {
        Step 'Vou instalar e construir a interface web.'
        Push-Location 'frontend'
        try {
            Run 'npx.cmd' @('--yes', '--package=npm@11.19.0', 'npm', 'ci')
            Run 'npx.cmd' @('--yes', '--package=npm@11.19.0', 'npm', 'run', 'build')
        }
        finally { Pop-Location }
    }
    Step 'Vou validar o doctor e o funcionamento por texto.'
    Run 'uv' @('run', '--no-sync', 'jarvis', 'doctor')
    Run 'uv' @('run', '--no-sync', 'python', '../voice/check_doctor.py')
    Run 'uv' @('run', '--no-sync', 'jarvis', 'ask', '--engine', 'ollama', 'Em uma frase, quem e voce? Responda em portugues do Brasil.')
    if (-not $SkipVoiceTest) {
        Step 'Vou baixar os modelos de voz e sintetizar uma frase em portugues para validar Kokoro e Whisper.'
        Run 'uv' @('run', '--no-sync', 'python', '../voice/validate.py')
    }
} finally { Pop-Location }
Step 'Vou disponibilizar o comando jarvis no PATH do seu usuario.'
$Bin = Join-Path $Root 'bin'
$UserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (($UserPath -split ';') -notcontains $Bin) {
    [Environment]::SetEnvironmentVariable('Path', "$Bin;$UserPath", 'User')
}
$env:Path = "$Bin;$env:Path"
Write-Host 'Configuracao concluida. Abra um terminal novo: jarvis, jarvis --listen ou jarvis --web.'
Write-Host 'Teste o microfone dizendo uma frase em jarvis. Ctrl+C encerra.'
