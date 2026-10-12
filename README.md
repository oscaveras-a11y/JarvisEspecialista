# J.A.R.V.I.S — local, com voz em português do Brasil

Projeto pessoal baseado no [OpenJarvis oficial](https://github.com/open-jarvis/OpenJarvis),
com Ollama para o modelo, faster-whisper para ouvir e Kokoro `pf_dora` para falar.
Ativação pelo comando `jarvis` ou falando **“Jarvis”** no modo de escuta.
Não há detector de palmas.

O código oficial completo está vinculado na pasta `jarvis/` como **submódulo Git**,
fixado em uma versão. Veja [UPSTREAM.md](UPSTREAM.md).

## Situação desta entrega

Preparado para instalar depois no computador. Os testes automáticos do launcher
e a sintaxe PowerShell foram verificados; microfone, alto-falantes, download dos
modelos, build web e `jarvis doctor` precisam ser validados na instalação real.
O GitHub armazena o código: ele não escuta seu microfone nem executa o assistente.

## Windows

Requer Windows 10/11 com winget. Clone este repositório usando Git autenticado
na sua conta (ele é privado), sem colocar tokens na URL:

```powershell
git clone --recurse-submodules https://github.com/oscaveras-a11y/J.A.R.V.I.S.git
cd J.A.R.V.I.S
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1
```

O instalador anuncia cada etapa, instala o que faltar usando winget, exige
Node >=22.22, usa npm 11.19.0 para construir a interface e deixa o uv escolher
Python >=3.10 e <3.14. Instala desktop/voz, inicia Ollama, baixa o modelo,
configura PT-BR e executa doctor, teste de texto e síntese de voz.
Abra um terminal novo depois da instalação para atualizar o PATH.

Por padrão usa `gemma4:e4b`. Se detectar menos de 16 GB de RAM, avisa e escolhe
`gemma4:e2b`. Para escolher explicitamente ou omitir a interface:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Model gemma4:e2b -SkipWeb
```

`-SkipVoiceTest` omite o download/síntese inicial da voz; eles ocorrerão no primeiro uso.

## Mac

```bash
git clone --recurse-submodules https://github.com/oscaveras-a11y/J.A.R.V.I.S.git
cd J.A.R.V.I.S
bash install.sh
```

Instala Homebrew se faltar, Node, Git, Ollama, PortAudio, eSpeak NG e uv oficial.
O Homebrew pode solicitar autenticação no próprio terminal; nenhuma senha ou
chave é solicitada em campos de navegador por este projeto.
Depois, abra um terminal novo. Se `jarvis` não for encontrado:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Adicione essa linha ao seu `~/.zprofile` se necessário.
Para escolher o modelo menor: `JARVIS_MODEL=gemma4:e2b bash install.sh`.

## Três comandos do dia a dia

```text
jarvis
jarvis --listen
jarvis --web
```

- `jarvis`: começa a conversa por voz imediatamente, sem pressionar Enter a cada frase.
- `jarvis --listen`: aguarda você falar “Jarvis”, responde “Estou aqui. Como posso ajudar?”
  e inicia a conversa. Diga **“encerrar conversa”** ou **“voltar a esperar”** para
  voltar a aguardar o nome. Primeiro diga o nome, aguarde o aviso, depois faça a pergunta.
- `jarvis --web`: inicia o servidor local e abre `http://127.0.0.1:8000`.

Também existem `jarvis --text`, `jarvis --doctor`, `jarvis --stop` e `jarvis --list-mics`.
Se o comando ainda não estiver no PATH, use `./bin/jarvis` no Mac ou
`.\bin\jarvis.cmd` no Windows, com os mesmos argumentos.
Mantenha a pasta do projeto onde foi instalada: os atalhos apontam para ela.

No modo de escuta, **Ctrl+C enquanto aguarda o nome** encerra o programa;
durante a gravação da conversa, Ctrl+C pode devolver à escuta do nome.
No modo direto, “encerrar conversa” encerra o chat.

## Microfone e ativação pelo nome

A ativação usa transcrição Whisper local em português; não é um detector
especializado de wake word. Consome CPU enquanto está ouvindo e pode falhar
com ruído, sotaque, distância ou se o nome for transcrito de outro modo.
Uma gravação termina após silêncio, então há uma pequena espera para ativar.
Conceda acesso ao microfone ao terminal nas configurações de privacidade do sistema.

Liste os dispositivos com `jarvis --list-mics`, e escolha pelo número ou nome:

```powershell
$env:JARVIS_MIC = '2'
jarvis --listen
```

```bash
JARVIS_MIC='Microfone USB' jarvis --listen
```

A escolha vale tanto para a escuta do nome quanto para a conversa.
Opcionalmente coloque `voice/assets/jingle.mp3`: ele toca quando o nome é reconhecido.

## Arquivos, modelos e privacidade

- Personalizações: este repositório; código oficial: submódulo `jarvis/`.
- Configuração, histórico local e teste de voz: `.state/`, fora do código oficial.
- Ambiente Python: `jarvis/.venv/`; modelos Ollama: armazenamento padrão do Ollama.
- Kokoro/Whisper: cache local do Hugging Face. O primeiro uso exige download;
  depois a inferência de texto e voz é local.
- Modelo e4b/e2b: o tamanho varia com a versão/quantização publicada no Ollama;
  consulte [o catálogo oficial](https://ollama.com/library/gemma4).
  Planeje espaço adicional para Python, dependências, frontend e caches.
- Nenhuma chave de API é necessária. `.env`, `.state/` e modelos não vão para o GitHub.
- Os instaladores desativam analytics e telemetry, deixam o servidor em
  `127.0.0.1` e usam chat sem ferramentas externas por padrão.
- O launcher desativa a consulta de atualização e restringe o fallback de TTS
  ao Kokoro local. O perfil de segurança solicitado é `personal`.

## Diagnóstico

O instalador interrompe nas falhas; leia a mensagem completa. Ele executa o doctor
normal e verifica seu JSON porque nem toda falha do doctor altera o código de saída.
Os avisos sobre componentes opcionais devem ser avaliados conforme o uso desejado.

Se `winget` falhar com certificado ou origem indisponível, não desative a validação
TLS: use os instaladores oficiais de [uv](https://docs.astral.sh/uv/getting-started/installation/),
[Git](https://git-scm.com/downloads/win), [Node](https://nodejs.org/) e
[Ollama](https://ollama.com/download/windows), abra outro terminal e execute novamente.

No Windows, `espeakng-loader` já é dependência do Kokoro. Só se aparecer erro
específico de eSpeak NG, instale e configure após verificar a DLL:

```powershell
winget install -e --id eSpeak-NG.eSpeak-NG --source winget
Test-Path 'C:\Program Files\eSpeak NG\libespeak-ng.dll'
# Apenas se o comando acima retornar True:
setx PHONEMIZER_ESPEAK_LIBRARY 'C:\Program Files\eSpeak NG\libespeak-ng.dll'
```

Abra outro terminal. Para dependências de compilação, siga a
[instalação oficial](https://open-jarvis.github.io/OpenJarvis/getting-started/installation/)
e o [guia Windows](https://open-jarvis.github.io/OpenJarvis/getting-started/windows-native/).
Não force Python 3.14. O instalador usa Whisper CPU/int8 para evitar exigir CUDA.

Se o modelo estiver lento, execute o instalador com `gemma4:e2b`; o modelo anterior
continua no armazenamento até ser removido com `ollama rm gemma4:e4b`.
No Windows, meça o tamanho da instalação com:

```powershell
(Get-ChildItem -LiteralPath . -File -Recurse -Force | Measure-Object Length -Sum).Sum / 1GB
```

Esse valor não inclui caches de modelos fora da pasta. No Mac: `du -sh .`.

## Testes sem instalar o assistente

```sh
python -m unittest discover -s tests -v
```

Testam reconhecimento do nome, frases de encerramento, seleção de microfone,
opções e integração do leitor automático com restauração após falha. Não
substituem o teste físico de voz na próxima etapa.
