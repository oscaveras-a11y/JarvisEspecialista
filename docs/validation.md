# Validação — 16/10/2026

**Resultado final: 33 testes passaram, 0 falhas, 0 erros, 0 skips, em 70,334 segundos.** Comando: `python -m unittest discover -s tests -v`, com PYTHONPATH=src. Não usar esses resultados como prova de módulos ainda pendentes.

Ambiente observado: Windows 10 build 19042, Python 3.12.14 (64 bits), SQLite 3.53.1, Git 2.55.0.windows.5, cryptography disponível. Python não estava no PATH inicial do shell; foi usado o runtime Python do aplicativo. O executável Codex foi descoberto no ambiente do processo Python e seu `exec --help` foi consultado. Claude e gh não foram encontrados.

Execuções iniciais: 10 testes do núcleo passaram; depois 21 testes de núcleo/CLI/AES passaram e 5 testes de subprocessos passaram. Revisão independente encontrou três falhas e cada uma foi reproduzida antes da correção: retorno do arquivo errado na fila; stdin bloqueado ignorando timeout; encadeamento concorrente de auditoria. Após correção, a suíte consolidada com 29 testes passou em 122,450 segundos.

Uma verificação adicional de banco corrompido mostrou traceback em vez de erro operacional; o tratamento de sqlite3.Error foi incluído e passou na execução final. Também passaram expiração de autorização, arquivo vazio e exigência de permissão separada para envio de resumo à nuvem.

A demonstração sintética passou nas 12 verificações solicitadas: investigação/autorização, assinatura, SHA-256, entropia, hipótese/experimento, persistência, relatório, pausa/retomada em processos novos, AES conhecido autenticado, rejeições de autorização/chave/escopo e integridade auditada. Binário: 32772 bytes, SHA-256 `1f1b0fd44bfd8ac41cefa1de8dd28989adcb25acf1f972fee97feebc5504ba58`, entropia 7,999999324684831. Plaintext recuperado: 40 bytes, SHA-256 `d886ecb5a92f302d5530a7dfd7da2d73a41f197d903aab8f952cb4ea71c8ea72`.

Integração real Codex: **não validada**. No sandbox, exit 1; `codex login status` informou `Could not find home directory`. Uma segunda chamada sob o usuário correto excedeu 30 segundos e foi encerrada pelo controle de timeout. Não houve resposta final do CLI nem autenticação comprovada. A revisão independente do código foi feita por agente de revisão do ambiente de desenvolvimento; isso não valida o adaptador Codex nem o Claude.

Instalação verificada: venv local criado com `--system-site-packages` para reutilizar cryptography 50.0.2 já instalado, sem download. `pip install --no-deps --no-build-isolation -e .` construiu e instalou cyber-core 0.1.0. A instalação foi repetida sem `--no-deps`: a resolução de dependências passou com cryptography 50.0.2, e `pip check` informou ausência de requisitos quebrados. O entrypoint `.venv/Scripts/cyber.exe doctor` executou com exit 0. `python -m compileall -q src scripts tests` passou.

Scripts PowerShell foram escritos, mas sua execução/validação não foi comprovada: o processo powershell.exe não retornou no ambiente de ferramentas e foi interrompido. Os testes e a instalação foram realizados pelos comandos Python diretos documentados no README. Não declarar o instalador PowerShell testado.

O Git HTTPS falhou no sandbox inicial; fetch autorizado fora dele funcionou. Publicação deve preservar o commit remoto anterior e13049b0ba3368d3b31c772f97ef8d856950f37f como ancestral.
