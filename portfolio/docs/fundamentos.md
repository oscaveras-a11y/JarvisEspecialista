# Fundamentos

A base técnica que sustenta forense, reverse e pentest. Sem ela, ferramentas viram "clicar botão sem entender".

## Linux

- Linha de comando: navegação, `grep`/`find`/`awk`, permissões (`chmod`/`chown`), pipes e redirecionamento.
- Sistema: processos (`ps`/`top`), serviços (`systemd`), logs (`journalctl`, `/var/log`).
- Por que importa: a maioria das ferramentas de segurança e servidores roda em Linux.

## Windows

- Linha de comando: `cmd` e **PowerShell** (cmdlets, pipeline, execução de scripts).
- Sistema: usuários e grupos, Registro do Windows, Visualizador de Eventos, serviços.
- Por que importa: a maioria dos incidentes periciais acontece em ambiente Windows.

## Redes

- Modelo TCP/IP, endereçamento IP, portas e protocolos.
- **DNS** (resolução de nomes), **HTTP/HTTPS** (requisições, cabeçalhos, status).
- Captura e análise de tráfego com **Wireshark**.
- Por que importa: entender a rede é pré-requisito para enumeração e forense de rede.

## Lógica e programação

- **Python** como primeira linguagem: tipos, controle de fluxo, funções, arquivos, bibliotecas.
- Noções de scripting para automatizar tarefas repetitivas.
- Por que importa: quem programa entende o que as ferramentas fazem — e constrói as próprias.

## Como estudar

Teoria curta + prática imediata no laboratório ([../lab/](../lab/)). Anotar o que aprendeu em writeups ([../writeups/](../writeups/)).
