# External Recovery Tools Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans inline; independent read-only CLI research and one final fresh review. Prior authorization waives intermediate approval gates.

**Goal:** integrar seis ferramentas reais aos fluxos autorizados, persistentes e auditáveis do CORE.
**Architecture:** perfis fechados em external_tools.py; subprocesso fixo external_tools_child.py com argv sem shell e saída normalizada. RecoverySessions reutiliza seus controles; análises usam operation_results.
**Tech Stack:** Python3.12, unittest, GitHub APIs/Actions, Hashcat, John Jumbo, QPDF, OpenSSL, DIE, Unblob.
**Spec:** docs/external-recovery-tools.md

## Global Constraints
- Somente GitHub; nenhum clone/instalação/execução local do produto.
- Preservar a branch Claude e os contratos do PR23.
- Senhas por stdin/arquivo0600; nenhum segredo em argv/log/relatório/artefato.
- Teste real obrigatório para cada CLI; ausência não é integração validada.

## Review Focus
- Senha errada não pode ser sucesso nem causar reutilização de potfile.
- Pausa/cancelamento durante chamada não pode publicar resposta tardia.
- Ferramenta não pode herdar credenciais nem executar arquivo analisado.
- Saída bruta potencialmente sensível não pode vazar em erro ou relatório.
- Parser/saída truncada não pode virar resultado completo.

### Task1: contratos e workflow
- [x] Criar tests/test_external_recovery_tools.py com chamadas reais e contratos de disponibilidade/escopo.
- [x] Criar workflow próprio; observar falhas antes do código.
- [x] Provisionar ferramentas só no runner e registrar versões.

### Task2: runtime, identificação e persistência
Files: src/cyber_core/external_tools.py, external_tools_child.py, cli/operations.py, cli/__init__.py.
Interface: tool_inventory() -> dict; analyze_tool(core,case,path,tool) -> resultado auditável.
- [x] Implementar seleção de executáveis absolutos e perfis allowlist, subprocessos limitados, parsing DIE/Unblob.
- [x] Provar cópia verificada, pausa/cancelamento, integridade e relatório.

### Task3: recuperação
Files: cryptanalysis/formats.py, recovery_trial.py, sessions.py, external_tools.py.
Interface: external_trial(mode,raw,candidate,config) -> dict matched/password_validated/format/validation.
- [x] Integrar os seis modos de tentativa e configuração confiável do ambiente.
- [x] Verificar senha incorreta/correta para QPDF/OpenSSL/John/Hashcat e ZIP real.
- [x] Manter todos os testes de sessão existentes.

### Task4: conclusão
- [ ] Concluir rodada final de CLIs reais em Linux; formatos internos, suíte e demo em Linux/Windows já passaram no commit 1a7c3ab.
- [x] Revisão independente; regressões reproduzidas antes das correções.
- [ ] Registrar recibo final do CI no PR; manter sem merge automático.

## Escopo adicional confirmado em 2026-10-22

Exibição explícita de senhas com recovery-session show --show-password, sem cópia
persistida em banco/relatórios. Testes do comando completo, pausa, revogação, HMAC
da lista e evidência alterada estão implementados. Documentação: external-password-display.md.

## Diagnóstico reproduzido

Run 39884244921: ZIP/John corrigido preservando argv[0] do symlink zip2john; Hashcat
falhou por ausência de libOpenCL (POCL instalado sem loader porque recommends está
desativado). Provisionamento agora exige ocl-icd-libopencl1, clinfo e backend-info.
A entrega permanece em validação até a execução final das seis ferramentas passar.
