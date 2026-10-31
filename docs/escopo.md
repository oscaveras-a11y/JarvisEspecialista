# CYBER CORE — Documento de escopo (autoritativo)

> **Proveniência.** Texto de escopo fornecido pelo proprietário do projeto (conta GitHub `oscaveras-a11y`) e versionado aqui como base oficial de referência para desenvolvimento e revisão. Resolve a lacuna apontada na revisão independente de 2026-10-17 (item 4.1: escopo autoritativo ausente do repositório). Uso legítimo, autorizado e dentro de escopo. Instalação e execução **somente no GitHub**.

**PROJETO CYBER CORE — PLATAFORMA AVANÇADA DE INVESTIGAÇÃO DIGITAL E CIBERSEGURANÇA**

## 1. Missão principal
Desenvolver uma plataforma profissional de investigação tecnológica, engenharia reversa, análise criptográfica, perícia digital, pesquisa de vulnerabilidades e resolução de problemas complexos. O objetivo é investigar problemas que ferramentas convencionais ou fabricantes não solucionaram, produzindo descobertas técnicas, soluções reproduzíveis e relatórios profissionais. O sistema poderá futuramente prestar serviços a fabricantes, empresas, laboratórios, especialistas, órgãos governamentais e autoridades policiais, sempre mediante autorização e dentro de escopo legítimo.

**Princípio fundamental: priorizar a qualidade e a profundidade da investigação, não a velocidade.** Uma investigação poderá durar horas ou dias; o sistema deve persistir o progresso, testar hipóteses e continuar enquanto houver caminhos tecnicamente fundamentados. Não prometer o impossível, não inventar descobertas, não declarar sucesso sem comprovação.

## 2. Ambiente de desenvolvimento
Windows 10/11; 8 GB de RAM; GPU integrada; IA prioritariamente na nuvem; Codex já instalado; Claude Code a instalar depois; repositório privado no GitHub; execução principal local; sem servidor pago; Python no núcleo; SQLite para memória/histórico; Git para versionamento; PowerShell para instalação/inicialização. Modular e preparado para futura migração para Linux/servidores. Não enviar dados confidenciais, firmware proprietário, credenciais, evidências ou dados de clientes a serviços externos sem autorização.

## 3. Arquitetura central
**CORE — orquestrador principal:** recebe problemas/objetivos; identifica o tipo de investigação; verifica escopo autorizado; cria planos; divide problemas em tarefas; distribui entre agentes; escolhe ferramentas; acompanha execução; identifica falhas/bloqueios; formula hipóteses; controla recursos; registra evidências; verifica resultados; produz relatórios. Controla todo o fluxo.

**CODEX — agente de engenharia:** programação, desenvolvimento de ferramentas, análise de código-fonte, testes, depuração, automação, correção de falhas, integração de módulos, engenharia reversa assistida, experimentos reproduzíveis.

**CLAUDE CODE — agente de investigação e revisão (integração futura):** revisão independente, análise de hipóteses, investigação técnica, identificação de inconsistências, revisão de código, avaliação de resultados, proposição de novos experimentos.

Agentes compartilham tarefas/resultados pelo CORE. Adaptadores independentes por agente; o sistema funciona inicialmente só com Codex, sem depender do Claude Code. Não presumir permissões, interfaces ou limites iguais entre as ferramentas.

## 4. Motor de raciocínio e investigação
Ciclos de: 1) entender o problema; 2) coletar informações; 3) identificar tecnologias; 4) pesquisar documentação; 5) formular hipóteses; 6) classificar por evidência/custo/risco/probabilidade; 7) selecionar experimentos; 8) executar ferramentas autorizadas; 9) interpretar resultados; 10) comparar com hipóteses; 11) descartar caminhos inválidos; 12) desenvolver alternativas; 13) validar descobertas; 14) registrar conclusões; 15) gerar relatório técnico. Evitar repetir testes idênticos sem justificativa. Distinguir sempre fatos, inferências, hipóteses e desconhecidos. Reconhecer quando faltam dados, hardware, chaves, permissões ou recursos.

## 5. Memória persistente
SQLite local armazenando: investigações anteriores, objetivos, hipóteses, experimentos, ferramentas usadas, comandos executados, resultados, erros, evidências, arquivos analisados, hashes, descobertas, soluções validadas e pontos de retomada. Permitir pesquisar e reaproveitar conhecimento; criar checkpoints para retomar após reinício. Evitar guardar segredos e dados pessoais desnecessários.

## 6. Módulo de engenharia reversa
Analisar: PE/EXE, DLL, ELF, firmware automotivo e eletrônico, BIN/HEX/S19/ELF, formatos proprietários, código de máquina, estruturas binárias, protocolos, arquivos compactados/ofuscados. Integrar Ghidra, Capstone, Binwalk, HxD (ou equivalente), Python e bibliotecas de análise. Identificar arquitetura, cabeçalhos, seções, strings, estruturas e regiões de memória. Análise estática e comparação entre versões de firmware. Não modificar dispositivos reais automaticamente.

## 7. Módulo de criptografia e recuperação
Identificar formatos criptografados; reconhecer algoritmos quando houver evidência; diferenciar criptografia/compressão/ofuscação/codificação; analisar cabeçalhos; calcular entropia; examinar metadados; investigar formatos proprietários; verificar integridade; recuperar arquivos danificados quando tecnicamente possível; trabalhar com chaves/credenciais fornecidas legitimamente; auditar implementações criptográficas; avaliar possibilidades reais de recuperação; documentar limitações. Considerar AES, RSA, ECC, ChaCha20 e outros. Não presumir que alta entropia é criptografia. Não prometer quebrar criptografia forte sem as chaves. Recuperação de senhas apenas de arquivos próprios/autorizados, com controle de escopo, recursos e registro. **Não** incluir extração clandestina de chaves, roubo de credenciais ou acesso não autorizado.

## 8. Módulo de perícia digital
Análise forense de arquivos; imagens de disco; recuperação de dados; identificação de arquivos suspeitos; metadados; integridade; SHA-256; organização de evidências; linha do tempo; cadeia de custódia; relatórios periciais. Avaliar Autopsy, The Sleuth Kit, YARA e equivalentes. Preservar originais; analisar sobre cópias de trabalho; registrar origem, data, operador, transformações e hashes.

## 9. Módulo de pesquisa de vulnerabilidades
Auditorias **autorizadas** em Windows, Linux, web, APIs, servidores, redes, dispositivos, firmware e aplicações próprias. Integrar Nmap, Wireshark, Semgrep, OWASP ZAP, YARA e auditoria de dependências. Identificar configurações inseguras, componentes vulneráveis, falhas de autenticação, problemas de código e exposição. Testes ativos exigem escopo autorizado e limites operacionais; experimentos invasivos só em laboratórios isolados ou ambientes expressamente autorizados.

## 10. Módulo de análise de protocolos
CAN, CAN FD, USB, UART, SPI, I2C, TCP/IP, HTTP e protocolos binários proprietários. Importar capturas, identificar padrões, comparar mensagens, reconstruir estruturas, investigar máquinas de estado. Integrar python-can, cantools, SavvyCAN e Wireshark conforme necessidade. Priorizar análise passiva. Não transmitir comandos a equipamentos críticos sem aprovação e validação em ambiente controlado.

## 11. Motor de pesquisa técnica
Quando houver conectividade e acesso autorizado, consultar: documentação oficial, manuais, especificações, artigos científicos, bases de vulnerabilidades, repositórios públicos, documentação de protocolos, publicações de segurança e informações de microcontroladores. Registrar fontes, versões, datas e referências. Diferenciar documentação oficial, pesquisa acadêmica, relatos comunitários e hipóteses dos agentes. Não executar automaticamente código obtido da internet sem inspeção.

## 12. Execução autônoma prolongada
Fila de tarefas; execução assíncrona; checkpoints; retomada após falhas; controle de RAM; limites de CPU; controle de custos de API; limites de tentativas; detecção de tarefas travadas; registro de progresso; cancelamento seguro; pausa/retomada; recuperação após reinício; tratamento de erros de conexão; respeito aos limites de uso de Codex e Claude Code. Persistir estado e continuar quando os serviços voltarem, sem contornar limites dos provedores. Uma investigação não deve ser encerrada só por demorar; mas o motor deve reconhecer impossibilidades demonstradas, falta de recursos e ausência de caminhos fundamentados.

## 13. Verificação independente
Nenhum resultado é "solucionado" só pela declaração de um agente. Exigir: evidências verificáveis, testes reproduzíveis, resultados registrados, comparação com o comportamento esperado, revisão independente quando disponível e documentação das limitações. Estados: Resolvido e validado; Em investigação; Aguardando informações; Aguardando autorização; Aguardando recursos; Sem solução viável demonstrada; Falha de execução.

## 14. Segurança do próprio sistema
Controle de permissões; auditoria; isolamento de processos; proteção de credenciais; armazenamento seguro de segredos; separação código/evidências; confirmação para ações destrutivas; escopo de autorização por investigação; bloqueio de operações fora do escopo; proteção contra instruções maliciosas em arquivos analisados; validação de comandos antes da execução; política de acesso à rede; limites de recursos por tarefa. O CORE não permite que um agente amplie sozinho suas permissões. Alterações no próprio código são versionadas, testadas e aprovadas antes de produção.

## 15. Interface do sistema
Inicialmente, terminal funcional: criar investigação; selecionar arquivo; definir objetivo; informar autorização/escopo; acompanhar tarefas; consultar progresso; ver hipóteses; ver logs; pausar; retomar; cancelar; consultar memória; exportar relatórios. Depois, interface gráfica profissional para Windows (painel de investigações, agentes, ferramentas, resultados). Não priorizar efeitos visuais antes do motor funcionar.

## 16. Estrutura do repositório
```
cyber-core/
├── core/{orchestrator,planner,scheduler,verifier,permissions,memory}/
├── agents/{codex,claude,interfaces}/
├── modules/{reverse_engineering,cryptanalysis,forensics,vulnerability_research,protocol_analysis,research}/
├── tools/  experiments/  reports/  tests/  scripts/  docs/  config/  cli/
├── pyproject.toml  README.md  .env.example  .gitignore
```
Manter arquivos sensíveis, evidências, bancos locais e credenciais fora do Git.

## 17. Integração GitHub
Repositório privado. Versionamento Git; branches de desenvolvimento; Git Worktrees para agentes paralelos; revisão de alterações; testes automatizados; integração controlada; histórico de decisões; documentação técnica. Não publicar arquivos confidenciais. Não commitar direto na branch principal sem validação.

## 18. Testes obrigatórios
Testes automatizados para: inicialização do CORE; comunicação com Codex; funcionamento sem Claude Code; persistência da memória; retomada de tarefas; detecção de falhas; controle de permissões; análise de arquivos de exemplo; identificação de formatos; cálculo de hashes; execução isolada de ferramentas; geração de relatórios; cancelamento seguro; recuperação após interrupções; proteção contra comandos fora do escopo. Usar arquivos sintéticos, públicos ou autorizados. Não afirmar que ferramentas externas funcionam sem testes reais.

## 19. Etapas de implementação
- **Fase 1 — Fundação:** repositório, estrutura, configuração, CLI, SQLite, logging, permissões, testes iniciais.
- **Fase 2 — Orquestração:** integrar Codex, tarefas, planejamento, checkpoints, controle de erros, execução prolongada.
- **Fase 3 — Investigação de arquivos:** formatos, cabeçalhos, hashes, entropia, metadados, integridade, relatórios.
- **Fase 4 — Engenharia reversa e criptografia:** ferramentas especializadas, fluxos reproduzíveis.
- **Fase 5 — Forense e protocolos:** preservação de evidências, importação de capturas, análise de protocolos.
- **Fase 6 — Segurança e vulnerabilidades:** ferramentas de auditoria, testes controlados.
- **Fase 7 — Claude Code:** instalar, configurar e integrar o segundo agente, revisão independente e trabalho paralelo.
- **Fase 8 — Validação completa:** testes integrados, investigação de falhas, correções, retomada de tarefas, documentação.
- **Fase 9 — Interface gráfica:** interface Windows somente após validar o núcleo.

## 20. Critérios de entrega
Uma fase não está concluída só porque os arquivos foram criados. Para cada fase: 1) implementar o código; 2) instalar dependências; 3) executar testes; 4) corrigir erros; 5) reexecutar testes; 6) registrar resultados; 7) atualizar documentação; 8) informar o funcional; 9) informar o pendente; 10) avançar quando as dependências estiverem atendidas. Bloqueios externos (autenticação, permissões, hardware, serviços) devem ser registrados com precisão. Nunca inventar resultados de testes.

## 21. Instrução final (papéis)
O Codex atua como **engenheiro principal**: implementação real, modular, testável e progressivamente completa — não proposta, protótipo visual ou arquivos vazios. Começar verificando ambiente, ferramentas e acesso ao GitHub. Não apagar nem modificar outros projetos do proprietário. Criar o CYBER CORE como projeto independente. Implementar primeiro a fundação e o núcleo, com Codex como agente inicial, deixando a arquitetura preparada para o Claude Code sem depender dele. Priorizar confiabilidade, capacidade de investigação, persistência, segurança, qualidade de código e resultados verificáveis. Trabalho incremental, com testes após cada etapa. Quando uma etapa exigir autorização, instalação manual, credenciais ou recursos indisponíveis, explicar o bloqueio e aguardar.

**Objetivo final:** uma plataforma de investigação digital profissional, com dois agentes colaborativos, capaz de investigar problemas complexos de forma persistente, controlada e tecnicamente comprovável.
