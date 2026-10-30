# ZAP passivo no Jarvis — desenho da próxima entrega

Estado: desenho para aprovação; implementação e testes ainda não executados.
Data: 2026-10-30.
Base: PR #34, codex/api-runtime-lab, 19bafbe1b94cfb87645e0cc784f87df4bd6e8cc0.
Contexto: PRs #29–34 já acrescentam HTTPS, campanhas persistentes, inventário HTML/OpenAPI e API sintética. Preservar esse trabalho; não recriar os módulos a partir da main.

## Objetivo
Acrescentar dast_passive às campanhas existentes: ZAP real analisa respostas de endpoints explicitamente autorizados e o CORE publica alertas sanitizados, cobertura e identidade da ferramenta no relatório. Este incremento não conclui a plataforma completa.

## Abordagens
1. Detectores próprios: integração pequena, cobertura limitada e manutenção de regras.
2. ZAP baseline com spider: cobertura mais ampla, mas descoberta automática não corresponde à lista exata de caminhos já autorizada.
3. ZAP passivo alimentado apenas por requisições controladas: recomendado para esta entrega, preserva escopo explícito e usa regras maduras.
O proprietário aceitou começar pela entrega passiva. A integração detalhada da opção 3 permanece proposta para revisão deste desenho.

## Contrato
- Reutilizar grant HTTPS, aquisição verificada, hashes, autorização, prazo, pausa, cancelamento, receipts e guard transacional de publicação.
- Execução inicial e validação em laboratório descartável Linux no GitHub. CLI e testes de contratos/regressão também Windows; backend ausente retorna unavailable, sem aprovação fictícia.
- ZAP em backend contido, sem acesso direto ao alvo. Transporte controlado aplica origem/caminho/GET, orçamento, validação TLS upstream e política DNS. Sem spider, AJAX spider, active scan, scripts do alvo ou atualização automática de add-ons durante a análise.
- Não habilitar URLs reais antes de comprovar contenção e equivalência dos controles HTTPS existentes. O CI não acessa alvos externos de pentest.
- Identidade do ZAP/imagem por digest e inventário de add-ons/regras capturado. Versões e digest serão fixados no plano após inspeção do backend.
- Até 8 caminhos, 1 requisição por vez, intervalo mínimo 0,25 s, corpo até 1 MiB por resposta; prazo total do estágio até 300 s, limitado pelo CORE. Incluir startup e espera da fila passiva no prazo. O plano deve identificar limites rígidos e cooperativos.
- Alertas exportam apenas rule ID, risco/confiança, método, caminho autorizado e códigos normalizados. Não exportar corpos, valores de cookies, tokens, cabeçalhos brutos ou evidências livres do scanner. Scratch temporário privado, limites e limpeza explícitos; nenhuma alegação de cofre.
- Cookies: registrar apenas contagens e presença de Secure/HttpOnly/SameSite, sem nomes/valores; ausência de atributo é observação contextual, não falha confirmada.
- Alertas são observation/suspected, nunca vulnerabilidade automaticamente validada. Fila incompleta, limite, timeout, dependência ausente e falha são estados explícitos.
- Retomada adota receipt já publicado. Sem receipt, repetição limitada de GET é declarada; sem alegação de checkpoint por requisição.
- full_pentest_completed permanece false. Sem login real, credenciais reais, exploração ou alterações no alvo.

## Integração e responsabilidades
Usar branch Codex própria a partir do head imutável acima; nenhuma branch Claude editada/integrada. Acrescentar adapter de protocolo/execução e testes das seções pares. Regras do ZAP são externas/versionadas, sem alterar silenciosamente os módulos de vulnerabilidades da seção 9. Preservar APIs compartilhadas de campanha/CORE.

## Aceite
1. ZAP real produz alerta esperado em fixture sintética e distingue controle corrigido.
2. Provas de bloqueio de egress direto, origem/caminho/método extra, redirect, DNS misto/rebinding e certificado inválido.
3. Marcadores secretos sintéticos ausentes de stdout, auditoria, SQLite de resultados e relatório.
4. Pausa/cancelamento/expiração e alteração de inputs interrompem estágio e impedem publicação tardia.
5. Falha após publicação seguida de reabertura adota receipt sem reenviar tráfego.
6. Limites, fila incompleta, ausência de backend e regressões HTTPS/API/campanhas Windows/Linux verificados.
7. PR contém links de CI do head exato; nada instalado/clonado/executado no computador do proprietário.

## Fora desta entrega
DAST ativo, crawling, sessões autenticadas, SAST/SCA, testes de negócio, operação em sites reais, merge e disponibilização do beta a terceiros.

## Fontes
- https://www.zaproxy.org/docs/docker/baseline-scan/
- https://www.zaproxy.org/docs/api/
- docs/superpowers/specs/2026-10-28-pentest-platform-design.md no PR #30.
