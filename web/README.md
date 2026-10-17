# CYBER CORE — interface azul aprovada

A direção visual foi apresentada como imagem e aprovada pelo proprietário antes do primeiro commit de implementação: fundo escuro, azul/ciano, escudo/globo e módulos na barra lateral.

## Escopo desta entrega

Interface de demonstração em HTML/CSS/JavaScript, sem dependências de produção ou fontes remotas. Reaproveita/evolui os fluxos do protótipo do Claude (referência ef8c6de4c5ab43c8d4c37ba441c3a6d2ad4d4343), mantendo compatibilidade com a chave de estado do navegador cybercore.ui.v1.

Inclui visão geral com busca, criação e seleção de investigações, tarefas, pausa/retomada/cancelamento, recuperação, perícia, ferramentas, agentes e relatório Markdown. Casos de exemplo são carregados na primeira visita; dados existentes não são substituídos pelos exemplos. A interface permanece identificada como demonstração em todas as telas.

Nenhum arquivo é lido/enviado, nenhuma análise do CORE é executada e nenhum provedor é chamado. Ghidra/Binwalk são apresentados como capacidades já integradas ao CORE, sem inventar disponibilidade ao vivo. Agentes aparecem aguardando configuração; a interface não recebe credenciais. A integridade indicada refere-se somente à cadeia dos registros locais de demonstração, não a evidências reais.

Não há login adicional. Armazenamento no navegador não fornece autenticação, exclusividade de uso, confidencialidade ou custódia forense. Usar apenas dados fictícios nesta prévia.

## Testar sem instalar no computador

Actions → Approved interface validation → Run workflow. Os testes instalam Chromium e Playwright somente nos runners descartáveis Windows/Linux. Artefatos interface-preview-* contêm capturas reais desktop/mobile e relatório dos testes; todos os dados são sintéticos.

Os testes cobrem busca, navegação responsiva, criação/persistência, pausa/cancelamento, estado legado, escape de HTML, download de relatório e auditoria concorrente/adulterada. A suíte Python existente continua independente da interface.

## Abrir no GitHub Pages

A publicação é manual. O proprietário configura Settings → Pages → Source: GitHub Actions e executa Actions → Publish approved interface → Run workflow na main. O link aparece no resultado da etapa de publicação. Nenhuma configuração administrativa ou publicação é executada automaticamente por este trabalho.

GitHub Pages hospeda somente estes arquivos estáticos; não executa Python, Ghidra ou Binwalk e não fornece armazenamento operacional do CORE. A ligação visual ao motor real continua uma entrega separada. Se a página for pública, continua sendo uma demonstração, sem acesso aos casos do CORE.

## Integração com a branch do Claude

Somente os arquivos da interface foram reaproveitados; a branch do Claude e seus módulos Python permanecem intactos. Como web/ não existia na main, um merge futuro do protótipo anterior pode apresentar conflitos add/add: manter a direção visual aprovada e preservar a compatibilidade do estado/fluxos, verificando novamente os testes de navegador. Não resolver isso substituindo automaticamente a interface aprovada pela paleta anterior.

Desenvolvimento e validação somente no GitHub. Nada foi instalado, clonado ou executado no computador do proprietário.
