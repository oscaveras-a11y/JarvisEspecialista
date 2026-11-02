# Logs, erros e evidências

Esta referência serve à revisão e à correção de software próprio ou explicitamente autorizado. Ela não contém alvos, credenciais, instruções de exploração ou automação ofensiva. Use fixtures inventadas, ambiente isolado e autorização verificável; interrompa a atividade se o escopo não estiver claro.

## Objetivo

Logs ajudam detecção e investigação quando registram eventos úteis, íntegros e protegidos. Colete o mínimo necessário, defina retenção e acesso, e trate toda entrada de log como não confiável para evitar falsificação ou exposição.

## Como revisar

Procure senhas, tokens, dados pessoais, cabeçalhos completos, consultas com parâmetros, erros internos e ausência de eventos de autorização. Revise também escape, correlação de eventos, relógio e permissões de armazenamento. Faça o percurso de ponta a ponta e registre premissas, fronteiras e controles existentes. Confirme o comportamento no código e na configuração, não apenas no nome da função ou no contrato.

## Evidências

Use marcadores sintéticos para verificar quais campos são emitidos, quem pode ler logs e como ocorre a rotação. Relatórios devem guardar hash ou metadados, com conteúdo sensível redigido. Preserve apenas o necessário para reproduzir a conclusão: versão, local do código, condição, resultado e hash quando útil. Redija segredos e dados pessoais, mantendo evidência privada em local aprovado.

## Correção

Estruture eventos com campos allowlisted, redija segredos antes de persistir, proteja integridade e acesso e escolha retenção proporcional. Retorne erros externos genéricos e mantenha detalhe restrito em canal operacional. Prefira uma mudança pequena na causa raiz, com defesa em profundidade e privilégio mínimo. Explique impacto, compatibilidade e qualquer risco residual; evite esconder falhas por mensagens ou filtros superficiais.

## Teste de regressão

Automatize asserções de não vazamento com canários sintéticos e confira eventos para sucesso, negação e erro. Verifique escaping, limites e rotação. Compare caso permitido e caso negado, limites e erro. Use dados sintéticos determinísticos, não dependa de rede pública e confirme que a correção não desabilita funcionalidade legítima.

## Limites

Mais telemetria não significa melhor detecção. Regras de privacidade e retenção variam; valide necessidade, autorização e proteção do pipeline de logs. Trate resultado como válido apenas para escopo, versão e configuração observados. Falta de alerta não comprova ausência de risco; uma declaração do sistema também não comprova sua imposição.

## Fontes

- https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/

Revise as fontes oficiais no momento da implementação: versões, defaults e recomendações podem mudar. Esta nota é material de referência local, não certificação nem substituto de revisão humana.
