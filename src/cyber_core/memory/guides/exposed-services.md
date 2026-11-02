# APIs e serviços expostos

Esta referência serve à revisão e à correção de software próprio ou explicitamente autorizado. Ela não contém alvos, credenciais, instruções de exploração ou automação ofensiva. Use fixtures inventadas, ambiente isolado e autorização verificável; interrompa a atividade se o escopo não estiver claro.

## Objetivo

Inventarie interfaces de rede, rotas, métodos, autenticação, exposição e dependências. Um contrato OpenAPI expressa declarações; compare com resposta observada e código de autorização em ambiente sintético antes de classificar comportamento.

## Como revisar

Revise endpoints de administração, serviços de dados sem necessidade pública, métodos não documentados, CORS permissivo, configurações inseguras, falta de TLS, limites ausentes e diferenças entre ambientes. Faça o percurso de ponta a ponta e registre premissas, fronteiras e controles existentes. Confirme o comportamento no código e na configuração, não apenas no nome da função ou no contrato.

## Evidências

Use laboratório ou fixture local e escopo explícito. Registre método, rota sintética, status, cabeçalhos e requisito declarado, redigindo dados sensíveis. Separe inventário, alerta e falha confirmada; não teste sites reais sem autorização específica. Preserve apenas o necessário para reproduzir a conclusão: versão, local do código, condição, resultado e hash quando útil. Redija segredos e dados pessoais, mantendo evidência privada em local aprovado.

## Correção

Desabilite serviços desnecessários, restrinja rede por firewall, autentique e autorize no servidor, valide entrada e aplique TLS e limites. Separe gestão de tráfego e monitore tentativas sem armazenar credenciais. Prefira uma mudança pequena na causa raiz, com defesa em profundidade e privilégio mínimo. Explique impacto, compatibilidade e qualquer risco residual; evite esconder falhas por mensagens ou filtros superficiais.

## Teste de regressão

Teste rotas e métodos documentados em servidor simulado, com identidades sintéticas e respostas esperadas. Cubra autorização, limites, cabeçalhos e comportamento de erro. Compare caso permitido e caso negado, limites e erro. Use dados sintéticos determinísticos, não dependa de rede pública e confirme que a correção não desabilita funcionalidade legítima.

## Limites

Resultados dependem de proxy, gateway e ambiente. Varredura estática ou contrato isolado não revela todo o estado implantado; registre limitações e não extrapole. Trate resultado como válido apenas para escopo, versão e configuração observados. Falta de alerta não comprova ausência de risco; uma declaração do sistema também não comprova sua imposição.

## Fontes

- https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/

Revise as fontes oficiais no momento da implementação: versões, defaults e recomendações podem mudar. Esta nota é material de referência local, não certificação nem substituto de revisão humana.
