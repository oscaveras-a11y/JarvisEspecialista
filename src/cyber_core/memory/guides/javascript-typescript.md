# JavaScript e TypeScript seguros

Esta referência serve à revisão e à correção de software próprio ou explicitamente autorizado. Ela não contém alvos, credenciais, instruções de exploração ou automação ofensiva. Use fixtures inventadas, ambiente isolado e autorização verificável; interrompa a atividade se o escopo não estiver claro.

## Objetivo

TypeScript melhora a descrição estática dos dados, mas tipos desaparecem em execução e não validam automaticamente JSON, parâmetros HTTP ou armazenamento. No navegador e no servidor, defina limites de confiança e valide dados na fronteira.

## Como revisar

Examine montagem de HTML, manipulação de URL, dependências do pacote, segredos enviados ao bundle, validação apenas no cliente, permissões de rota e funções dinâmicas. Confira se o framework escapa o contexto correto e se há escapes inseguros ou renderização direta. Faça o percurso de ponta a ponta e registre premissas, fronteiras e controles existentes. Confirme o comportamento no código e na configuração, não apenas no nome da função ou no contrato.

## Evidências

Siga cada valor externo até DOM, API, banco ou chamada de sistema. Use casos sintéticos em navegador de teste e confirme a configuração de produção, cabeçalhos, build e permissões. Diferencie aviso do scanner de comportamento alcançável. Preserve apenas o necessário para reproduzir a conclusão: versão, local do código, condição, resultado e hash quando útil. Redija segredos e dados pessoais, mantendo evidência privada em local aprovado.

## Correção

Prefira renderização contextual segura, APIs de DOM que tratam texto como texto, validação de schema em runtime e autorização no servidor. Remova segredos do cliente, restrinja origens e mantenha dependências e scripts de build sob controle. Prefira uma mudança pequena na causa raiz, com defesa em profundidade e privilégio mínimo. Explique impacto, compatibilidade e qualquer risco residual; evite esconder falhas por mensagens ou filtros superficiais.

## Teste de regressão

Inclua testes de componentes e API para valores válidos e inválidos, contexto HTML/atributo/URL, papéis autorizados e falhas de validação. Trave versões, revise alterações de lockfile e execute a suíte em CI. Compare caso permitido e caso negado, limites e erro. Use dados sintéticos determinísticos, não dependa de rede pública e confirme que a correção não desabilita funcionalidade legítima.

## Limites

Escaping apropriado depende do contexto e da biblioteca. Um teste unitário isolado não cobre o bundle ou a política implantada; confirme a saída efetiva sem usar conteúdo nocivo real. Trate resultado como válido apenas para escopo, versão e configuração observados. Falta de alerta não comprova ausência de risco; uma declaração do sistema também não comprova sua imposição.

## Fontes

- https://developer.mozilla.org/en-US/docs/Web/Security
- https://cheatsheetseries.owasp.org/

Revise as fontes oficiais no momento da implementação: versões, defaults e recomendações podem mudar. Esta nota é material de referência local, não certificação nem substituto de revisão humana.
