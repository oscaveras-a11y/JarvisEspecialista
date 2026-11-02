# Python seguro

Esta referência serve à revisão e à correção de software próprio ou explicitamente autorizado. Ela não contém alvos, credenciais, instruções de exploração ou automação ofensiva. Use fixtures inventadas, ambiente isolado e autorização verificável; interrompa a atividade se o escopo não estiver claro.

## Objetivo

Em Python, a segurança depende de como dados externos atravessam bibliotecas, sistema de arquivos, processos e serialização. Prefira APIs explícitas, tipos e validações próximas ao limite de entrada; não trate anotações de tipo ou validações da interface como controles de segurança.

## Como revisar

Revise subprocessos, desserialização, construção de SQL, caminhos derivados de entrada, carregamento dinâmico, desativação de verificação TLS e configuração por ambiente. Verifique versões e opções reais da biblioteca, incluindo defaults que variam entre plataformas. Faça o percurso de ponta a ponta e registre premissas, fronteiras e controles existentes. Confirme o comportamento no código e na configuração, não apenas no nome da função ou no contrato.

## Evidências

Para cada suspeita, trace origem, transformações, sanitização e destino. Demonstre em testes com fixtures locais e entradas inofensivas; confirme se o caminho é alcançável e quais privilégios do processo se aplicam. Guarde hashes ou metadados em vez de valores secretos. Preserve apenas o necessário para reproduzir a conclusão: versão, local do código, condição, resultado e hash quando útil. Redija segredos e dados pessoais, mantendo evidência privada em local aprovado.

## Correção

Use argumentos separados em APIs de subprocesso, queries parametrizadas, formatos de dados seguros, diretórios controlados, timeouts e limites de tamanho. Trate erros de forma específica e mantenha dependências atualizadas dentro de uma política de compatibilidade. Prefira uma mudança pequena na causa raiz, com defesa em profundidade e privilégio mínimo. Explique impacto, compatibilidade e qualquer risco residual; evite esconder falhas por mensagens ou filtros superficiais.

## Teste de regressão

Automatize testes para entradas vazias, malformadas, excessivas e válidas, além de regressões de permissão e comportamento multiplataforma. Execute ferramentas de análise e auditoria de dependências em CI, mas revise cada alerta no contexto. Compare caso permitido e caso negado, limites e erro. Use dados sintéticos determinísticos, não dependa de rede pública e confirme que a correção não desabilita funcionalidade legítima.

## Limites

A documentação de segurança da linguagem enumera perigos conhecidos, não substitui a revisão do desenho. Um padrão suspeito pode ser seguro em contexto limitado; uma ausência de alerta não prova segurança. Trate resultado como válido apenas para escopo, versão e configuração observados. Falta de alerta não comprova ausência de risco; uma declaração do sistema também não comprova sua imposição.

## Fontes

- https://docs.python.org/3/library/security_warnings.html
- https://cheatsheetseries.owasp.org/

Revise as fontes oficiais no momento da implementação: versões, defaults e recomendações podem mudar. Esta nota é material de referência local, não certificação nem substituto de revisão humana.
