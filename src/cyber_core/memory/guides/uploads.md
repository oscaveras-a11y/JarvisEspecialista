# Upload e processamento de arquivos

Esta referência serve à revisão e à correção de software próprio ou explicitamente autorizado. Ela não contém alvos, credenciais, instruções de exploração ou automação ofensiva. Use fixtures inventadas, ambiente isolado e autorização verificável; interrompa a atividade se o escopo não estiver claro.

## Objetivo

Upload combina entrada não confiável, armazenamento e parsers complexos. Trate nome, extensão, MIME declarado, conteúdo e metadados como dados separados; não execute arquivos enviados nem confie em uma única verificação.

## Como revisar

Examine destino dentro da raiz pública, nomes controlados, sobrescrita, tamanho sem limite, parser permissivo, arquivo temporário previsível e associação automática de extensão a execução. Faça o percurso de ponta a ponta e registre premissas, fronteiras e controles existentes. Confirme o comportamento no código e na configuração, não apenas no nome da função ou no contrato.

## Evidências

Use arquivos sintéticos inofensivos em ambiente isolado e confira caminho final, permissões, validações e fluxo de download. Registre tipo detectado e resultado sem guardar conteúdo privado desnecessário. Preserve apenas o necessário para reproduzir a conclusão: versão, local do código, condição, resultado e hash quando útil. Redija segredos e dados pessoais, mantendo evidência privada em local aprovado.

## Correção

Gere nomes internos, armazene fora da raiz executável, limite tamanho e tipos necessários, valide conteúdo com parser seguro e mantenha quarentena até análise. Sirva como download com cabeçalhos apropriados e acesso autorizado. Prefira uma mudança pequena na causa raiz, com defesa em profundidade e privilégio mínimo. Explique impacto, compatibilidade e qualquer risco residual; evite esconder falhas por mensagens ou filtros superficiais.

## Teste de regressão

Cubra arquivo válido, extensão divergente, tamanho limite, nome estranho e conteúdo malformado em fixtures benignas. Confirme isolamento, ausência de execução e limpeza de temporários. Compare caso permitido e caso negado, limites e erro. Use dados sintéticos determinísticos, não dependa de rede pública e confirme que a correção não desabilita funcionalidade legítima.

## Limites

MIME e magic bytes podem estar errados ou ser ambíguos. Antivírus não substitui isolamento e validação; arquivos legítimos complexos também podem explorar bugs do parser. Trate resultado como válido apenas para escopo, versão e configuração observados. Falta de alerta não comprova ausência de risco; uma declaração do sistema também não comprova sua imposição.

## Fontes

- https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/

Revise as fontes oficiais no momento da implementação: versões, defaults e recomendações podem mudar. Esta nota é material de referência local, não certificação nem substituto de revisão humana.
