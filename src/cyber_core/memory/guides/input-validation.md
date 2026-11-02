# Validação de entradas

Esta referência serve à revisão e à correção de software próprio ou explicitamente autorizado. Ela não contém alvos, credenciais, instruções de exploração ou automação ofensiva. Use fixtures inventadas, ambiente isolado e autorização verificável; interrompa a atividade se o escopo não estiver claro.

## Objetivo

Valide cedo, no limite de confiança, e represente os dados com formatos explícitos: tipo, tamanho, faixa, codificação e gramática permitida. Validação de entrada reduz estados inesperados, mas não substitui codificação de saída, parametrização ou autorização.

## Como revisar

Procure conversões permissivas, limites ausentes, validação só no browser, normalização feita depois da checagem, listas de bloqueio frágeis e divergência entre componentes sobre Unicode, separadores ou codificações. Faça o percurso de ponta a ponta e registre premissas, fronteiras e controles existentes. Confirme o comportamento no código e na configuração, não apenas no nome da função ou no contrato.

## Evidências

Documente a regra esperada e teste entradas válidas, inválidas e de fronteira com casos sintéticos. Verifique o valor após normalização e o valor efetivamente usado pelo destino. Registre decisão e motivo sem armazenar conteúdo sensível bruto. Preserve apenas o necessário para reproduzir a conclusão: versão, local do código, condição, resultado e hash quando útil. Redija segredos e dados pessoais, mantendo evidência privada em local aprovado.

## Correção

Use allowlists de formato quando apropriado, parsers reconhecidos, limites de bytes e caracteres, normalização canônica definida e rejeição explícita de dados inválidos. Diferencie ausência, vazio e valor padrão; não corrija silenciosamente dados ambíguos. Prefira uma mudança pequena na causa raiz, com defesa em profundidade e privilégio mínimo. Explique impacto, compatibilidade e qualquer risco residual; evite esconder falhas por mensagens ou filtros superficiais.

## Teste de regressão

Crie tabela de casos que cubra limites, caracteres internacionais, valores repetidos e conversões. Testes devem comprovar aceitação do formato válido e rejeição segura do inválido sem efeitos colaterais. Compare caso permitido e caso negado, limites e erro. Use dados sintéticos determinísticos, não dependa de rede pública e confirme que a correção não desabilita funcionalidade legítima.

## Limites

Nenhuma validação genérica serve para todos os campos. O contexto de uso determina a regra; restrições excessivas podem quebrar dados legítimos e devem ser justificadas. Trate resultado como válido apenas para escopo, versão e configuração observados. Falta de alerta não comprova ausência de risco; uma declaração do sistema também não comprova sua imposição.

## Fontes

- https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/

Revise as fontes oficiais no momento da implementação: versões, defaults e recomendações podem mudar. Esta nota é material de referência local, não certificação nem substituto de revisão humana.
