# Uso seguro de criptografia aplicada

Esta referência serve à revisão e à correção de software próprio ou explicitamente autorizado. Ela não contém alvos, credenciais, instruções de exploração ou automação ofensiva. Use fixtures inventadas, ambiente isolado e autorização verificável; interrompa a atividade se o escopo não estiver claro.

## Objetivo

Criptografia protege propriedades específicas quando algoritmo, modo, chaves, nonces, contexto e ciclo de vida estão corretos. Prefira bibliotecas mantidas e construções autenticadas de alto nível a combinações próprias de primitivas.

## Como revisar

Revise algoritmos legados, modo sem autenticação, nonce repetido, chave embutida, gerador fraco, validação TLS desligada, comparação variável e ausência de rotação ou separação de finalidade. Faça o percurso de ponta a ponta e registre premissas, fronteiras e controles existentes. Confirme o comportamento no código e na configuração, não apenas no nome da função ou no contrato.

## Evidências

Registre algoritmo e configuração sem revelar chave. Use vetores de teste oficiais e dados sintéticos para validar integridade, rejeição de alteração e tratamento de chave. Confirme versão e parâmetros efetivamente ativos. Preserve apenas o necessário para reproduzir a conclusão: versão, local do código, condição, resultado e hash quando útil. Redija segredos e dados pessoais, mantendo evidência privada em local aprovado.

## Correção

Use API de alto nível com AEAD para novos dados, geração criptográfica de aleatoriedade, armazenamento de chave protegido e rotação planejada. Separe chaves por finalidade e não invente protocolo próprio. Prefira uma mudança pequena na causa raiz, com defesa em profundidade e privilégio mínimo. Explique impacto, compatibilidade e qualquer risco residual; evite esconder falhas por mensagens ou filtros superficiais.

## Teste de regressão

Teste round-trip, rejeição de ciphertext modificado, nonce e parâmetros requeridos, rotação e migração. Inclua casos de erro e teste as configurações de TLS sem desativar validação. Compare caso permitido e caso negado, limites e erro. Use dados sintéticos determinísticos, não dependa de rede pública e confirme que a correção não desabilita funcionalidade legítima.

## Limites

Criptografia não corrige controle de acesso, endpoint comprometido ou má gestão de chave. Adequação depende do modelo de ameaça e das recomendações atuais do ecossistema. Trate resultado como válido apenas para escopo, versão e configuração observados. Falta de alerta não comprova ausência de risco; uma declaração do sistema também não comprova sua imposição.

## Fontes

- https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/

Revise as fontes oficiais no momento da implementação: versões, defaults e recomendações podem mudar. Esta nota é material de referência local, não certificação nem substituto de revisão humana.
