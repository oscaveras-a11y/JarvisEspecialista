# Desserialização e formatos de dados

Esta referência serve à revisão e à correção de software próprio ou explicitamente autorizado. Ela não contém alvos, credenciais, instruções de exploração ou automação ofensiva. Use fixtures inventadas, ambiente isolado e autorização verificável; interrompa a atividade se o escopo não estiver claro.

## Objetivo

Desserializar dados não confiáveis pode instanciar tipos inesperados, consumir recursos ou acionar comportamentos especiais. Prefira formatos de dados simples e esquemas explícitos; integridade criptográfica não torna um formato perigoso seguro.

## Como revisar

Procure carregadores que reconstroem objetos arbitrários, formatos legados, polimorfismo irrestrito, validação depois da instanciação e entradas sem limite de profundidade, tamanho ou quantidade. Faça o percurso de ponta a ponta e registre premissas, fronteiras e controles existentes. Confirme o comportamento no código e na configuração, não apenas no nome da função ou no contrato.

## Evidências

Inspecione API e formato aceito e use amostras sintéticas benignas e limitadas. Confirme classes instanciadas, limites e comportamento com dado inválido sem efeitos externos. Preserve apenas o necessário para reproduzir a conclusão: versão, local do código, condição, resultado e hash quando útil. Redija segredos e dados pessoais, mantendo evidência privada em local aprovado.

## Correção

Use parser seguro de dados primitivos, allowlist de schemas e tipos, limites de profundidade/tamanho e validação antes de uso. Remova formatos perigosos legados e evite carregar objetos de origem não verificada. Prefira uma mudança pequena na causa raiz, com defesa em profundidade e privilégio mínimo. Explique impacto, compatibilidade e qualquer risco residual; evite esconder falhas por mensagens ou filtros superficiais.

## Teste de regressão

Cubra schema válido, campos desconhecidos, tipos errados, grandes quantidades e limites de aninhamento com fixtures pequenas. Verifique rejeição previsível e nenhum efeito colateral. Compare caso permitido e caso negado, limites e erro. Use dados sintéticos determinísticos, não dependa de rede pública e confirme que a correção não desabilita funcionalidade legítima.

## Limites

Assinatura ou canal autenticado demonstra origem/integridade sob certas premissas, não segurança de objetos. Revise bibliotecas e configurações concretas. Trate resultado como válido apenas para escopo, versão e configuração observados. Falta de alerta não comprova ausência de risco; uma declaração do sistema também não comprova sua imposição.

## Fontes

- https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/

Revise as fontes oficiais no momento da implementação: versões, defaults e recomendações podem mudar. Esta nota é material de referência local, não certificação nem substituto de revisão humana.
