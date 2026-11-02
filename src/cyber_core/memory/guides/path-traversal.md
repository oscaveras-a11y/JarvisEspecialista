# Acesso seguro a arquivos e caminhos

Esta referência serve à revisão e à correção de software próprio ou explicitamente autorizado. Ela não contém alvos, credenciais, instruções de exploração ou automação ofensiva. Use fixtures inventadas, ambiente isolado e autorização verificável; interrompa a atividade se o escopo não estiver claro.

## Objetivo

Um caminho fornecido externamente pode escapar da área pretendida após normalização, links simbólicos, diferenças de separador ou corrida entre checagem e uso. A regra deve ser aplicada ao caminho efetivo, com API e permissões adequadas.

## Como revisar

Procure concatenação de diretório e nome enviado, checagem por prefixo textual, decodificação repetida, symlinks, extração de arquivos e operações que aceitam caminho absoluto. Faça o percurso de ponta a ponta e registre premissas, fronteiras e controles existentes. Confirme o comportamento no código e na configuração, não apenas no nome da função ou no contrato.

## Evidências

Em fixture temporária, teste nomes válidos e inválidos não destrutivos e inspecione destino canônico. Considere Windows e Unix, caminhos relativos, links e concorrência; não leia arquivos externos ao laboratório. Preserve apenas o necessário para reproduzir a conclusão: versão, local do código, condição, resultado e hash quando útil. Redija segredos e dados pessoais, mantendo evidência privada em local aprovado.

## Correção

Mapeie IDs lógicos para nomes internos, use diretório base controlado e resolução segura com checagem de contenção por componentes. Evite seguir links não confiáveis e aplique permissões mínimas. Prefira uma mudança pequena na causa raiz, com defesa em profundidade e privilégio mínimo. Explique impacto, compatibilidade e qualquer risco residual; evite esconder falhas por mensagens ou filtros superficiais.

## Teste de regressão

Crie testes multiplataforma para separadores, nomes absolutos, symlink controlado, normalização e arquivo válido. Verifique que rejeições não alterem arquivos e que erros sejam genéricos. Compare caso permitido e caso negado, limites e erro. Use dados sintéticos determinísticos, não dependa de rede pública e confirme que a correção não desabilita funcionalidade legítima.

## Limites

Prefixo textual não é prova de contenção. A semântica varia por sistema de arquivos e corrida; escolha API que mantenha operações relativas a descritor quando disponível. Trate resultado como válido apenas para escopo, versão e configuração observados. Falta de alerta não comprova ausência de risco; uma declaração do sistema também não comprova sua imposição.

## Fontes

- https://cwe.mitre.org/data/definitions/22.html
- https://cheatsheetseries.owasp.org/

Revise as fontes oficiais no momento da implementação: versões, defaults e recomendações podem mudar. Esta nota é material de referência local, não certificação nem substituto de revisão humana.
