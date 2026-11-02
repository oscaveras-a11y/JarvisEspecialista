# Memória local de programação segura para Qwen3

**Estado:** proposta para aprovação do proprietário  
**Data:** 2026-11-02  
**Base examinada:** `main` em `d7218fbfde77097dac79e3d490efa16cd978ec98`

## Intenção

Permitir que o Jarvis consulte uma biblioteca local, pequena e revisável sobre programação segura e passe trechos pertinentes à Qwen3 local antes de responder. O objetivo é melhorar respostas de revisão e correção de código no computador do proprietário, sem retreinar pesos nem modificar o perfil padrão do Ollama.

A expressão “locais frágeis de invadir” será tratada como pontos de código que merecem revisão defensiva: entradas, validação, autenticação/autorização, limites de confiança e tratamento de segredos. A memória orienta a localizar e corrigir falhas em código/laboratório autorizado.

## Estado encontrado

- `src/cyber_core/memory/__init__.py` cria o banco SQLite operacional e mantém registros/auditoria.
- `Core.recall_by_hash` e `Core.recall_by_type` recuperam casos anteriores; não existe busca de conhecimento de programação.
- Não há cliente de chat Ollama/Qwen3 no pacote atualmente.
- A memória de conhecimento deve ficar separada do banco de casos para evitar migração da versão global do SQLite e mistura com evidências de operação.

## Abordagens consideradas

1. Arquivos Markdown com busca por palavras: simples, mas não fornece ranking consistente nem conecta a busca com a chamada de modelo.
2. SQLite FTS5 + cliente Ollama local: busca textual eficiente, sem outro modelo de embeddings ou dependências pesadas; contexto e fontes podem ser enviados na mesma chamada local. **Escolhida.**
3. Banco vetorial/embeddings: busca semântica potencialmente útil, mas exige outro modelo/dependências, mais RAM e administração, desnecessários para a primeira versão e para o Qwen3 1.7B disponível.

## Escopo da primeira versão

- Biblioteca pequena de guias revisáveis, distribuída como Markdown versionado; índice FTS5 é derivado e reconstruível. Tópicos iniciais: SQL parametrizado; injeção de comandos e APIs seguras de subprocesso; escape contextual/CSP para XSS; autenticação e autorização por requisição; segredos e configuração; dependências vulneráveis; serviços expostos; validação/armazenamento de uploads; revisão e testes de regressão.
- Cada guia identifica título, tópico, versão/data, proveniência e referências. Conteúdo foca sinais para localizar no código, evidências mínimas, impacto, mitigação e testes corretivos.
- Comando de indexação e busca; comando opcional `cyber ask` que recupera poucos trechos, monta contexto com fonte e consulta o endpoint de chat do Ollama. O modelo é configurável, com `qwen3:1.7b` como exemplo/documentação, não hardcoded.
- Cliente HTTP da biblioteca padrão, somente loopback IPv4/IPv6 e porta local configurada; sem ferramenta, execução de código, navegação ou chamada a host remoto. Entrada do usuário não é gravada automaticamente.
- Prompt separa instruções do usuário dos documentos recuperados, trata material recuperado como referência inerte e pede citação das fontes; sem contexto suficiente, a resposta deve dizer isso.
- O índice é local e derivado. Guias públicos/genéricos podem ficar versionados; banco local, código do usuário, respostas e evidências não entram no Git, logs ou CI.
- Avaliação sintética separada por tópico, com rubrica para identificar evidência, precisão, correção, citação e segurança. Validar resposta gerada é distinto de medir perda de treino.

## Fora do escopo

- Alterar os pesos do Qwen3, importar ou adotar o adaptador experimental, ou prometer que o código ficará sem erros.
- Senhas, credential stuffing, quebra de credenciais, instruções de invasão, exploração de sites reais ou execução de payloads.
- Coletar ou indexar automaticamente repositórios/código privado, guardar conversas sem pedido explícito, buscar conteúdo na internet ou enviar dados fora de localhost.
- Fazer merge ou instalar/executar o produto no computador do proprietário nesta entrega.

## Critérios de aceitação propostos

1. Guias podem ser indexados/reindexados de modo determinístico, e a busca apresenta trechos e fontes corretas com limite de resultados/contexto.
2. Uma pergunta sintética sobre cada tópico recupera material pertinente; consulta sem resultado não inventa fonte.
3. `cyber ask` envia apenas prompt/contexto limitado ao endpoint local configurado, preserva citações e nunca ativa ferramentas de ataque.
4. Testes usam servidor Ollama falso e conteúdo sintético no GitHub Actions; verificam loopback, limites, ausência de persistência de prompt/evidência e regressões.
5. Documentação explica ativação local pelo proprietário e deixa claro que o CI não prova inferência com o modelo Qwen3 instalado.
6. Branch e PR ficam separados; nenhum merge sem autorização explícita.

## Decisões deixadas ao implementador

- Omitir embeddings e usar FTS5 por simplicidade, baixo consumo e reprodutibilidade.
- Manter os guias fonte em arquivos legíveis e a base SQLite como cache local reconstruível.
- Tratar Qwen3/Ollama como cliente opcional; se Ollama não responder no loopback, falhar com orientação clara sem trocar de modelo.
- Limitar tamanho de documento, quantidade de trechos e tamanho do prompt, sem afirmar quotas rígidas de SSD/RAM.

## Limitações e risco residual

FTS5 depende de suporte no SQLite da plataforma; a inicialização precisa detectar ausência e informar indisponibilidade. Busca lexical pode deixar de encontrar sinônimos; isso pode ser avaliado e melhorado depois sem trocar o banco. Modelo pequeno pode ignorar referências, errar código ou produzir falsos positivos. Recuperação de contexto melhora disponibilidade de referências, não inteligência geral nem segurança garantida. CI valida integração com servidor falso; o proprietário ainda precisará testar manualmente com a instalação Ollama local antes de ativar no Jarvis.
