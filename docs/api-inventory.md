# Inventário OpenAPI para preparação de pentest

O Jarvis lê uma descrição OpenAPI JSON e cruza rotas declaradas com uma autorização
HTTPS independente. Essa etapa não envia requisições, não autentica e não confirma
vulnerabilidades. O estágio `api` continua sem executor; `api_inventory` registra
cobertura `inventoried`, nunca `exercised`.

## Preparação e execução

Use o ambiente Python já preparado para o projeto (`python -m pip install .`).
Não há dependência externa nova. Na fase atual, executar apenas no GitHub com
amostras sintéticas; comandos abaixo documentam a operação posterior autorizada.

Registre a investigação pelo fluxo existente e coloque os arquivos dentro do escopo.
A autorização é o mesmo JSON v1 de [web-probe.md](web-probe.md), com origem HTTPS,
até oito caminhos explícitos, declaração de autorização e validade futura.

```text
cyber --home STORAGE api-inventory CASE api.json --grant grant.json
cyber --home STORAGE api-inventory CASE api.json --grant grant.json --max-bytes 1048576 --max-operations 64 --output-bytes 131072 --seconds 30
```

Manifesto de campanha, com referências por basename no mesmo diretório:

```json
{"version":1,"stages":["api_inventory"],"api_spec":"api.json","web_grant":"grant.json","seconds":30}
```

```text
cyber --home STORAGE pentest create CASE campaign.json
cyber --home STORAGE pentest run CASE CAMPAIGN
cyber --home STORAGE pentest show CASE CAMPAIGN
cyber --home STORAGE report CASE
```

Para observar respostas de uma API, o operador pode incluir separadamente
`https_probe` na campanha. Ele fará GET somente nos caminhos explícitos da
autorização; não seleciona nem expande rotas a partir da especificação. Não existe
nesta entrega comparação automática de respostas com schemas.

## Resultado e interpretação

- Métodos declarados, caminho, mapeamento de servidor e indicação de GET elegível.
- Herança de segurança por operação: `declared_required`, `declared_anonymous`
  ou `unknown`. Trata-se da declaração do documento, não de autenticação testada.
- Precedência de servidor: operação, path item, documento; ausência equivale a
  servidor relativo `/`. A origem da autorização é a base explícita da análise
  offline, não a URL de origem do arquivo.
- URLs externas, servidores múltiplos/variáveis e formatos não suportados não
  ampliam autorização. Templates exigem binding explícito ainda não implementado.
- SHA-256 dos dois arquivos, parâmetros, versão do analisador/Python, auditoria,
  recibo da campanha e retomada sem repetir estágio já publicado.
- Alteração dos arquivos originais, pausa e revogação bloqueiam nova execução.
- Exemplos, descrições, valores e configurações de credenciais não são exportados.
  Caminhos e metadados podem ser sensíveis; relatórios não são publicação pública.
  A aquisição existente preserva a cópia original no armazenamento do caso.

## Limites e pendências

Suporte parcial a OpenAPI 3.0.x e 3.1.x em JSON UTF-8, até 1 MiB; profundidade 32,
50 mil nós JSON, 4096 path items, 128 operações (64 por padrão), 16 referências
locais encadeadas e saída até 128 KiB. Campos desconhecidos não recebem validação
completa de schema. Versão não suportada retorna `unsupported`; omissões e campos
não interpretados relevantes retornam flags e estado `partial`.
Orçamento de parsing é cooperativo; a aquisição CORE anterior tem seus próprios
limites e não integra um prazo total rígido de parede.

Referências locais são resolvidas somente em path items. Referências remotas,
siblings de $ref, webhooks, callbacks, parâmetros, schemas de resposta e detalhes
OAuth não são plenamente interpretados. YAML e OpenAPI 2/3.2 não suportados.
Não há geração de payload, execução de POST/PUT/DELETE, teste de login,
autorização entre contas, descoberta de BOLA/IDOR, ZAP/Semgrep ou análise SCA.
GET elegível não significa ausência de efeitos colaterais.

Revisão registrou uma limitação menor: urlsplit normaliza TAB/CR/LF em uma URL de
servidor antes do filtro; um servidor malformado pode receber mapeamento válido.
Não provoca requests nem amplia os caminhos da autorização. Endurecimento adicional
dessa validação ficou pendente para revisão explícita.

## Verificação

```text
python scripts/run-tests.py test_api_inventory.py
python scripts/run-tests.py
```

Workflow `OpenAPI inventory`: Linux e Windows, fixtures sintéticas, CLI real,
SQLite/auditoria real e regressões; integração HTTPS sintética já existente
executa apenas no Linux. Sem especificação privada ou credenciais em logs/artefatos.

Referência de semântica: [OpenAPI 3.1.0](https://github.com/OAI/OpenAPI-Specification/blob/main/versions/3.1.0.md).
