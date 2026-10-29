# Testes automáticos de API em laboratório sintético

O estágio de campanha `api` executa GETs em uma API de laboratório. Não testa
sites reais. O destino é sempre `127.0.0.1`, com SNI/hostname TLS
`jarvis-api.test`; não há resolução DNS, proxy ou opção de destino externo.
O grant HTTPS v1 existente continua independente da especificação.
Somente caminhos GET declarados e exatamente autorizados podem ser executados.

## Manifestos

Crie os arquivos sintéticos no mesmo diretório autorizado do caso, dentro de
runner temporário do GitHub. Use o fluxo existente `pentest create/run/show`.
A interface CLI é a de campanhas; não existe novo comando avulso.

Campanha:
```json
{"version":1,"stages":["api"],"api_spec":"api.json","api_matrix":"matrix.json","web_grant":"grant.json","ca_file":"ca.pem","seconds":30,"body_bytes":65536}
```

Matriz independente do OpenAPI:
```json
{"version":1,"synthetic_only":true,"cases":[{"path":"/items","allowed":["alice"],"resource":"fixture-alice"}]}
```

O grant usa `origin: https://jarvis-api.test:PORTA` e caminhos estáticos explícitos;
os demais campos são os do [grant existente](web-probe.md).
A fixture HTTPS deve escutar apenas no loopback e apresentar certificado com SAN
`DNS:jarvis-api.test`, validado pelo sistema e/ou CA pública fornecida.
Chave privada efêmera fica somente no runner e nunca entra no Git, logs ou artefatos.

A matriz aceita até oito caminhos únicos presentes no grant. `allowed` contém
uma ou ambas as identidades `alice` e `bob`. `resource` deve corresponder ao campo
JSON de topo `resource` e ter formato `fixture-[a-z0-9-]{1,64}`.
Cada caminho recebe quatro GETs: alice, bob, anonymous, invalid.
O cabeçalho de laboratório é fixo `Bearer synthetic-alice`, `synthetic-bob` ou
`synthetic-invalid`; anonymous omite Authorization. São marcadores públicos de
fixture, não credenciais de operador. Nenhuma credencial externa é aceita.
Não há criação de login da aplicação nem alteração da política do beta.

## Contratos suportados e interpretação

OpenAPI JSON UTF-8 3.0.x/3.1.x; resolução/mapeamento do inventário existente.
Respostas por status exato ou `default`. Conteúdo `application/json`, sem
compressão, UTF-8, com schema explícito. Campos de schema suportados:

- `type`: object, array, string, integer, number, boolean, null;
- objetos: properties, required, additionalProperties booleano;
- arrays: items, minItems, maxItems;
- strings: minLength, maxLength;
- números: minimum, maximum;
- title/description como anotações ignoradas.

Inteiros aceitam número JSON integral como 1.0; booleano não é número.
Sem schema de corpo, registra apenas que o status está declarado.
Palavras-chave desconhecidas, refs de resposta/schema, composição, enum,
format, pattern, nullable, tipos em lista, headers de contrato, outros tipos
de mídia e parâmetros de operação não validados produzem alerta.
Não se afirma validação completa de OpenAPI/JSON Schema.

A evidência distingue:

- `declaration`: segurança declarada pelo OpenAPI; nunca prova enforcement.
- `observation`: comparação suportada satisfeita ou negação 401/403 observada.
- `alert`: contrato não suportado, corpo incompleto, conexão/TLS falhou,
  controle positivo falhou, limite de análise JSON foi excedido ou acesso ficou inconclusivo.
- `confirmed_failure`: divergência concreta do contrato suportado, ou exposição
  do recurso sintético identificado a um perfil que a matriz explicitamente nega,
  com controle positivo funcionando no mesmo conjunto de respostas.

Um HTTP 200 isolado não confirma falha de acesso. Divergência de contrato
não equivale automaticamente a vulnerabilidade de segurança. Os perfis anonymous
e invalid avaliam autenticação bearer sintética; o cruzamento alice/bob avalia
permissão para o recurso explicitamente identificado. Não há inferência de
política a partir apenas da declaração OpenAPI.

## Evidência, cancelamento e retomada

Operação `api` registra hashes dos inputs, certificado TLS, prefixo/corpo completo
por SHA-256, número de bytes, status, perfil, classificação e códigos fixos.
Não persiste corpo HTTP, headers brutos, cookies, tokens enviados, valores do
schema ou marcador de recurso no resultado. O armazenamento CORE preserva as
cópias originais dos inputs sintéticos dentro do caso, como nas outras operações.

A campanha congela spec, grant, matriz e CA por hash. Auditoria e recibo vinculam
o resultado a esses inputs e aos parâmetros. Publicação usa guard transacional
de propriedade da etapa e ciclo de vida. Pausa, revogação, mudança de input,
prazo ou perda de propriedade impedem publicação. Worker fica em subprocesso
limitado e é interrompido pelo supervisor.

Retomada adota recibo publicado sem reenviar o estágio, inclusive após falha de
publicação do checkpoint da campanha. Não há checkpoint durável por GET:
interrupção antes de publicar a operação pode repetir GETs já enviados.
GET não garante ausência de efeitos colaterais.

## Limites objetivos

Até 1 MiB de spec, oito casos/quatro perfis por caso (32 GETs), matriz 8 KiB,
CA pública 4 KiB, headers HTTP 64 KiB, corpo 64 KiB por padrão (até 1 MiB),
saída 128 KiB, até 300 s sujeito ao timeout CORE. JSON: profundidade 32 e
50 mil nós; schemas: profundidade 16 e até 256 propriedades por objeto.
O prazo supervisionado cobre o worker; aquisição CORE prévia tem orçamento próprio.

A automação `api` cobre este laboratório bearer restrito. Estágios independentes
`authentication` e `authorization` continuam indisponíveis: não há login real,
OAuth/OIDC, sessões/cookies, renovação/revogação de tokens ou testes de fluxos de
negócio. Sem templates, query, payloads, POST/PUT/PATCH/DELETE, DAST/SAST/SCA nesta
entrega. `full_pentest_completed` permanece falso, inclusive quando a matriz passa.

## Validação

Workflow `Synthetic API runtime`: testes focados e suíte completa Linux/Windows.
Integração TLS real no Linux, incluindo Core/SQLite/auditoria, matriz segura e
vulnerável, redaction, CA não confiável, falha de checkpoint, reabertura/adoção,
mutação, cancelamento durante resposta TLS bloqueada e pausa no instante da publicação. A integração TLS nova é ignorada no
Windows; testes puros e regressão completa executam nas duas plataformas.
A regressão HTTPS sintética anterior executa no Linux.

RED: [40903266960](https://github.com/oscaveras-a11y/JarvisEspecialista/actions/runs/40903266960),
seis falhas Linux por adapter ainda ausente. Evidência GREEN final no PR #34.
