# Varredura YARA (item 9 — vulnerabilidades)

Correspondência de assinaturas estática, opcional, sobre uma amostra autorizada.
Não executa o arquivo analisado, não varre rede nem host, não extrai nada.
O conteúdo correspondido (os bytes que casaram com a regra) **nunca** sai do
módulo `cyber_core.vulnerability.yara_scan`: o resultado só expõe nome da
regra, tags, meta e o **offset** das strings casadas — nunca o valor em si.
Isso preserva a mesma postura de `audit_config` (item 9 existente): uma string
YARA pode casar justamente com uma senha ou chave presente na amostra, então
o trecho correspondido não pode vazar pelo achado, pela auditoria ou pelo
relatório.

## Configuração

Caminho de regras é configuração confiável do operador, nunca derivado da
evidência, de uma amostra ou de resposta de agente — mesmo padrão de
`--ghidra-home`/`--binwalk-executable`:

```
cyber --yara-rules /trusted/rules.yar scan-yara CASO ARQUIVO
cyber --yara-rules /trusted/rules_dir/ scan-yara CASO ARQUIVO --max-sample 1048576 --yara-timeout 10
```

Aceita um arquivo `.yar`/`.yara` único ou um diretório (percorrido recursivamente
por `.yar`/`.yara`). Link simbólico no caminho de regras ou em qualquer arquivo
dentro do diretório é recusado. Teto de 8 MiB agregados e 256 arquivos de regra.

## Dependência opcional

Usa a biblioteca `yara-python` (binding oficial do YARA, BSD), instalada com
o extra `vulnerability`:

```
pip install ".[vulnerability]"
```

Sem a dependência instalada, `scan-yara` responde `status: dependency_unavailable`
em vez de falhar — mesmo padrão do Capstone opcional em `reverse_engineering`.
Diferente de Ghidra/Binwalk, não há binário externo nem subprocesso: a
correspondência roda no próprio processo supervisionado, com o timeout nativo
do YARA (`rules.match(data=..., timeout=...)`), limitado a 120s por chamada.

## Limites e resultado

- Amostra: até 16 MiB, com `sample_truncated` reportado quando o arquivo
  excede o teto pedido.
- Até 256 achados por chamada, 64 strings por achado, 64 offsets por string;
  cada nível sinaliza seu próprio truncamento (`truncated`, `strings_truncated`,
  `offsets_truncated`).
- `status`: `completed`, `timeout`, `dependency_unavailable`. Um erro de
  sintaxe na regra configurada levanta erro explícito na configuração, não
  um falso "sem achados".
- Persistido em `side_analyses` (kind `yara_scan`) e no relatório da
  investigação, igual às demais análises estáticas do item 9.

## Limites declarados

Correspondência por assinatura é indício, não prova de comportamento malicioso.
Não há varredura ativa, sandbox dinâmica nem análise de comportamento — apenas
o que a regra YARA já reconhece estaticamente nos bytes autorizados.
