# Linha do tempo de firmware (offline)

O comando lê observações fornecidas em JSONL. Não acessa dispositivos, não executa firmware, não coleta logs remotos e não conclui fraude.

## Preparação e execução

Sem ferramentas extras: instalação Python habitual do projeto. Desenvolvimento/testes desta entrega somente nos runners GitHub; instalação no computador fica para a etapa autorizada futura.

Registre uma investigação pelo fluxo existente:
```text
cyber --home STORAGE investigate --project laboratorio --objective "Linha do tempo" --scope EVIDENCE_DIRECTORY --owner RESPONSAVEL --authorization "Evidências sintéticas locais"
cyber --home STORAGE firmware-timeline CASE_ID EVIDENCE_DIRECTORY/events.jsonl --max-events 10000 --max-findings 128 --max-seconds 30
cyber --home STORAGE report CASE_ID
```

A autorização precisa estar vigente; pausa, revogação e cancelamento são verificados pelo CORE e durante a leitura. O resultado e a aquisição verificada são persistidos com SHA-256, parâmetros, versão do analisador e Python. Reexecutar faz nova operação; não há checkpoint por evento. Pausa não garante interrupção instantânea de uma leitura de disco já iniciada.

## Formato v1

UTF-8, um objeto por linha. Campos obrigatórios: id globalmente único, device, component, source, time ISO-8601 com fuso, kind. Identificadores/textos têm até 128 caracteres, sem controles. kind: measurement, update, access, boot, log_gap. Campos opcionais: sha256, sequence (inteiro não negativo), uncertainty_ms (0 a 86400000), actor. measurement exige SHA-256 hexadecimal de 64 caracteres. Campos desconhecidos, IDs/chaves duplicados, JSON truncado e valores inválidos são rejeitados.

Exemplo sintético de uma observação:
```json
{"id":"sample-1","device":"synthetic-device","component":"main","source":"synthetic-log","time":"2026-01-01T00:00:01Z","kind":"measurement","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sequence":1,"uncertainty_ms":100}
```

component deve identificar a MESMA região/domínio de medição entre observações. Cabe ao procedimento de coleta distinguir arquivo, firmware instalado e firmware em execução. Valores importados e nomes de fontes são declarações não autenticadas. SHA-256 da entrada prova identidade dos bytes adquiridos, não veracidade histórica.

## Interpretação

Agrupa medidas por device/component, normaliza fusos e procura A/B/A entre mudanças consecutivas de fingerprint. Medições repetidas mantêm a observação mais recente do mesmo valor. Só afirma a ordem quando os intervalos declarados de incerteza não se sobrepõem; ambiguidade interrompe a sequência. As três referências de eventos, linhas, fontes e hashes são registradas.

Update/access/boot contextualizam a linha do tempo, mas não provam troca. Lacunas de sequência, reversões de sequência/horário e log_gap são alertas de qualidade, não provas de adulteração. Sequências são comparadas na ordem de entrada por source/device/component; concatenar arquivos fora de ordem pode gerar esses alertas. Incerteza padrão zero significa somente que o arquivo não declarou margem, não que o relógio foi validado.

O relatório separa achados sobre os registros, hipóteses e pendências. Todas as execuções retornam insufficient_to_determine_fraud: não existe critério suficiente neste módulo para uma decisão de fraude/autoria/impacto eleitoral. A/B/A observado não autentica o equipamento. Somente original no fim não exclui troca temporária.

## Recursos e limites

Entrada até 16 MiB e 10000 eventos, linha até 64 KiB (padrão 16 KiB), até 128 padrões e 128 eventos de prévia. Entradas excedentes falham explicitamente; resultados omitidos são contados. Orçamento temporal cooperativo até 300 s, limitado também pelo timeout do CORE. O parser lê por linhas; aquisição do CORE mantém uma cópia verificada e o adaptador materializa uma entrada limitada a 16 MiB. Não é o leitor de firmware grande: os binários continuam no fluxo de análise estática existente.

Não valida assinaturas de logs/atestação, identidade de fontes, relógios reais, cobertura contínua, equivalência de domínios, nem lê formatos proprietários de equipamentos. Não há análise efetiva de eleição, urna, VisionFT ou outro dispositivo real nesta entrega.

## Testes

```text
python scripts/run-tests.py test_firmware_timeline.py
python scripts/run-tests.py
```

Workflow firmware-timeline.yml executa os testes e regressões offline em Linux e Windows, com fixtures sintéticas em diretórios temporários, sem upload de evidências.
