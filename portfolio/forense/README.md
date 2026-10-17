# Forense digital

Trilha de **perícia digital** — a área mais alinhada a carreiras em polícia científica, perícia criminal e defesa. Forense é sobre **preservar, analisar e documentar** evidências digitais de forma que resistam a escrutínio técnico e legal.

## Subáreas de estudo

- **Análise de memória (RAM):** processos, conexões e artefatos voláteis (ex.: Volatility).
- **Análise de disco:** sistemas de arquivos, arquivos apagados, metadados, linha do tempo (ex.: Autopsy, Sleuth Kit).
- **Análise de logs:** correlação de eventos, reconstrução de incidentes.
- **Cadeia de custódia:** registro de quem teve acesso à evidência, quando e como.

## Cadeia de custódia (conceito-chave)

Uma evidência só tem valor se for possível provar que **não foi alterada**. Isso exige:

- **Hash** (ex.: SHA-256) do original e das cópias, para comprovar integridade.
- **Cópias de trabalho** — nunca se analisa o original diretamente.
- **Registro** de data/hora (UTC), origem, responsável e cada operação feita.
- **Armazenamento protegido**, fora de repositórios públicos (ver `.gitignore` e [../docs/etica-e-escopo.md](../docs/etica-e-escopo.md)).

> Nunca versionar evidências reais neste repositório. Aqui ficam apenas **estudos, anotações e exercícios** com dados sintéticos ou de treino.

## O que virá

Conforme eu avançar: guias práticos de cada ferramenta, exercícios com imagens de treino e um checklist de cadeia de custódia.
