# Análise CAN estritamente offline

`cyber_core.automotive.analyze_can(path, *, max_bytes=16777216,
max_frames=100000)` e `compare_can(first, second, *, max_bytes=16777216,
max_frames=100000)` leem arquivos regulares, retornam dicionários serializáveis
e não alteram os arquivos. Não abrem barramento, não transmitem e não diagnosticam
compatibilidade de ECU/TCU.

Formato aceito: log compacto candump ASCII, uma linha por frame clássico de dados:
`(1.000001) can0 123#AABB`. Timestamp não negativo com exatamente seis casas
decimais e até 16 dígitos na parte inteira; canal de 1–64 caracteres alfanuméricos
ou `_ . : -`; ID de exatamente três dígitos (0–7FF) ou oito (0–1FFFFFFF),
preservando a identidade standard/extended. Payload hexadecimal sem separadores,
com 0–8 bytes. LF/CRLF e arquivo sem newline final são aceitos. Linhas vazias são
ignoradas. Não há detecção automática de CSV ou outros formatos.

Frames remotos (`#R`), CAN FD (`##`), error flags, CAN XL, DLC estendido (`_`),
payloads com pontos, comentários e quaisquer registros malformados são rejeitados
com `CoreError` e número da linha quando disponível. Toda a análise falha: não há
retorno parcial que esconda frames perdidos. Um último registro completo sem
newline é válido; bytes removidos que ainda formem outro registro válido não
podem ser detectados sem evidência externa.

Os limites são positivos inteiros: até 16 MiB e 100 mil frames por arquivo por
padrão, incluindo cada arquivo de uma comparação. Leitura limitada a max_bytes+1;
todos os registros e distribuições ficam limitados por esses tetos. Oito amostras
distintas de payload por stream; as contagens completas de payload e comprimento
são preservadas. Para frames clássicos aceitos, DLC equivale ao comprimento.

Cada stream é identificado por canal e ID formatado. Intervalos são calculados
em microssegundos inteiros antes da conversão. Timestamps não decrescentes permitem
estatísticas; duplicatas contam separadamente e geram intervalo zero. Qualquer
regressão no stream desativa suas estatísticas de intervalo, duração e taxa.
Jitter significa `max(intervalo)-min(intervalo)`, em segundos. Taxa observada é
`(contagem-1)/(último-primeiro)`, indefinida com duração zero ou frame único.
Nenhuma taxa implica carga de barramento ou frequência configurada no equipamento.

A comparação apresenta streams comuns e exclusivos de cada arquivo, contagens,
diferença de taxa quando definida e mudanças na distribuição normalizada de
payloads, por multiplicação cruzada inteira. Não alinha relógios nem agrupa IDs
de canais diferentes. Diferenças observadas não demonstram causa de defeito.

Referência primária de formato: [linux-can/can-utils lib.c](https://github.com/linux-can/can-utils/blob/master/lib.c),
funções `parse_canframe` e formatação compacta; [README](https://github.com/linux-can/can-utils/blob/master/README.md)
descreve candump como ferramenta de logs. Esta implementação usa o subconjunto
explícito acima e não replica todos os formatos aceitos pelas ferramentas upstream.
