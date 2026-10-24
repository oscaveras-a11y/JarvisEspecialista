# Arquivos grandes — primeira etapa VisionFT

Implementação em revisão no PR #27. Padrão dos comandos existentes: 64 MiB; teto configurável: 1 GiB (1073741824 bytes). O teto percorre serviço, processo de análise e adaptador externo. Não equivale a concluir o fluxo VisionFT.

## Uso futuro em ambiente operacional privado

Preparar Python 3.12 de 64 bits e instalar o pacote como documentado no projeto. Desenvolvimento e validação desta entrega permanecem somente no GitHub. Não enviar evidências reais aos runners públicos.

Na CLI, opções globais vêm antes do subcomando:

```text
cyber --home DIRETORIO_OPERACIONAL --max-bytes 1073741824 --timeout 300 analyze-firmware ID_DO_CASO CAMINHO_ABSOLUTO
```

O caso precisa ter autorização vigente e escopo contendo o arquivo. A aquisição gera cópia verificada e persiste resultados e SHA-256 pelo CORE, sem executar o binário.

API existente:
```python
analyze_firmware(path, max_bytes=1073741824)
compare_firmware(first, second, max_bytes=1073741824)
```

## Leitura e limites

PE/ELF/BIN usam mapeamento somente leitura com fechamento determinístico; SHA-256 é calculado em chunks de 1 MiB. Comparação pula chunks iguais e mantém até 1000 ranges, como antes. Aquisição já usa chunks e verificação de cópia. O teto de entrada não aumenta limites de resultados, de tempo, de scratch ou de instruções.

O mapeamento ocupa espaço de endereçamento virtual; não significa reserva de uma cópia Python inteira. Páginas residentes/cache são controladas pelo sistema operacional. tracemalloc mede alocações Python, não RSS, árvore Java ou cache. Não há neste incremento um teto agregado rígido de RAM ou disco para todas as ferramentas.

HEX/S-record continuam limitados a 64 MiB de texto e 1 MiB decodificado por padrão; não recebem o caminho grande sem limite. O supervisor continua responsável pelo timeout/cancelamento das tarefas CORE. Chamadas diretas da API de firmware não têm timeout próprio.

Fontes devem permanecer estáveis. Stat pré/pós detecta algumas alterações; não protege contra escrita transitória por outro processo com os mesmos privilégios. O CORE analisa a cópia adquirida. Nunca tratar hash consistente como controle de acesso.

## Testes

Workflow Large synthetic inputs: Linux e Windows, arquivos sintéticos de 600 MiB e 900 MiB, PE sintético de 250 MiB, passagem de 600 MiB pelo CORE, comparação acima de 64 MiB e limites menores preservados. Nenhuma fixture proprietária é publicada.

Comandos no runner:
```text
python -m pip install ".[reverse]"
python scripts/run-tests.py test_large_inputs.py
python scripts/run-tests.py
```

O adaptador externo aceita tamanho maior para hashing/encaminhamento; Ghidra conserva limites de scratch/tempo/saída anteriores e não foi comprovado aqui em executável de 900 MiB. Esta etapa não entrega extração NSIS, COFF/QML, seletores aprofundados, variante FTW2 real ou normalização de funções. VisionFT real e descobertas DSG continuam não reproduzidos.
