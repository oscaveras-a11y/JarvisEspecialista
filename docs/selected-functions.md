# Análise direcionada de funções — Ghidra

Operação adicional às prévias existentes; o binário examinado nunca é executado. Backend inicial Linux, Ghidra 12.1.4 e JDK 21 nos runners descartáveis já configurados em external-backends.yml. O script Java é um recurso confiável do pacote, não um script fornecido pela evidência.

## Uso futuro em ambiente operacional privado

Registrar o caso e sua autorização/escopo pelo fluxo existente. Opções globais antes do comando:

```text
cyber --home DIRETORIO_OPERACIONAL --max-bytes 1073741824 --timeout 300 --ghidra-home /CAMINHO/GHIDRA --java-home /CAMINHO/JDK functions CASO /CAMINHO/arquivo.exe --name NomeExato
cyber --home DIRETORIO_OPERACIONAL --timeout 300 --ghidra-home /CAMINHO/GHIDRA --java-home /CAMINHO/JDK functions CASO /CAMINHO/arquivo.elf --address 0x401000 --range 0x401000 0x402000
```

Seletores múltiplos formam uma união. Nomes exatos podem ser simples ou qualificados; name_matches informa quantas funções corresponderam ao nome, inclusive ambiguidades. Endereços referem-se à entrada de função reconhecida no modelo Ghidra; não transformam bytes arbitrários em função. Intervalos semiabertos selecionam entradas (start <= entry < end), não interseção de todo corpo. Os endereços são os do programa importado, não offsets de arquivo.

API: analyze_functions(core, case, path, ghidra_home=absolute_path, java_home=absolute_path, names=[...], addresses=[...], ranges=[[start,end]], **budgets).

## Resultados e limites

A aquisição usa a fila de cópia verificada do CORE. Entrada/hash são revalidados antes e depois da ferramenta; seleção, caminhos confiáveis das ferramentas, hash, parâmetros e resultados ficam numa operação selected_functions auditada, incluída no relatório.

Cada função contém pseudocódigo identificado como interpretação do decompilador; nunca código-fonte original recuperado. Exporta referências de entrada para o entry point e referências de saída das instruções no corpo. call=true permite filtrar chamadas. Endereços/tipos/símbolos pertencem ao modelo estático do Ghidra; incluem referências externas sem bytes locais. Chamadas indiretas e destinos não resolvidos podem não aparecer. Não é prova de comportamento executado.

Orçamento por operação:
- até 32 nomes, 32 endereços e 32 intervalos; requisição normalizada <=8192 bytes;
- até 128 funções, 512 referências por função, respeitando também um orçamento combinado conservador de saída;
- pseudocódigo entre 256 e 8192 caracteres por função (padrão 4096);
- até 60 segundos de decompilação por função (padrão 5);
- até 600 segundos de autoanálise (padrão 30), sempre dentro do prazo restante do CORE;
- até 100 mil funções percorridas para seleção e 10 mil instruções por função por padrão;
- limites existentes de JSON, stdio e scratch da integração Ghidra continuam aplicáveis. A operação retorna parcial quando seleção ou referências são truncadas. Pseudocode_truncated marca o texto limitado, sem afirmar sua integralidade.

Exemplos de configuração: --max-functions 4 --max-references 32 --decompile-seconds 10 --analysis-seconds 60 --pseudocode-chars 8192.
A combinação funções/referências/texto pode ser rejeitada antes da aquisição para manter a resposta abaixo do limite IPC. Valores máximos individuais não são promessa de que todos os máximos simultâneos caibam.

## Validação e pendências

scripts/check-selected-functions.py compila um ELF sintético com função alvo, auxiliar e variável global, sem executá-lo. A integração real deve comprovar seleção por nome, endereço/intervalo, chamada, referência a dados, preservação do original, persistência e relatório. Testes apenas no GitHub; nenhum VisionFT privado é enviado ao CI.

A prévia ExportPreview.java e o contrato Capstone atual permanecem preservados. Esta etapa não implementa seleção profunda no Capstone, COFF/demangling, QML, comparação semântica, FTW2 ou retomada por função. A aquisição é persistente, mas a análise direcionada é uma operação síncrona: interrupção exige nova execução. O orçamento de scratch existente ainda limita executáveis grandes; não há validação de Ghidra profundo em VisionFT ou em executável de 250 MiB nesta entrega.
