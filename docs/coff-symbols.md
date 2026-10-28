# Símbolos COFF e nomes C++

O comando adicional symbols usa a cópia verificada pelo CORE, lê a tabela COFF padrão de registros de 18 bytes e opcionalmente chama demanglers LLVM confiáveis. Não executa o objeto ou o executável examinado. Objetos COFF e imagens PE são distinguidos; BigObj/anônimos são explicitamente unsupported_variant. Arquivos opacos retornam unsupported_format.

```text
cyber --home DIRETORIO_OPERACIONAL --max-bytes 1073741824 --timeout 300 symbols CASO arquivo.exe --llvm-bin /usr/lib/llvm-18/bin --max-symbols 128
```

O leitor usa mmap somente leitura e SHA-256 por partes. Valida tabela de seções, limites das tabelas de símbolos/strings, índices, contagens auxiliares e registros não apresentados após o limite. Entradas auxiliares são puladas, não interpretadas como símbolos. Nomes originais e seus bytes hexadecimais permanecem junto do nome apresentado; nomes extensos são marcados name_truncated e não são enviados ao demangler.

section_offset, rva, virtual_address e file_offset são campos separados. Objetos relocáveis não recebem VA/RVA inventados; endereços PE derivam do cabeçalho e da seção. Nem todo símbolo possui bytes locais. Símbolos não provam limites de função, resolução de relocations, origem do código ou comportamento em execução.

LLVM llvm-undname trata ABI Microsoft; llvm-cxxfilt trata nomes Itanium reconhecidos. Sem --llvm-bin, o leitor preserva nomes e informa not_requested nos símbolos decorados, com resultado parcial. A ferramenta recebe somente nomes limitados como argumentos, sem shell. Plataforma de demangling inicial: Linux. Versão, caminho e SHA-256 da ferramenta usada são persistidos. Versões diferentes das exercitadas no CI não estão comprovadas por esta entrega.

Orçamentos: --max-symbols entre 1 e 1024, --max-records entre 1 e 100000, --max-name-bytes entre 8 e 4096; estimativa combinada limita os máximos simultâneos. A string table possui limite fixo de 16 MiB. --output-bytes entre 4096 e 1048576 limita JSON serializado incluindo escaping Unicode; registros completos são omitidos do final quando necessário. symbols_truncated, output_truncated e output_symbols_omitted indicam o corte, preservando symbol_count total. Metadados isolados que excedam o orçamento causam falha explícita. O timeout e o cancelamento pertencem ao supervisor CORE. Scratch/stdio da chamada LLVM usam os limites externos existentes.

A operação coff_symbols persiste evidência/hash, parâmetros, resultados e ferramentas na auditoria e no relatório existentes. A aquisição é persistente; esta operação síncrona ainda não possui retomada por símbolo.

## Validação

tests/test_coff_symbols.py usa tabelas sintéticas com nomes curtos/longos, auxiliares, PE e COFF, offsets inválidos, truncamento, contagens excessivas e orçamento. scripts/check-coff-symbols.py compila C++ Microsoft COFF com clang++-18 e exige que LLVM desambigue Lab::selected(int), além de verificar CORE, hash, auditoria e relatório. O objeto nunca é executado. CI: .github/workflows/coff-symbols.yml.

Referência de layout: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-symbol-table.
Referência da ferramenta exercitada: https://github.com/llvm/llvm-project/blob/llvmorg-18.1.8/llvm/tools/llvm-undname/llvm-undname.cpp.

Nenhum VisionFT real foi analisado. PDB/CodeView, import libraries, auxiliares tipados, BigObj e resolução/normalização de relocations permanecem pendentes. Qt/QML e FTW2 são etapas separadas.
