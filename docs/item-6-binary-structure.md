# Item 6 — estruturas de executáveis e firmware

Este incremento amplia o analisador já existente. ELF/PE continuam entrando
por `analyze-firmware`: autorização, aquisição de cópia verificada, processo
monitorado, resultado persistente e relatório. Não há execução do binário,
mapeamento de memória no sistema nem escrita em dispositivo.

## Contrato

O resultado mantém os campos antigos e acrescenta, em `firmware.metadata`:

- `architecture` e sua origem no cabeçalho; máquina desconhecida conserva o
  número e recebe `unknown`. O campo identifica a arquitetura declarada.
- `section_headers`: nomes, offsets/tamanhos de arquivo, endereços/tamanhos
  declarados de memória, atributos e índices.
- ELF: `section_count`, `program_header_count` e `segments`; suporte a classes
  32/64 bits e ordens little/big endian. Permissões de segmento são separadas
  dos atributos de seção.
- PE: base preferida da imagem, RVA e endereço preferido de entrada,
  características, indicação DLL e seções PE32/PE32+. RVA de entrada zero é
  preservado como ausência: entry_point=null e has_entry_point=false.

A seção ELF NOBITS pode declarar memória sem bytes armazenados. Não se lê
nem se aloca sua extensão virtual. Segmentos LOAD também mantêm separados
os tamanhos em arquivo e memória. PE informa `memory_size` como o VirtualSize
declarado, sem fingir emulação das regras do loader.

## Limites e rejeições

Cada tabela admite no máximo 256 entradas. Nomes ELF retornam no máximo
128 bytes de origem por nome, com `name_truncated` explícito; não é necessário
varrer todo um nome enorme. Isso limita a expansão da resposta, inclusive
em comparações que incluem os metadados das duas entradas.

São rejeitados payloads fora do arquivo, referências inválidas de nomes,
tabelas de nomes incompatíveis, alinhamentos ELF inválidos, estouro de
endereços, segmento LOAD com mais bytes em arquivo que em memória e
intervalos de arquivo de seções sobrepostos. NOBITS/entradas NULL não são
confundidos com payloads de arquivo; regiões virtuais não são materializadas.

Permanecem os limites anteriores de arquivo e supervisão. Numeração estendida
ELF continua sem suporte. Tipos/flags desconhecidos são apresentados como
valores, sem atribuir uma semântica inventada. SHF_COMPRESSED é rotulado;
seu tamanho físico não é validado como múltiplo do tamanho lógico de entrada.
Não há descompressão nem validação do cabeçalho/dados comprimidos neste incremento.

## Validação e pendências

Testes de aceitação foram publicados antes da implementação: run39037526828
executou 172 testes e demonstrou 13 falhas de asserção relacionadas à
funcionalidade ausente (incluindo subcasos). A suíte prévia não era prova
de validação das estruturas novas.

Os controles sintéticos cobrem ELF64 little endian, ELF32 big endian,
PE32/PE32+, nomes, regiões sem bytes, arquitetura desconhecida, limites e
integração real do filho → SQLite → relatório. Os binários sintéticos são
somente lidos; nunca são executados.

Este incremento não conclui todo o item 6. Desmontagem, decompilação,
importações/símbolos, formatos proprietários e integrações Ghidra/Capstone/
Binwalk/equivalentes continuam separados. Strings do candidato Claude
permanecem na branch dele; não foram copiadas nem integradas aqui.

A revisão independente detectou entrada PE ausente tratada como base de imagem
e validação de tamanho lógico sobre seção ELF comprimida. As duas regressões
foram reproduzidas no run39037905810 (240 descobertos na combinação Linux,
1 falha, 1 erro, 2 skips) antes das correções. São casos de compatibilidade,
não provas de execução de DLL ou de descompressão.

## Referências primárias

- [ELF 4.2 — seções](https://gabi.xinuos.com/v42/elf/03-sheader.html)
- [ELF 4.2 — segmentos](https://gabi.xinuos.com/v42/elf/07-pheader.html)
- [Registro de máquinas ELF](https://gabi.xinuos.com/elf/a-emachine.html)
- [Microsoft PE/COFF](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)

A validação é estrutural e limitada; não comprova autenticidade, segurança
do código, compatibilidade com ECU, validade completa para o loader ou
endereço efetivo após relocação.
