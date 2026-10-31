# Pentest web operacional e identificação de criptografia em programas

Estado: desenho para aprovação do proprietário. Não é implementação concluída.
Data: 2026-10-31.
Pedido: deixar pentest e identificação de criptografia de programas funcionando; formatos solicitados: todos.
Base funcional examinada: codex/zap-passive, 40c2b320a638e142d8eaa3181b75f122518935b4.
Main atual examinada: 217f70986d6c5ac6e2287f23389197115f7ec655.

## Objetivo e entrega verificável
O proprietário deve conseguir iniciar uma avaliação autorizada de site/API e analisar um programa/firmware para localizar evidências estáticas de uso de criptografia. Cada capacidade deve executar de verdade, produzir evidências rastreáveis no CORE e declarar ausências/limites. Um menu de ferramentas ou um teste --version não satisfaz esse objetivo.

São duas frentes independentes: A, pentest web; B, identificação criptográfica. Implementação em incrementos revisáveis, com testes sintéticos no GitHub. A conclusão de uma frente não encerra a outra. Não chamar a plataforma completa de concluída enquanto os critérios aplicáveis abaixo permanecerem pendentes.

## Abordagens
1. Reimplementar scanners e descompiladores: manutenção alta e cobertura inicial menor; não recomendado.
2. Reconhecimento superficial por palavras/entropia: útil como camada fraca, insuficiente como entrega principal.
3. Ampliar adaptadores existentes: recomendado; ZAP e Ghidra reais, regras versionadas, transporte/execução supervisionados e resultados persistidos no CORE. Preservar Python/SQLite e CLI; interface consome o mesmo serviço.

A arquitetura híbrida é a proposta do implementador, não uma aprovação presumida deste novo desenho.

## Restrições comuns
- Desenvolvimento/validação somente no GitHub, sem instalar, clonar ou executar o produto no computador do proprietário.
- Somente arquivos/alvos sintéticos nos runners; sem dados/credenciais reais, bancos operacionais ou evidências de clientes no Git/CI.
- Beta pessoal sem novo login da aplicação. Login de um alvo web é uma capacidade separada.
- Não editar/integrar automaticamente branch Claude. Preservar os contratos compartilhados e sua divisão de responsabilidades.
- As análises não executam os programas/firmwares examinados. Nenhum script originado da amostra/website vira código confiável.
- A autorização de desenvolvimento não inicia testes em sites reais. A operação posterior pertence ao proprietário, com escopo explícito.
- Implementação e validação precedem integração na main; nenhum merge/deploy/publicação faz parte desta aprovação de desenho.

## Frente A — pentest de sites/APIs

### Base reaproveitada
HTTPS com escopo, TLS/pinning e controles; inventários HTML/OpenAPI; campanhas/recibos; API bearer sintética; ZAP passivo offline. APIs de campanha existentes são preservadas, incluindo retomada de operações já publicadas.

### A1. Transporte ativo contido
Introduzir backend Linux para requisições ativas, separado do importador passivo sem rede.
ZAP tem acesso apenas a um gateway por rede interna isolada; não recebe rota direta ao alvo/Internet, socket Docker, rede do host ou privilégios.
O gateway aplica origem exata, caminho, método, parâmetros permitidos, janela e orçamento antes de cada envio. Verifica DNS público/pinning/TLS upstream. Redirects, referências externas e scripts não ampliam escopo.
Para HTTPS via proxy, o gateway termina o transporte do cliente com CA efêmera da execução e valida separadamente o TLS upstream. O certificado temporário do gateway não é apresentado como certificado do alvo.
Comprovar contenção real por testes de egress direto, rede privada/mista, troca de DNS, redirects e requisições que tentam escapar da política. Sem prova, etapa fica indisponível.

Manifesto ativo é versionado e separado do grant de leitura atual. Classes/métodos/caminhos e parâmetros de teste exigem declaração explícita. Ausência não habilita active scan. Compatibilidade com campanhas antigas permanece.

### A2. Motor ativo ZAP
Começar com regras versionadas de XSS refletido e SQL injection não temporal (classes oficiais 40012/40018), somente em endpoints de laboratório descartável. Confirmar configuração e comportamento da versão fixada no plano; regras adicionais exigem seus próprios testes.
Sem crawling/JavaScript implícito, callbacks externos, carga/DoS, persistência ou geração de tentativas de login.
Fixtures vulnerável/corrigida devem produzir diferença comprovada. Alertas do ZAP são suspected; confirmação exige critério reproduzível da classe e controle negativo adequado. Não declarar execução de JavaScript só pela reflexão de um marcador em HTML.

Tetos iniciais por estágio: 300 s, 128 requisições, uma em andamento, intervalo mínimo 0,5 s, headers 64 KiB, corpo 1 MiB, resultado 128 KiB, até 128 achados. O orçamento inclui tentativas/retries e requisições do scanner. Container: CPU 1, memória 1 GiB, 128 PIDs, tmpfs 512 MiB; excesso explícito, sem transformar análise truncada em sucesso. Limites do gateway e do SO separados no relatório.

### A3. Autenticação, sessões e permissões
Perfis isolados: visitante, usuário A, usuário B e administrador quando fornecido. Suportar inicialmente bearer, cookie de sessão e login de formulário/JSON expressamente configurado.
Material secreto fica fora do manifesto/repositório/argv/resultados. Canal de fornecimento é local e efêmero ao worker; CI usa apenas segredos inventados. Não alegar cofre criptografado novo.
Definir verificador de sessão autenticada para cada perfil; perda de sessão bloqueia/reclassifica o estágio, nunca mantém cobertura autenticada fictícia.
Reusar a matriz de acesso existente, ampliando transporte controlado para origens autorizadas. Política esperada e identificação de recurso vêm do operador; não inferir permissões a partir de HTTP200 ou de diferença de tamanho.
MFA, provedores OAuth/OIDC arbitrários e fluxos não descritos aparecem como não suportados, até adaptadores específicos serem validados.

### A4. Cobertura, retomada e uso
Estágios ativos interrompidos com efeitos desconhecidos não são repetidos automaticamente. Registrar a tentativa antes do envio e exigir decisão explícita de retomada/limpeza quando houver incerteza. Recibo já publicado continua adotável sem reenvio.
CLI expõe os contratos novos; campanhas e relatórios discriminam executado/parcial/indisponível/bloqueado. Reteste preserva achados anteriores e associa versão corrigida.
Painel existente pode consumir os mesmos serviços depois dos contratos CLI; ausência de conexão do painel não equivale a ferramenta ausente.
SAST/SCA/segredos e cenários completos de negócio continuam parte do escopo maior da plataforma, mas não podem aparecer como implementados por esta integração web. Entram como entregas separadas, com insumos e aceite próprios.

## Frente B — localizar criptografia em todos os formatos solicitados

### Formatos e significado de suporte
Incluir EXE/DLL PE, ELF e firmware/BIN, além dos contêineres HEX/S-record já lidos pelo projeto. Todos têm triagem por bytes. Só formatos/arquiteturas efetivamente interpretados recebem endereços, símbolos e relações de funções.
.NET, Java, scripts, imagens compactadas/proprietárias e executáveis de outras famílias recebem suporte parcial ou não suportado explícito quando não houver parser validado. “Todos” não significa identificação universal de qualquer implementação criptográfica.

### B1. Camadas de evidência
1. Imports/símbolos estruturais: APIs Windows CryptoAPI/CNG, OpenSSL e bibliotecas reconhecidas. Exemplos: BCryptEncrypt/BCryptDecrypt e EVP_EncryptInit_ex. Uma função genérica de cifrar não determina automaticamente algoritmo/modo/chave.
2. Assinaturas versionadas de constantes completas reconhecíveis, como tabelas AES/SHA e constantes ChaCha20. Retornar regra, família e offset, sem bytes adjacentes nem trechos arbitrários.
3. Strings técnicas de nomes de algoritmo/biblioteca como indícios fracos, sem promovê-las a prova de uso.
4. Instruções criptográficas quando Capstone e arquitetura/mapeamento suportados estiverem disponíveis; nunca atribuir instrução a uma região sem bytes respaldados pelo arquivo.
5. Ghidra opcional: localizar referências a APIs/símbolos/constantes e funções que as referenciam, com script fixo e limites. Pseudocódigo é interpretação, não código-fonte original nem prova de execução.
6. Entropia por janelas apenas como região possivelmente comprimida/cifrada; não identificar AES ou qualquer algoritmo por entropia.

Implementar a orquestração na engenharia reversa (seção 6), preservando o módulo de criptanálise do Claude. Regras/contratos existentes no lado Claude serão referenciados, não copiados/integrados silenciosamente.

### B2. Relatório e limites
Novo comando proposto: crypto-inspect CASE ARQUIVO. O nome final e as opções exatas ficam para o plano.
Resultado por achado: classificação/força da evidência, algoritmo ou família quando sustentado, regra/versão, offset de arquivo; RVA/VA/endereço virtual somente quando mapeamento validado. Relações de funções incluem referência de origem.
O relatório distingue biblioteca importada, constante encontrada, referência estática e resultado inconclusivo. Ausência de achado não comprova ausência de criptografia.
Não exportar chaves, segredos ou strings brutas arbitrárias; não recuperar chaves nem prometer descriptografia universal. Recuperação existente permanece outro fluxo, com material autorizado.
Tetos iniciais: entrada até limite CORE vigente (máximo 1 GiB), timeout até 300 s limitado pelo CORE, 256 achados, saída 256 KiB; entropia em janelas de 4 KiB e até 256 regiões exportadas. Leitura em chunks/mmap, sem copiar arquivo inteiro para Python. Varredura completa vs prefixo/interrupção e omissões explícitas.
Ghidra/Capstone ausentes reduzem cobertura, não derrubam a triagem pura nem são apresentados como executados.
Aquisição verificada, processo supervisionado, autorização/cancelamento e guarda transacional de publicação seguem o CORE.

## Critérios de aceite
- A1: scanner real não consegue contornar gateway/rede; escopo/TLS/DNS/orçamento exercitados com fixtures.
- A2: ZAP real encontra os casos conhecidos de laboratório; controles corrigidos são diferenciados; sem falsa aprovação de limite/falha.
- A3: login/sessão positivos e negativos, expiração, isolamento de perfis e acesso cruzado A/B comprovados; nenhum segredo nos outputs.
- A4: campanha interrompida/reaberta preserva recibos, efeitos incertos e histórico; CLI e relatório funcionam.
- B: PE/ELF/BIN/HEX/S-record com sinais conhecidos e negativos/compressão; offsets/mapeamentos conferidos; exemplos compilados benignos analisados sem execução.
- B com Ghidra real: referências/funções conhecidas localizadas no fixture, sem substituir o teste real por mocks.
- Ambas: falhas/dependência ausente/arquivos malformados/limites/cancelamento e regressões Windows/Linux no GitHub. Backend de rede/Ghidra real comprovado inicialmente Linux.
- Cada incremento termina com PR, SHA exato, testes RED/GREEN e limitações; revisão independente antes da conclusão.

## Integração e ordem
Preparar primeiro uma candidata isolada que preserve o stack Codex e a main atual; validar a combinação sem editar branches de outro agente. A mudança nova do PDF na main deve ser preservada/reconciliada explicitamente, não revertida por uma árvore antiga.
Entregas: B1/B2 (triagem criptográfica utilizável); A1 (fronteira ativa); A2 (ZAP ativo); A3 (sessões/permissões); A4 (reteste/uso). Essa ordem é proposta técnica para produzir uma ferramenta estática útil enquanto a fronteira ativa é comprovada.
Não encerrar o pedido completo na primeira etapa nem chamar um laboratório limitado de plataforma integral.

## Decisões delegadas ao implementador
Estrutura de arquivos, assinaturas de métodos, fixtures, parsers auxiliares e versão final de dependências compatíveis são definidos no plano, com hashes/versões e testes. Falhas adicionais descobertas durante implementação serão corrigidas quando necessárias ao contrato, preservando trabalho externo.

## Fontes
- docs/superpowers/specs/2026-10-28-pentest-platform-design.md
- docs/zap-passive.md e docs/api-runtime.md
- https://www.zaproxy.org/docs/alerts/40012/
- https://www.zaproxy.org/docs/alerts/40018/
- https://www.zaproxy.org/docs/desktop/addons/automation-framework/job-ascan/
