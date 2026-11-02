# Cobertura solicitada: sites e aplicativos

Este inventário registra o pedido do proprietário. Não é um resultado de pentest e não declara que os controles do alvo estão corretos. A disponibilidade de um executável também não significa que exista integração testada no CORE.

| Área | Base existente nesta entrega | O que ainda exige integração/validação |
| --- | --- | --- |
| Senhas e login | Perfis isolados, verificação explícita de sessão, material privado fora dos resultados | Testes de bloqueio/limite de tentativas e verificação de política MFA com contas sintéticas; auditoria de configuração SSH por chave. Recuperação offline com John/Hashcat não testa login remoto. |
| Software desatualizado | Inventário HTML/OpenAPI limitado; identidades dos próprios backends | SCA sobre manifests/lockfiles, npm audit e pip-audit; identificação de versões não basta para confirmar exploração. WordPress/plugins exigem inventário autorizado específico. |
| Segredos expostos | Inventário de chaves e evidências sem exportar valores; aquisição verificada | Detector de segredos em árvore/histórico Git e JavaScript, rotas .env/.git/backups explicitamente autorizadas. Registrar só tipo/localização/hash redigido; rotação pertence ao proprietário. |
| SQL e comandos | ZAP ativo com regra SQL não temporal, consulta/formulário declarados | Injeção de comandos continua fora da política atual; SAST e fixtures sem execução destrutiva. |
| XSS | ZAP passivo e XSS refletido ativo; controles de cabeçalhos conforme regras passivas | XSS armazenado/DOM, navegação autenticada complexa e validação contextual precisam cenários adicionais. CSP ausente não comprova XSS. |
| Autorização | Matriz explícita com recurso e controle positivo, perfis e visitante | Cobertura de cada objeto/rota/papel deve ser fornecida; não deduzir propriedade pela troca arbitrária de IDs. |
| Portas e serviços | Gateway atual só origens HTTPS declaradas | Adaptador separado de inventário de rede, por exemplo Nmap, com IPs/portas fixos autorizados. Não ampliar o gateway web para SSH/FTP/bancos. Firewall exige evidência de configuração. |
| Upload | Nenhum ensaio ativo de upload nesta política | Fixture de upload com conteúdo inerte, validação de MIME/magic/tamanho e evidência de armazenamento sem execução; não enviar webshell. |
| Engenharia reversa e criptografia | Ghidra, Capstone opcional, DIE, Binwalk, Unblob; crypto-inspect estático PE/ELF/BIN/HEX/S-record | Indícios de algoritmo não são chaves nem prova de uso. Detecção de segredos embutidos deve ser um módulo separado com redação. Formatos gerenciados/proprietários têm cobertura parcial. |
| Atualização de aplicativos | Inspeção estática de binários | Verificar código/configuração do atualizador, cadeia de assinatura e rejeição de pacote alterado em fixture; HTTPS sozinho não garante autenticidade do update. |
| Dependências comprometidas | Aquisição e hashes dos backends preparados em CI | SCA/SBOM, origem e assinatura/proveniência quando disponível, análise de scripts de instalação; typosquatting e pacote malicioso não são excluídos por um audit limpo. |
| Phishing | Fora do scanner de site/binário | Checklist de conta/dispositivo, MFA resistente a phishing, proteção do e-mail e treinamento. Sem envio de campanhas ou leitura de caixas de e-mail nesta entrega. |

## Ferramentas

**Atualização de 2026-11-02:** Semgrep (SAST) e detect-secrets (segredos) estão
integrados e testados de verdade, pelo mesmo caminho isolado/limitado que já
sustentava DIE e Unblob (`external_tool_runtime.py`, `external_tools.py`,
`external_tools_child.py`): executável absoluto configurado via variável de
ambiente (`CYBER_SEMGREP_EXECUTABLE`, `CYBER_DETECT_SECRETS_EXECUTABLE`),
subprocesso com RAM/CPU/saída limitados e sem rede liberada, resultado validado
campo a campo antes de persistir. O Semgrep usa um conjunto de regras próprio e
confiável (`config/semgrep-rules/python-security.yml`, nunca a origem/URL do
registro público) com o mesmo padrão de configuração do YARA. O achado nunca
inclui o trecho de código correspondido (poderia conter um segredo da própria
amostra) — só identificador de regra, severidade e linha. O detect-secrets
nunca retorna o valor do segredo, só o SHA1 já produzido pela própria
ferramenta. Cobertos por `tests/test_external_recovery_tools.py`
(`test_semgrep_and_detect_secrets_find_real_synthetic_issues` e o teste de
rejeição de JSON malformado), providos no CI dedicado por
`scripts/setup-external-recovery-tools.sh`.

**Atualização de 2026-11-02 (decisão do proprietário: liberar rede só para
isso):** pip-audit (SCA) também está integrado. É o único adaptador deste
módulo que roda com `network=True` — uma exceção estreita e explícita
(`external_tool_runtime.NETWORK_TOOLS`) à postura "sem rede" do resto da
classe `Runner`: só para consultar o índice de pacotes (PyPI, serviço
`pypi` do próprio pip-audit) pelos pares nome/versão já fixados no arquivo de
requisitos adquirido (`--no-deps --disable-pip`, nunca resolvendo nem
instalando nada), nunca sobre a amostra sob investigação. Testado de verdade
contra uma dependência com vulnerabilidade pública conhecida
(`test_pip_audit_finds_a_real_known_vulnerable_pin`, com gate de opt-in
próprio `CYBER_REQUIRE_PIP_AUDIT_NETWORK=1` para não tornar a suíte
dependente de rede por padrão).

Pendente nesta entrega:

- **npm audit** — mesmo princípio do pip-audit, ainda não implementado para
  o ecossistema Node.
- **Nmap (inventário de rede)** — precisa de um escopo de rede autorizado
  explícito (IPs/portas fixos declarados pelo operador), separado do
  gateway web atual, igual ao que o pentest ativo (seção 9 original) já
  exige para HTTP. Ainda não implementado — é uma mudança de forma
  diferente do pip-audit (não é "ler um arquivo e consultar um índice", é
  "varrer um alvo de rede"), por isso tratada como próximo passo separado.

Seleção de versão, licença, limites, formato de saída e testes reais em runner
devem preceder a disponibilidade operacional de qualquer adaptador novo.

YARA pode ajudar em assinaturas estáticas, mas não substitui SAST/SCA, autorização ou testes de atualização. Ghidra/Capstone e regras próprias já sustentam a identificação de constantes/instruções; não é necessário instalar todas as ferramentas possíveis.

Não importar listas de credenciais vazadas nem realizar credential stuffing. Para avaliar a defesa de login, usar contas e candidatas sintéticas fornecidas pelo proprietário em ambiente descartável, com limite explícito, e verificar bloqueio/rate limit sem enumeração de usuários. Não iniciar varreduras reais automaticamente.

## Critério de entrega dos próximos adaptadores

Cada módulo precisa separar disponível/indisponível/parcial, escopo autorizado, execução realizada, achado suspeito e confirmação. Usar fixtures positivas e corrigidas, tempo/bytes/tentativas limitados, cancelamento, nenhuma persistência de segredos e relatórios com evidência. Instalar um pacote ou adicionar uma linha ao catálogo não conclui a integração.

## Referências das ferramentas candidatas

- [Semgrep](https://github.com/semgrep/semgrep): análise estática; a edição comunitária tem limites de fluxo entre arquivos/funções.
- [pip-audit](https://github.com/pypa/pip-audit) e [npm audit](https://docs.npmjs.com/cli/v11/commands/npm-audit/): vulnerabilidades conhecidas em dependências, sem garantia de ausência de código malicioso.
- [Gitleaks](https://github.com/gitleaks/gitleaks): detecção de segredos, exigindo redação e revisão dos achados.
- [Nmap](https://nmap.org/book/port-scanning.html): inventário de portas; requer novo escopo de rede separado.
