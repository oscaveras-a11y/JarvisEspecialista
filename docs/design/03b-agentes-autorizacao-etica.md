# Item 3 (parte B) — Agentes, autorização e fronteira ética

Autor: **Claude Code** (item ímpar 3, design/revisão). Data: 2026-10-17.
Complementa [03-arquitetura-core.md](03-arquitetura-core.md). Consolida em design as decisões discutidas com o proprietário sobre agentes, limites e contexto forense.

> **Fronteira.** Design (item 3). Implementação é do Codex (itens pares / Fase 2 e item 14). Modelo aditivo, compatível com `agents/runner.py` e `service.Core`.

## 1. Papéis dos agentes (recapitulando o escopo)

| Agente | Papel | Nunca faz |
|---|---|---|
| **CORE** | Orquestra, valida escopo/autorização, decide quem executa, audita | Não executa conteúdo de evidência; não amplia permissão de ninguém |
| **Codex** | Engenharia: código, ferramentas, automação, RE assistida | Não é fronteira de segurança; respostas não viram comandos automáticos |
| **Claude** | Revisão independente, hipóteses, inconsistências | Opcional; o sistema roda sem ele |

Adaptadores **independentes e plugáveis** (já em `runner.py`). O sistema funciona só com Codex. Um **modelo local** (open-source, offline) pode entrar como terceiro adaptador para privacidade/custo/trabalho sem nuvem — **legítimo**, e não muda o que é autorizado.

## 2. Separação essencial: agente ≠ ferramenta

O agente **orquestra, analisa e documenta**. O trabalho técnico pesado é das **ferramentas** (Ghidra, Binwalk, hashcat/John, Autopsy, Sleuth Kit, Nmap, bibliotecas de cripto). Consequência de projeto:

- O agente **não precisa** "quebrar" nada; ele conduz ferramentas legítimas dentro do escopo.
- Logo, **não existe e não se cria** um "agente sem ética" para contornar recusas: contra cripto forte isso não funciona (é limite matemático, não de política), e tornaria o sistema ilegítimo. Fica **vedado por design**, coerente com os itens 7, 9 e 14.

## 3. Modelo de autorização (dois tipos)

O item 7 hoje cobre o caso "dono fornece a chave". Perícia criminal exige um segundo tipo: **autoridade legal**. Proposta de modelo (migração aditiva):

```sql
CREATE TABLE IF NOT EXISTS authorization_basis(
 case_id TEXT PRIMARY KEY REFERENCES investigations(id),
 kind TEXT NOT NULL,              -- 'owner_consent' | 'legal_authority'
 authority TEXT NOT NULL,         -- autoridade emissora (ex.: vara/juízo) ou dono
 reference TEXT NOT NULL,         -- nº do mandado/processo ou termo de autorização
 examiner TEXT NOT NULL,          -- perito/operador responsável
 scope TEXT NOT NULL,             -- escopo determinado
 expires REAL, created TEXT NOT NULL);
```

- `owner_consent`: arquivos próprios ou de cliente com termo (caso atual).
- `legal_authority`: mandado/decisão judicial, com autoridade, referência do processo, perito e escopo.
- Estado da implementação: a `authorization_basis` é **exigida hoje** para a recuperação/autoteste (`self_test_recovery`, `make_lab_envelope` exigem `owner_consent`). As demais análises (`analyze-file`, `decompose`, `recover-aes`, `assess-recovery`) exigem a autorização do `investigate()` (dono/escopo/prazo/revogação), ainda **não** a `authorization_basis`. Passar a exigir `authorization_basis` também nessas análises é um passo de núcleo (item 14) a coordenar com o item 4 do Codex — registrado aqui para não haver divergência entre design e código. Em todos os casos, um agente **não** pode criar nem ampliar essa base (item 14); tudo vai para a auditoria encadeada.

## 4. Fronteira ética (vedações por design)

Direto dos itens 7/9/14 do escopo, codificadas como regras do CORE — não como "educação" de um agente:

- **Proibido:** extração clandestina de chaves, roubo de credenciais, acesso a sistemas de terceiros sem base legal/consentimento, contornar limites de provedores.
- **Permitido sob autorização:** análise de mídia lícita, recuperação de senha de **material próprio ou lawfully seized sob mandado** com ferramentas padrão, auditoria autorizada em escopo.
- **Resultado honesto é resultado válido:** quando o alvo é inacessível (cripto forte sem chave/senha), o estado é `SEM SOLUCAO VIAVEL DEMONSTRADA` (item 13) — nunca "sucesso" inventado.

## 5. Modo de autoteste autorizado (para testar o beta com segurança)

Para o proprietário exercitar a recuperação **em arquivo próprio**:

```
self_test_recovery(core, case, target_path, *, strength) -> dict
```
- O operador gera um alvo **seu** e escolhe a força da proteção.
- O sistema tenta recuperar com ferramenta padrão e orçamento de tempo/recursos.
- Saída honesta: proteção fraca → recuperada; forte/aleatória → `recovery_demonstrated: false`, registrando a inviabilidade.
- Requer `authorization_basis` = `owner_consent` sobre arquivo dentro do escopo; auditado.

Isso dá um **beta de cripto real, legítimo e reproduzível** (o `recover-aes` com chave e o `assess-recovery` sem chave já são a base).

## 6. Distribuição entre agentes (liga ao G5 do 03-arquitetura)

O broker do CORE roteia:
- execução de análise/ferramenta → **local (CORE)**;
- segunda opinião/revisão → **Codex** (ou Claude, se presente);
- respeitando limites próprios de cada adaptador (item 3: não presumir permissões iguais) e nunca enviando conteúdo de evidência ao agente (só metadados derivados em allowlist, como já faz `review_summary`).

## 7. Critérios de teste (para o Codex, item 18)

- Sem `authorization_basis` registrada → análise/recuperação é recusada pelo CORE.
- `legal_authority` exige autoridade+referência+perito+escopo não vazios.
- Autoteste em arquivo próprio: senha fraca recuperada; forte → `recovery_demonstrated: false` e estado honesto.
- Agente não consegue criar/alterar `authorization_basis` nem ampliar escopo.
- Nenhuma rota envia conteúdo de evidência a agente; auditoria íntegra.

## 8. Handoff ao Codex

Implementação de §3–§6 é núcleo/segurança (itens 14 e Fase 2/6) — do Codex. Este documento é o contrato. Decisões em aberto: formato exato do registro de mandado (campos mínimos exigidos por lei aplicável) e qual ferramenta de recuperação de senha integrar primeiro (hashcat vs John) para o modo de autoteste.
