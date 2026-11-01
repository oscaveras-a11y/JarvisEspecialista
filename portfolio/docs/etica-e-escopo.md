# Ética e escopo

A linha que separa um profissional de segurança de um criminoso é **autorização**. Esta página é a regra mais importante do repositório.

## O conceito de "escopo"

**Escopo** é a definição exata do que você está autorizado a testar: quais sistemas, quais endereços IP, quais aplicações, em qual janela de tempo e com quais técnicas. Tudo que está **fora do escopo** é proibido — mesmo que seja tecnicamente possível e esteja "ali do lado".

Um teste de segurança legítimo sempre tem:

- **Autorização por escrito** do dono do sistema (contrato, termo, ou regras de um programa).
- **Escopo definido**: o que pode e o que não pode ser tocado.
- **Janela e limites**: quando testar e até onde ir (ex.: sem negação de serviço, sem exfiltrar dados reais).

Sem autorização por escrito, **não há teste** — há invasão, que é crime.

## Regra de ouro

Só pratique em um destes três lugares:

1. **Ambientes de treino** — TryHackMe, Hack The Box, VulnHub, plataformas de CTF.
2. **Sistemas próprios** — suas máquinas, suas VMs, seu laboratório isolado.
3. **Alvos com autorização explícita** — e por escrito, dentro do escopo acordado.

## O que NÃO fazer

- Testar sites, redes ou dispositivos de terceiros "por curiosidade".
- Usar credenciais ou dados que não são seus.
- Sair do escopo porque "achou uma brecha interessante".
- Guardar evidências reais de terceiros neste repositório (o `.gitignore` já ajuda a evitar vazamentos).

## Por que isso importa para a carreira

Em perícia digital, polícia científica e defesa, **integridade e respeito ao procedimento legal valem mais que habilidade técnica**. Um portfólio que deixa a ética explícita mostra maturidade profissional — exatamente o que um recrutador do setor procura.
