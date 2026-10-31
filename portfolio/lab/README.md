# Laboratório local

Um laboratório **isolado** é onde se pratica com segurança e legalidade: máquinas virtuais na sua própria máquina, sem contato com redes de terceiros.

## Montagem básica

1. **Virtualizador:** [VirtualBox](https://www.virtualbox.org/) (gratuito) ou VMware.
2. **Máquina atacante:** [Kali Linux](https://www.kali.org/) — já traz as ferramentas de estudo.
3. **Máquinas-alvo (propositalmente vulneráveis):**
   - **DVWA** (Damn Vulnerable Web Application) — vulnerabilidades web para treinar.
   - **Metasploitable** — servidor Linux cheio de falhas conhecidas.
   - **VulnHub** — imagens de VMs vulneráveis para baixar e resolver.
4. **Rede isolada:** configurar uma rede **host-only** ou **interna** no virtualizador, para que as VMs só conversem entre si — nunca com a internet aberta ou a rede de casa/trabalho.

## Regras do laboratório

- Alvos vulneráveis **nunca** ficam expostos à internet.
- Snapshots antes de cada experimento, para reverter facilmente.
- Tudo aqui é treino em sistemas próprios — ver [../docs/etica-e-escopo.md](../docs/etica-e-escopo.md).

## O que virá

Conforme eu montar os ambientes, documento aqui a configuração de cada um (rede, credenciais de treino, objetivos de aprendizado).
