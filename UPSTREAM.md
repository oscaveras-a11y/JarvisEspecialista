# Base oficial

Este projeto usa [open-jarvis/OpenJarvis](https://github.com/open-jarvis/OpenJarvis)
como submodulo Git na pasta `jarvis/`, fixado no commit:

`ccf02ec7bdda2e2b344eeb8dd986d742ff458acc`

O submodulo preserva o codigo, o historico, a atribuicao e a licenca Apache-2.0
do projeto original. Seus arquivos de personalizacao ficam neste repositorio.
Nenhum modelo de IA ou instalador binario e armazenado no GitHub.

Para obter todo o codigo:

```sh
git clone --recurse-submodules https://github.com/oscaveras-a11y/J.A.R.V.I.S.git
```

Se ja clonou sem a opcao acima:

```sh
git submodule update --init --recursive
```

O ZIP do GitHub nao inclui o conteudo do submodulo; use Git.
Atualizacoes do submodulo devem ser testadas: o launcher usa o leitor de voz
do CLI oficial, que pode mudar em novas versoes.
