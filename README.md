# Implementacao do AES-128

Este projeto implementa o algoritmo de criptografia AES-128 em Python, com suporte aos modos de operacao ECB e CBC para criptografar e descriptografar arquivos.

O algoritmo foi desenvolvido como trabalho academico para a materia de Sistemas da Informacao, ministrada pelo professor Gilvan Justino.

## Autores

- Matheus Christo da Silva
- Pedro Felipe Matos Menezes

## Arquivos do Projeto

- `AES.py`: contem a implementacao principal do AES, incluindo cifragem, decifragem, expansao de chave, ECB e CBC.
- `utils.py`: contem funcoes auxiliares para leitura/escrita de arquivos, validacao de chave e padding PKCS#7.
- `menu.py`: contem o menu interativo para executar a criptografia ou descriptografia.
- `cli.py`: interface de linha de comando para executar operacoes diretamente via argumentos, sem menu interativo.
- `Tabelas (1).txt`: contem as tabelas usadas pelo AES, como S-Box, Inverse S-Box, Tabela L e Tabela E.

## Como Executar

Para iniciar o programa, execute:

```bash
python menu.py
```

Depois, siga as opcoes exibidas no terminal:

1. Escolha se deseja cifrar ou decifrar.
2. Escolha o modo de operacao: ECB ou CBC.
3. Informe o caminho do arquivo de entrada.
4. Informe o caminho/nome do arquivo de saida.
5. Informe a chave com 16 valores decimais separados por virgula.
6. Caso use CBC, informe tambem o IV com 16 valores decimais separados por virgula.

## Exemplo de Chave e IV

Chave:

```text
12,45,78,101,34,255,0,19,88,76,54,32,10,99,123,200
```

IV para CBC:

```text
1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16
```

Para descriptografar um arquivo em modo CBC, e necessario usar a mesma chave e o mesmo IV usados na criptografia.

## Observacoes

O programa trabalha com arquivos em modo binario, portanto pode criptografar arquivos de diferentes tipos, como `.txt`, `.pdf`, `.png`, `.jpg`, `.docx`, entre outros.

O modo ECB esta disponivel para fins didaticos, mas o modo CBC e mais indicado por oferecer maior seguranca contra repeticoes de padroes no arquivo criptografado.

## CLI

Alternativa ao menu interativo. Todos os parametros sao passados como argumentos, sem prompts.

```
uso: cli.py COMANDO [opcoes]

comandos:
  cifrar    Cifra um arquivo com AES-128
  decifrar  Decifra um arquivo com AES-128

opcoes (ambos os comandos):
  --modo {ECB,CBC}   Modo de operacao (padrao: CBC)
  --entrada ARQUIVO  Arquivo de entrada
  --saida   ARQUIVO  Arquivo de saida
  --chave   BYTES    16 valores decimais separados por virgula
  --iv      BYTES    IV para CBC: 16 valores decimais separados por virgula
```

### Exemplo 1 — Cifragem CBC

Cifra `arquivos/imagem_original.jpeg` e salva o resultado em `arquivos/imagem_cifrada.bin`:

```bash
python3 cli.py cifrar \
  --modo CBC \
  --entrada arquivos/imagem_original.jpeg \
  --saida arquivos/imagem_cifrada.bin \
  --chave 12,45,78,101,34,255,0,19,88,76,54,32,10,99,123,200 \
  --iv 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16
```

### Exemplo 2 — Decifragem CBC

Decifra `arquivos/imagem_cifrada.bin` de volta para a imagem original:

```bash
python3 cli.py decifrar \
  --modo CBC \
  --entrada arquivos/imagem_cifrada.bin \
  --saida arquivos/imagem_decifrada.jpeg \
  --chave 12,45,78,101,34,255,0,19,88,76,54,32,10,99,123,200 \
  --iv 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16
```

A chave e o IV devem ser identicos aos usados na cifragem para que a decifragem seja bem-sucedida.

