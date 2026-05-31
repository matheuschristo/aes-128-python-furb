from __future__ import annotations

import re

from pathlib import Path
from utils import aplicar_pkcs7_padding, remover_pkcs7_padding

State = list[list[int]]
Word = list[int]
RoundKeys = list[State]


def carregar_tabelas_aes(caminho: Path) -> dict[str, list[int]]:
    tabelas = {
        "sbox": [],
        "tabela_l": [],
        "tabela_e": [],
        "inv_sbox": [],
    }

    secao_atual = None

    with open(caminho, "r", encoding="utf-8") as arquivo:
        for linha in arquivo:
            linha = linha.strip()

            if not linha:
                continue

            linha_upper = linha.upper()

            if linha_upper.startswith("SBOX"):
                secao_atual = "sbox"
                continue

            if linha_upper.startswith("TABELA L"):
                secao_atual = "tabela_l"
                continue

            if linha_upper.startswith("TABELA E"):
                secao_atual = "tabela_e"
                continue

            if linha_upper.startswith("INVERSE S-BOX"):
                secao_atual = "inv_sbox"
                continue

            if secao_atual is not None:
                valores_hex = re.findall(r"\b[0-9a-fA-F]{2}\b", linha)
                tabelas[secao_atual].extend(int(valor, 16) for valor in valores_hex)

    return tabelas


CAMINHO_TABELAS = Path(__file__).with_name("Tabelas (1).txt")
TABELAS_AES = carregar_tabelas_aes(CAMINHO_TABELAS)

SBOX = TABELAS_AES["sbox"]
TABELA_L = TABELAS_AES["tabela_l"]
TABELA_E = TABELAS_AES["tabela_e"]
INV_SBOX = TABELAS_AES["inv_sbox"]
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def bytes_para_estado(bloco: bytes) -> State:
    if len(bloco) != 16:
        raise ValueError("O bloco deve ter exatamente 16 bytes.")

    estado = [[0 for _ in range(4)] for _ in range(4)]

    for i in range(4):
        for j in range(4):
            estado[j][i] = bloco[i * 4 + j]

    return estado


def estado_para_bytes(estado: State) -> bytes:
    saida = []

    for i in range(4):
        for j in range(4):
            saida.append(estado[j][i])

    return bytes(saida)


def imprimir_estado(estado: State, titulo: str) -> None:
    print(titulo)
    for i in estado:
        print(" ".join(f"0x{valor:02x}" for valor in i))
    print()


def add_round_key(estado: State, round_key: State) -> State:
    resultado = [[0 for _ in range(4)] for _ in range(4)]

    for i in range(4):
        for j in range(4):
            resultado[i][j] = estado[i][j] ^ round_key[i][j]

    return resultado


def sub_bytes(estado: State) -> State:
    resultado = [[0 for _ in range(4)] for _ in range(4)]

    for i in range(4):
        for j in range(4):
            resultado[i][j] = SBOX[estado[i][j]]

    return resultado


def inv_sub_bytes(estado: State) -> State:
    resultado = [[0 for _ in range(4)] for _ in range(4)]

    for i in range(4):
        for j in range(4):
            resultado[i][j] = INV_SBOX[estado[i][j]]

    return resultado


def shift_rows(estado: State) -> State:
    resultado = []

    for i in range(4):
        nova_linha = estado[i][i:] + estado[i][:i]
        resultado.append(nova_linha)

    return resultado


def inv_shift_rows(estado: State) -> State:
    resultado = []

    for i in range(4):
        nova_linha = estado[i][-i:] + estado[i][:-i] if i != 0 else estado[i][:]
        resultado.append(nova_linha)

    return resultado


def multiplicar_galois(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0

    if a == 1:
        return b

    if b == 1:
        return a

    soma = TABELA_L[a] + TABELA_L[b]
    if soma > 0xFF:
        soma -= 0xFF

    return TABELA_E[soma]


def mix_columns(estado: State) -> State:
    resultado = [[0 for _ in range(4)] for _ in range(4)]

    for coluna in range(4):
        a0 = estado[0][coluna]
        a1 = estado[1][coluna]
        a2 = estado[2][coluna]
        a3 = estado[3][coluna]

        resultado[0][coluna] = (
            multiplicar_galois(a0, 2)
            ^ multiplicar_galois(a1, 3)
            ^ multiplicar_galois(a2, 1)
            ^ multiplicar_galois(a3, 1)
        )
        resultado[1][coluna] = (
            multiplicar_galois(a0, 1)
            ^ multiplicar_galois(a1, 2)
            ^ multiplicar_galois(a2, 3)
            ^ multiplicar_galois(a3, 1)
        )
        resultado[2][coluna] = (
            multiplicar_galois(a0, 1)
            ^ multiplicar_galois(a1, 1)
            ^ multiplicar_galois(a2, 2)
            ^ multiplicar_galois(a3, 3)
        )
        resultado[3][coluna] = (
            multiplicar_galois(a0, 3)
            ^ multiplicar_galois(a1, 1)
            ^ multiplicar_galois(a2, 1)
            ^ multiplicar_galois(a3, 2)
        )

    return resultado


def inv_mix_columns(estado: State) -> State:
    resultado = [[0 for _ in range(4)] for _ in range(4)]

    for coluna in range(4):
        a0 = estado[0][coluna]
        a1 = estado[1][coluna]
        a2 = estado[2][coluna]
        a3 = estado[3][coluna]

        resultado[0][coluna] = (
            multiplicar_galois(a0, 0x0E)
            ^ multiplicar_galois(a1, 0x0B)
            ^ multiplicar_galois(a2, 0x0D)
            ^ multiplicar_galois(a3, 0x09)
        )
        resultado[1][coluna] = (
            multiplicar_galois(a0, 0x09)
            ^ multiplicar_galois(a1, 0x0E)
            ^ multiplicar_galois(a2, 0x0B)
            ^ multiplicar_galois(a3, 0x0D)
        )
        resultado[2][coluna] = (
            multiplicar_galois(a0, 0x0D)
            ^ multiplicar_galois(a1, 0x09)
            ^ multiplicar_galois(a2, 0x0E)
            ^ multiplicar_galois(a3, 0x0B)
        )
        resultado[3][coluna] = (
            multiplicar_galois(a0, 0x0B)
            ^ multiplicar_galois(a1, 0x0D)
            ^ multiplicar_galois(a2, 0x09)
            ^ multiplicar_galois(a3, 0x0E)
        )

    return resultado


def rot_word(word: Word) -> Word:
    return word[1:] + word[:1]


def sub_word(word: Word) -> Word:
    return [SBOX[byte] for byte in word]


def xor_words(word_a: Word, word_b: Word) -> Word:
    return [a ^ b for a, b in zip(word_a, word_b)]


def gerar_words_da_chave(chave: bytes) -> list[Word]:
    words = []

    for i in range(4):
        word = [
            chave[4 * i],
            chave[4 * i + 1],
            chave[4 * i + 2],
            chave[4 * i + 3],
        ]
        words.append(word)

    # Gera w4 ate w43.
    for i in range(4, 44):
        temp = words[i - 1][:]

        if i % 4 == 0:
            temp = rot_word(temp)
            temp = sub_word(temp)
            temp[0] = temp[0] ^ RCON[(i // 4) - 1]

        nova_word = xor_words(words[i - 4], temp)
        words.append(nova_word)

    return words


def words_para_round_key(words: list[Word], numero_round: int) -> State:
    round_key = [[0 for _ in range(4)] for _ in range(4)]
    inicio = numero_round * 4

    for i in range(4):
        word = words[inicio + i]
        for j in range(4):
            round_key[j][i] = word[j]

    return round_key


def expandir_chave(chave: bytes) -> RoundKeys:
    words = gerar_words_da_chave(chave)
    round_keys = []

    for numero_round in range(11):
        round_key = words_para_round_key(words, numero_round)
        round_keys.append(round_key)

    return round_keys


def cifrar_bloco(bloco: bytes, round_keys: RoundKeys) -> bytes:
    estado = bytes_para_estado(bloco)
    estado = add_round_key(estado, round_keys[0])

    for rodada in range(1, 10):
        estado = sub_bytes(estado)
        estado = shift_rows(estado)
        estado = mix_columns(estado)
        estado = add_round_key(estado, round_keys[rodada])

    estado = sub_bytes(estado)
    estado = shift_rows(estado)
    estado = add_round_key(estado, round_keys[10])

    return estado_para_bytes(estado)


def decifrar_bloco(bloco: bytes, round_keys: RoundKeys) -> bytes:
    estado = bytes_para_estado(bloco)
    estado = add_round_key(estado, round_keys[10])
    estado = inv_shift_rows(estado)
    estado = inv_sub_bytes(estado)

    for rodada in range(9, 0, -1):
        estado = add_round_key(estado, round_keys[rodada])
        estado = inv_mix_columns(estado)
        estado = inv_shift_rows(estado)
        estado = inv_sub_bytes(estado)

    estado = add_round_key(estado, round_keys[0])

    return estado_para_bytes(estado)


def dividir_em_blocos(dados: bytes, tamanho_bloco: int = 16) -> list[bytes]:
    blocos = []

    for i in range(0, len(dados), tamanho_bloco):
        blocos.append(dados[i:i + tamanho_bloco])

    return blocos


def cifrar_ecb(dados: bytes, chave: bytes) -> bytes:
    round_keys = expandir_chave(chave)
    dados_com_padding = aplicar_pkcs7_padding(dados)
    blocos = dividir_em_blocos(dados_com_padding)

    dados_cifrados = b""

    for bloco in blocos:
        bloco_cifrado = cifrar_bloco(bloco, round_keys)
        dados_cifrados += bloco_cifrado

    return dados_cifrados


def decifrar_ecb(dados_cifrados: bytes, chave: bytes) -> bytes:
    round_keys = expandir_chave(chave)
    blocos = dividir_em_blocos(dados_cifrados)

    dados_decifrados_com_padding = b""

    for bloco in blocos:
        bloco_decifrado = decifrar_bloco(bloco, round_keys)
        dados_decifrados_com_padding += bloco_decifrado

    return remover_pkcs7_padding(dados_decifrados_com_padding)


def xor_bytes(bytes_a: bytes, bytes_b: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(bytes_a, bytes_b))


def cifrar_cbc(dados: bytes, chave: bytes, iv: bytes) -> bytes:
    round_keys = expandir_chave(chave)
    dados_com_padding = aplicar_pkcs7_padding(dados)
    blocos = dividir_em_blocos(dados_com_padding)

    dados_cifrados = b""
    bloco_anterior = iv

    for bloco in blocos:
        bloco_xor = xor_bytes(bloco, bloco_anterior)
        bloco_cifrado = cifrar_bloco(bloco_xor, round_keys)

        dados_cifrados += bloco_cifrado
        bloco_anterior = bloco_cifrado

    return dados_cifrados


def decifrar_cbc(dados_cifrados: bytes, chave: bytes, iv: bytes) -> bytes:
    round_keys = expandir_chave(chave)
    blocos = dividir_em_blocos(dados_cifrados)

    dados_decifrados_com_padding = b""
    bloco_anterior = iv

    for bloco_cifrado in blocos:
        bloco_decifrado_xor = decifrar_bloco(bloco_cifrado, round_keys)
        bloco_original = xor_bytes(bloco_decifrado_xor, bloco_anterior)

        dados_decifrados_com_padding += bloco_original
        bloco_anterior = bloco_cifrado

    return remover_pkcs7_padding(dados_decifrados_com_padding)
