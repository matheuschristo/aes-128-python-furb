BLOCK_SIZE = 16

def parse_decimal_bytes(texto, nome="entrada"):
    valores = [int(x.strip()) for x in texto.split(",")]

    for v in valores:
        if v < 0 or v > 255:
            raise ValueError(
                f"{nome}: o valor {v} é inválido. Use apenas valores entre 0 e 255."
            )

    return valores


def validar_16_bytes(valores, nome="entrada"):
    if len(valores) != 16:
        raise ValueError(
            f"{nome}: deve possuir exatamente 16 bytes. "
            f"Foram informados {len(valores)}."
        )

    return bytes(valores)


def aplicar_pkcs7_padding(dados):
    falta = BLOCK_SIZE - (len(dados) % BLOCK_SIZE)

    if falta == 0:
        falta = BLOCK_SIZE

    return dados + bytes([falta] * falta)


def remover_pkcs7_padding(dados):
    if len(dados) == 0:
        raise ValueError("Dados vazios. Não é possível remover padding.")

    if len(dados) % BLOCK_SIZE != 0:
        raise ValueError("Dados inválidos. O tamanho não é múltiplo de 16 bytes.")

    valor_padding = dados[-1]
    if valor_padding < 1 or valor_padding > BLOCK_SIZE:
        raise ValueError("Padding inválido.")

    padding = dados[-valor_padding:]
    if padding != bytes([valor_padding] * valor_padding):
        raise ValueError("Padding inválido.")

    return dados[:-valor_padding]


def ler_arquivo_binario(caminho):
    with open(caminho, "rb") as arquivo:
        return arquivo.read()


def salvar_arquivo_binario(caminho, dados):
    with open(caminho, "wb") as arquivo:
        arquivo.write(dados)
