import aes 

from utils import (
    ler_arquivo_binario,
    parse_decimal_bytes,
    salvar_arquivo_binario,
    validar_16_bytes,
)


def processar_arquivo(operacao, modo, arquivo_entrada, arquivo_saida, chave, iv=None):
    """
    Processa um arquivo usando AES-128 em ECB ou CBC.

    operacao: "cifrar" ou "decifrar"
    modo: "ECB" ou "CBC"
    """

    dados = ler_arquivo_binario(arquivo_entrada)

    if operacao == "cifrar":
        if modo == "ECB":
            resultado = aes.cifrar_ecb(dados, chave)
        elif modo == "CBC":
            resultado = aes.cifrar_cbc(dados, chave, iv)
        else:
            raise ValueError("Modo inválido.")

    elif operacao == "decifrar":
        if modo == "ECB":
            resultado = aes.decifrar_ecb(dados, chave)
        elif modo == "CBC":
            resultado = aes.decifrar_cbc(dados, chave, iv)
        else:
            raise ValueError("Modo inválido.")

    else:
        raise ValueError("Operação inválida.")

    salvar_arquivo_binario(arquivo_saida, resultado)

    return resultado


def menu_aes():
    print("=== AES-128 ===")
    print("1 - Cifrar")
    print("2 - Decifrar")

    opcao_operacao = input("Escolha a operação: ").strip()

    if opcao_operacao == "1":
        operacao = "cifrar"
    elif opcao_operacao == "2":
        operacao = "decifrar"
    else:
        raise ValueError("Operação inválida.")

    print()
    print("Modo de operação:")
    print("1 - ECB")
    print("2 - CBC")

    opcao_modo = input("Escolha o modo: ").strip()

    if opcao_modo == "1":
        modo = "ECB"
    elif opcao_modo == "2":
        modo = "CBC"
    else:
        raise ValueError("Modo inválido.")

    print()
    arquivo_entrada = input("Digite o caminho do arquivo de entrada: ").strip()

    if not arquivo_entrada:
        raise ValueError("O arquivo de entrada não pode ser vazio.")

    arquivo_saida = input("Digite o nome/caminho do arquivo de saída: ").strip()

    if not arquivo_saida:
        raise ValueError("O arquivo de saída não pode ser vazio.")

    print()
    chave_texto = input("Digite a chave com 16 valores decimais separados por vírgula: ")

    chave = validar_16_bytes(
        parse_decimal_bytes(chave_texto, "chave"),
        "chave"
    )

    iv = None

    if modo == "CBC":
        print()
        iv_texto = input("Digite o IV com 16 valores decimais separados por vírgula: ")

        iv = validar_16_bytes(
            parse_decimal_bytes(iv_texto, "IV"),
            "IV",
        )

    print()
    print("Processando...")

    resultado = processar_arquivo(
        operacao=operacao,
        modo=modo,
        arquivo_entrada=arquivo_entrada,
        arquivo_saida=arquivo_saida,
        chave=chave,
        iv=iv,
    )

    print("Processamento concluído.")
    print("Arquivo de entrada:", arquivo_entrada)
    print("Arquivo de saída:", arquivo_saida)
    print("Tamanho do resultado:", len(resultado), "bytes")


if __name__ == "__main__":
    menu_aes()
