from __future__ import annotations

import argparse
import sys

from menu import processar_arquivo
from utils import parse_decimal_bytes, validar_16_bytes


def parse_chave(valor: str) -> bytes:
    return validar_16_bytes(parse_decimal_bytes(valor, "chave"), "chave")


def parse_iv(valor: str) -> bytes:
    return validar_16_bytes(parse_decimal_bytes(valor, "IV"), "IV")


def cmd_cifrar(args: argparse.Namespace) -> None:
    iv = parse_iv(args.iv) if args.modo == "CBC" else None

    resultado = processar_arquivo(
        operacao="cifrar",
        modo=args.modo,
        arquivo_entrada=args.entrada,
        arquivo_saida=args.saida,
        chave=parse_chave(args.chave),
        iv=iv,
    )

    print(f"Arquivo cifrado: {args.saida} ({len(resultado)} bytes)")


def cmd_decifrar(args: argparse.Namespace) -> None:
    iv = parse_iv(args.iv) if args.modo == "CBC" else None

    resultado = processar_arquivo(
        operacao="decifrar",
        modo=args.modo,
        arquivo_entrada=args.entrada,
        arquivo_saida=args.saida,
        chave=parse_chave(args.chave),
        iv=iv,
    )

    print(f"Arquivo decifrado: {args.saida} ({len(resultado)} bytes)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cli.py",
        description="AES-128 — cifrar e decifrar arquivos (ECB ou CBC)",
    )

    subparsers = parser.add_subparsers(dest="comando", metavar="COMANDO")
    subparsers.required = True

    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument(
        "--modo",
        choices=["ECB", "CBC"],
        default="CBC",
        help="Modo de operação (padrão: CBC)",
    )
    parent.add_argument(
        "--entrada",
        required=True,
        metavar="ARQUIVO",
        help="Caminho do arquivo de entrada",
    )
    parent.add_argument(
        "--saida",
        required=True,
        metavar="ARQUIVO",
        help="Caminho do arquivo de saída",
    )
    parent.add_argument(
        "--chave",
        required=True,
        metavar="BYTES",
        help="16 valores decimais separados por vírgula (ex: 0,1,2,...,15)",
    )
    parent.add_argument(
        "--iv",
        metavar="BYTES",
        help="IV para CBC: 16 valores decimais separados por vírgula",
    )

    subparsers.add_parser(
        "cifrar",
        parents=[parent],
        help="Cifra um arquivo com AES-128",
    )
    subparsers.add_parser(
        "decifrar",
        parents=[parent],
        help="Decifra um arquivo com AES-128",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.modo == "CBC" and not args.iv:
        parser.error("--iv é obrigatório no modo CBC")

    try:
        if args.comando == "cifrar":
            cmd_cifrar(args)
        elif args.comando == "decifrar":
            cmd_decifrar(args)
    except (ValueError, OSError) as e:
        print(f"Erro: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
