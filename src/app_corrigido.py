# =============================================================================
#  VERSAO CORRIGIDA de src/app_vulneravel.py
# -----------------------------------------------------------------------------
#  Correcoes aplicadas:
#   1. Query parametrizada (placeholders "?")  -> elimina SQL Injection (CWE-89)
#   2. Validacao de entrada por allowlist      -> defesa em profundidade
#   3. Senha com hash PBKDF2 + salt            -> elimina senha em texto puro (CWE-256)
#   4. Comparacao em tempo constante           -> evita vazamento por tempo de resposta
#   5. Mensagem de erro generica               -> nao revela se o usuario existe
# =============================================================================
import hashlib
import hmac
import re
import secrets
import sqlite3

# Usuario: 3 a 32 caracteres, apenas letras, numeros, ponto, hifen e underline.
PADRAO_USUARIO = re.compile(r"^[A-Za-z0-9._-]{3,32}$")
TAMANHO_MAX_SENHA = 128
ITERACOES_PBKDF2 = 600_000  # recomendacao OWASP para PBKDF2-HMAC-SHA256


def gerar_hash_senha(senha, salt=None):
    """Retorna (salt, hash) usando PBKDF2-HMAC-SHA256."""
    if salt is None:
        salt = secrets.token_bytes(16)
    hash_senha = hashlib.pbkdf2_hmac("sha256", senha.encode("utf-8"), salt, ITERACOES_PBKDF2)
    return salt, hash_senha


def entrada_valida(usuario, senha):
    """Validacao de entrada (allowlist). Camada extra, NAO substitui a parametrizacao."""
    if not isinstance(usuario, str) or not isinstance(senha, str):
        return False
    if not PADRAO_USUARIO.fullmatch(usuario):
        return False
    if not 1 <= len(senha) <= TAMANHO_MAX_SENHA:
        return False
    return True


def criar_banco():
    """Cria um banco em memoria com um usuario de exemplo (senha guardada como hash)."""
    conn = sqlite3.connect(":memory:")
    conn.execute(
        "CREATE TABLE usuarios (usuario TEXT PRIMARY KEY, salt BLOB NOT NULL, hash_senha BLOB NOT NULL)"
    )
    salt, hash_senha = gerar_hash_senha("S3nh@Forte")
    conn.execute(
        "INSERT INTO usuarios (usuario, salt, hash_senha) VALUES (?, ?, ?)",
        ("admin", salt, hash_senha),
    )
    conn.commit()
    return conn


def login(conn, usuario, senha):
    if not entrada_valida(usuario, senha):
        return False

    # SEGURO: a estrutura do SQL e fixa; o valor vai separado, sempre como DADO.
    linha = conn.execute(
        "SELECT salt, hash_senha FROM usuarios WHERE usuario = ?",
        (usuario,),
    ).fetchone()

    if linha is None:
        # Calcula um hash mesmo assim, para o tempo de resposta nao revelar
        # se o usuario existe ou nao.
        gerar_hash_senha(senha)
        return False

    salt, hash_armazenado = linha
    _, hash_informado = gerar_hash_senha(senha, salt)
    return hmac.compare_digest(hash_informado, hash_armazenado)


if __name__ == "__main__":
    conn = criar_banco()
    usuario = input("Usuario: ")
    senha = input("Senha: ")
    if login(conn, usuario, senha):
        print("Login realizado com sucesso!")
    else:
        print("Usuario ou senha invalidos.")
