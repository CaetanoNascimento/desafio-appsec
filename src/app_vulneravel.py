# =============================================================================
#  ATENCAO: CODIGO INTENCIONALMENTE VULNERAVEL - APENAS MATERIAL DE ESTUDO
# -----------------------------------------------------------------------------
#  Este arquivo contem uma falha de SQL Injection (CWE-89) PROPOSITAL, criada
#  para ser analisada e corrigida no desafio de AppSec.
#  NAO use este codigo em producao nem como base para outros projetos.
#  A versao segura esta em src/app_corrigido.py.
# =============================================================================
import sqlite3


def criar_banco():
    """Cria um banco em memoria com um usuario de exemplo."""
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE usuarios (usuario TEXT, senha TEXT)")
    # Falha adicional proposital: senha armazenada em texto puro (CWE-256).
    conn.execute("INSERT INTO usuarios VALUES ('admin', 'S3nh@Forte')")
    conn.commit()
    return conn


def login(conn, usuario, senha):
    # VULNERAVEL: a entrada do usuario e concatenada direto na query SQL.
    query = "SELECT * FROM usuarios WHERE usuario = '" + usuario + "' AND senha = '" + senha + "'"
    resultado = conn.execute(query).fetchone()
    return resultado is not None


if __name__ == "__main__":
    conn = criar_banco()
    usuario = input("Usuario: ")
    senha = input("Senha: ")
    if login(conn, usuario, senha):
        print("Login realizado com sucesso!")
    else:
        print("Usuario ou senha invalidos.")
