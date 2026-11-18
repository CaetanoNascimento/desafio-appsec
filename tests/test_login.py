"""Validacao (Fase 6): confirma que o SQL Injection existe na versao vulneravel
e foi mitigado na versao corrigida. Executar: python -m unittest -v"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import app_corrigido  # noqa: E402
import app_vulneravel  # noqa: E402

# Entradas maliciosas didaticas (mudam a estrutura da query na versao vulneravel).
ENTRADAS_MALICIOSAS = [
    ("admin' --", "qualquer"),
    ("' OR '1'='1' --", "qualquer"),
    ("admin", "' OR '1'='1"),
]


class TestVersaoVulneravel(unittest.TestCase):
    def setUp(self):
        self.conn = app_vulneravel.criar_banco()

    def test_login_legitimo_funciona(self):
        self.assertTrue(app_vulneravel.login(self.conn, "admin", "S3nh@Forte"))

    def test_sql_injection_burla_login(self):
        """Demonstra a falha: o login passa SEM a senha correta."""
        for usuario, senha in ENTRADAS_MALICIOSAS:
            with self.subTest(usuario=usuario, senha=senha):
                self.assertTrue(app_vulneravel.login(self.conn, usuario, senha))


class TestVersaoCorrigida(unittest.TestCase):
    def setUp(self):
        self.conn = app_corrigido.criar_banco()

    def test_login_legitimo_funciona(self):
        self.assertTrue(app_corrigido.login(self.conn, "admin", "S3nh@Forte"))

    def test_senha_errada_falha(self):
        self.assertFalse(app_corrigido.login(self.conn, "admin", "errada"))

    def test_usuario_inexistente_falha(self):
        self.assertFalse(app_corrigido.login(self.conn, "fulano", "S3nh@Forte"))

    def test_sql_injection_bloqueado(self):
        for usuario, senha in ENTRADAS_MALICIOSAS:
            with self.subTest(usuario=usuario, senha=senha):
                self.assertFalse(app_corrigido.login(self.conn, usuario, senha))

    def test_parametrizacao_protege_mesmo_sem_validacao(self):
        """Desliga a validacao de entrada: a protecao vem da query parametrizada."""
        with mock.patch.object(app_corrigido, "entrada_valida", return_value=True):
            for usuario, senha in ENTRADAS_MALICIOSAS:
                with self.subTest(usuario=usuario, senha=senha):
                    self.assertFalse(app_corrigido.login(self.conn, usuario, senha))

    def test_senha_nao_fica_em_texto_puro(self):
        linhas = self.conn.execute("SELECT * FROM usuarios").fetchall()
        for linha in linhas:
            for coluna in linha:
                self.assertNotIn(b"S3nh@Forte", coluna if isinstance(coluna, bytes) else coluna.encode())


if __name__ == "__main__":
    unittest.main()
