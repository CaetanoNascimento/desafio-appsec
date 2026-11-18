# Análise de Segurança — `src/app_vulneravel.py`

Análise conduzida pelo agente AppSec seguindo a skill
`.claude/skills/vulnerability-analysis`.

## Fase 1 — Contexto considerado

- **Ativo:** função de autenticação (`login`) que consulta uma tabela de
  usuários em SQLite.
- **Exposição:** o script em si roda localmente via `input()`. Porém, uma
  função `login(usuario, senha)` é exatamente o que fica atrás de um
  formulário web ou de uma API. A análise considera **dois cenários**:
  (a) uso local, como está; (b) a mesma função reaproveitada em uma
  aplicação exposta na internet — o cenário realista de risco.
- **Dados:** credenciais de usuários, incluindo um administrador.
- **Quem interage:** qualquer pessoa que chegue à tela de login
  (usuário **não autenticado**).
- **Ambiente:** material de estudo; nenhum sistema real envolvido.

---

### [ACH-01] SQL Injection na função de login

| Campo              | Valor                                                        |
|--------------------|--------------------------------------------------------------|
| Local              | `src/app_vulneravel.py:24` (montagem) e `:25` (execução)     |
| OWASP Top 10       | A03:2021 – Injection                                         |
| CWE                | CWE-89 – Improper Neutralization of Special Elements used in an SQL Command |
| MITRE ATT&CK       | T1190 – Exploit Public-Facing Application                    |
| Confidencialidade  | **Alto**                                                     |
| Integridade        | **Alto**                                                     |
| Disponibilidade    | **Baixo**                                                    |
| Probabilidade      | **Alta** (cenário exposto) / Baixa (uso local)               |
| Severidade         | **Crítica** (cenário exposto) — CVSS v3.1 estimado ≈ 9.4 (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L`) |

**Descrição / causa raiz:** a linha 24 monta o comando SQL concatenando o
texto digitado pelo usuário entre aspas:

```python
query = "SELECT * FROM usuarios WHERE usuario = '" + usuario + "' AND senha = '" + senha + "'"
```

O banco recebe **uma única string** e não tem como distinguir o que é
comando (escrito pelo desenvolvedor) do que é dado (digitado pelo usuário).
Dado e comando estão misturados, e isso viola o princípio de separar dado
de comando.

**Impacto na tríade CID:**

- **Confidencialidade — Alto:** a falha permite entrar como outro usuário,
  inclusive `admin`, e acessar tudo o que essa conta vê. Em uma aplicação
  real, a mesma injeção pode ser usada para ler outras tabelas.
- **Integridade — Alto:** o controle de autenticação é anulado. O sistema
  passa a "acreditar" numa identidade falsa, e qualquer ação feita depois do
  login (alterar dados, aprovar operações) fica atribuída à vítima.
- **Disponibilidade — Baixo:** o `sqlite3.execute()` do Python executa
  apenas **um comando por chamada**, o que dificulta encadear comandos
  destrutivos. Ainda assim, consultas pesadas injetadas poderiam degradar o
  serviço. Com outros bancos/drivers, esse impacto pode ser maior.

**Probabilidade — Alta (se exposto):** não exige autenticação, a técnica é
amplamente conhecida e documentada, é detectável por scanners automáticos e
a tela de login costuma ser o primeiro ponto testado. Em uso estritamente
local, a probabilidade cai, pois só quem já tem acesso à máquina interage.

**Severidade:** Impacto Alto × Probabilidade Alta = **Crítica**.

**Como seria explorada (conceitual):** como o valor digitado vai para
dentro das aspas da query, um atacante pode digitar uma **aspa simples**
para "fechar" a string antes da hora. Tudo o que vier depois dela deixa de
ser tratado como texto e passa a ser **interpretado como SQL**. Com isso, o
atacante consegue acrescentar uma condição que é sempre verdadeira e/ou
transformar o restante da linha (a verificação de senha) em comentário.
Ilustração da *estrutura* resultante:

```
Pretendido: ... WHERE usuario = '<texto>' AND senha = '<texto>'
Injetado:   ... WHERE usuario = 'admin' --' AND senha = '...'
                                       └─ tudo daqui em diante vira comentário
```

A cláusula `AND senha = ...` some da lógica, e a consulta retorna o
usuário `admin` sem que a senha seja conhecida: **o login é burlado**.

**Correção recomendada:** usar **query parametrizada** (placeholders `?`),
de modo que a estrutura do SQL seja fixa e os valores sejam enviados
separadamente ao banco, sempre como dados. Defesa em profundidade:
validação de entrada (allowlist de formato e tamanho), conta de banco com
menor privilégio e mensagens de erro genéricas. Ver `src/app_corrigido.py`.

**Validação:** teste automatizado que envia entradas maliciosas para as duas
versões e verifica que somente a vulnerável é burlada
(`tests/test_login.py`).

**Risco residual:** nenhum para o ACH-01 após a correção; ver ACH-02.

---

### [ACH-02] Senha armazenada em texto puro

| Campo              | Valor                                                        |
|--------------------|--------------------------------------------------------------|
| Local              | `src/app_vulneravel.py:17` e comparação em `:24`             |
| OWASP Top 10       | A02:2021 – Cryptographic Failures                            |
| CWE                | CWE-256 – Plaintext Storage of a Password                    |
| MITRE ATT&CK       | T1552 – Unsecured Credentials                                |
| Confidencialidade  | **Alto**                                                     |
| Integridade        | **Médio**                                                    |
| Disponibilidade    | **Nenhum**                                                   |
| Probabilidade      | **Média** (depende de outra falha ou de acesso ao banco)     |
| Severidade         | **Alta**                                                     |

**Descrição / causa raiz:** a senha é gravada e comparada em texto puro.
Qualquer vazamento do banco (pela própria SQL Injection, por backup exposto
ou por acesso interno) revela as senhas reais, que costumam ser reutilizadas
em outros serviços.

**Correção recomendada:** armazenar apenas um **hash lento com salt**
(PBKDF2-HMAC-SHA256 com muitas iterações, ou bcrypt/Argon2) e comparar em
tempo constante.

**Validação:** conferir que a tabela não contém a senha original e que o
login correto continua funcionando.

---

## Fase 6 — Reanálise após a correção

Ver seção "Validação" no `README.md` e o resultado de `tests/test_login.py`.
