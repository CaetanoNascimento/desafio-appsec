# Desafio AppSec — Agente Especialista em Segurança de Aplicações

**Autor:** Caetano Nascimento

Este projeto especializa um agente de IA (Claude Code) para atuar como
**especialista em Segurança de Aplicações (AppSec)**. Em vez de entregar
respostas prontas, o agente **entende o contexto, avalia impacto,
probabilidade e severidade, e orienta a correção** — sempre com postura
defensiva.

---

## 1. O agente

O comportamento do agente é definido em três camadas:

| Camada          | Arquivo                                            | Papel                                                                 |
|-----------------|----------------------------------------------------|-----------------------------------------------------------------------|
| **Persona**     | `CLAUDE.md`                                        | Quem o agente é e as regras inegociáveis (contexto antes de ação, fundamentação em OWASP/CWE/MITRE/CID, nunca escrever exploit ou malware). Carregado automaticamente em toda sessão. |
| **Método**      | `.claude/skills/vulnerability-analysis/SKILL.md`   | Roteiro de análise em 6 fases e formato padrão de saída dos achados.  |
| **Conhecimento**| `knowledge/security-basics.md`                     | Conceitos de base: vulnerabilidade × ameaça × risco, tríade CID, frameworks e princípios de defesa. |

As 6 fases da skill:

1. Entender o contexto
2. Identificar a vulnerabilidade e mapear para OWASP / CWE / MITRE ATT&CK
3. Avaliar impacto (CID), probabilidade e severidade
4. Explicar a exploração **apenas conceitualmente**
5. Propor a correção explicando por que resolve
6. Validar que a falha foi mitigada

## 2. Estrutura do projeto

```
desafio-appsec/
├── CLAUDE.md                                  # persona e regras do agente
├── README.md                                  # este documento
├── .claude/
│   └── skills/
│       └── vulnerability-analysis/
│           └── SKILL.md                       # roteiro de análise
├── knowledge/
│   └── security-basics.md                     # base conceitual
├── src/
│   ├── app_vulneravel.py                      # login vulnerável (material de estudo)
│   └── app_corrigido.py                       # versão segura
├── docs/
│   └── analise.md                             # relatório completo dos achados
└── tests/
    └── test_login.py                          # validação da mitigação
```

## 3. A vulnerabilidade encontrada

`src/app_vulneravel.py` contém, **de propósito**, uma função de login que
monta a consulta SQL concatenando o que o usuário digitou
(`src/app_vulneravel.py:24`):

```python
query = "SELECT * FROM usuarios WHERE usuario = '" + usuario + "' AND senha = '" + senha + "'"
```

| Classificação | Valor                                         |
|---------------|-----------------------------------------------|
| OWASP Top 10  | A03:2021 – Injection                          |
| CWE           | CWE-89 – SQL Injection                        |
| MITRE ATT&CK  | T1190 – Exploit Public-Facing Application     |

**Como burlaria o login (conceitual):** o valor digitado vai para dentro
das aspas da query. Ao digitar uma aspa, o atacante "fecha" a string antes
da hora, e o que vem depois passa a ser interpretado como SQL. Assim é
possível anular a verificação de senha (por exemplo, transformando-a em
comentário) e entrar como `admin` sem conhecer a senha.

Achado secundário: a senha era armazenada em **texto puro**
(CWE-256, OWASP A02:2021).

## 4. Risco avaliado

| Pilar CID          | Impacto | Justificativa                                                         |
|--------------------|---------|-----------------------------------------------------------------------|
| Confidencialidade  | Alto    | Acesso à conta de qualquer usuário, inclusive admin; leitura de dados. |
| Integridade        | Alto    | Autenticação anulada; ações feitas em nome da vítima.                 |
| Disponibilidade    | Baixo   | `sqlite3.execute()` não executa comandos encadeados; resta degradação por consultas pesadas. |

- **Probabilidade:** Alta se a função estiver exposta (sem autenticação
  prévia, técnica amplamente conhecida, detectável por scanners); Baixa no
  uso puramente local.
- **Severidade:** **Crítica** no cenário exposto
  (CVSS v3.1 estimado ≈ 9.4 — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L`).

Relatório completo: [`docs/analise.md`](docs/analise.md).

## 5. Correção aplicada

`src/app_corrigido.py`:

| Medida                                | Problema que resolve                                    |
|---------------------------------------|---------------------------------------------------------|
| **Query parametrizada** (`?`)         | Causa raiz do SQL Injection: separa dado de comando.     |
| Validação de entrada (allowlist)      | Defesa em profundidade: rejeita formatos inesperados.    |
| Hash PBKDF2-HMAC-SHA256 + salt        | Senha deixa de existir em texto puro (CWE-256).          |
| `hmac.compare_digest`                 | Comparação em tempo constante.                           |
| Hash calculado mesmo p/ usuário inexistente + mensagem genérica | Não revela quais usuários existem. |

```python
conn.execute("SELECT salt, hash_senha FROM usuarios WHERE usuario = ?", (usuario,))
```

**Por que resolve:** a estrutura do SQL é fixa e o valor é enviado ao banco
separadamente, sempre como **dado**. Uma aspa digitada vira apenas um
caractere a ser procurado; ela não consegue mais alterar a estrutura da query.

### Validação

```bash
python -m unittest discover -s tests -v
```

Resultado: **8 testes aprovados**. A versão vulnerável é burlada pelas
entradas maliciosas; a corrigida as bloqueia — **inclusive com a validação
de entrada desligada**, o que prova que a proteção vem da parametrização, e
não de um filtro.

**Risco residual / próximos passos:** limitar tentativas de login (contra
força bruta, MITRE T1110), registrar falhas de autenticação para
monitoramento e usar conta de banco com menor privilégio.

## 6. Reflexão final sobre defesa

- **Prevenção de injeção:** a lição central é *separar dado de comando*.
  Tentar "limpar" a entrada (remover aspas, bloquear palavras como `OR`)
  é frágil e sempre tem brechas; a solução robusta é usar APIs que nunca
  misturam as duas coisas — queries parametrizadas, ORMs, `subprocess`
  com lista de argumentos, templates com escape automático.
- **Menor privilégio:** mesmo com o código correto, assuma que algo pode
  falhar. Se a conta do banco usada pelo login só pode ler a tabela de
  usuários, uma eventual injeção não consegue apagar tabelas nem ler o
  resto do sistema. O privilégio define o tamanho do estrago.
- **Validação de entrada:** é uma camada valiosa — reduz superfície de
  ataque, evita dados inválidos e entradas gigantes —, mas é
  **complementar**. Os testes mostram isso: a defesa se mantém mesmo sem
  ela, porque a causa raiz foi resolvida.
- **O papel do agente:** um bom especialista de AppSec não começa pela
  resposta, e sim pelas perguntas. Entender o contexto define a
  probabilidade, que define a severidade, que define a prioridade da
  correção. Este projeto codifica esse raciocínio para que o agente o
  aplique de forma consistente — e sempre do lado da defesa.
