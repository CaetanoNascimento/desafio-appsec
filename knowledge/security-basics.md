# Fundamentos de Segurança de Aplicações

## 1. Conceitos essenciais

| Conceito          | Definição                                                                 | Exemplo                                                   |
|-------------------|---------------------------------------------------------------------------|-----------------------------------------------------------|
| **Vulnerabilidade** | Uma fraqueza no sistema (código, configuração, processo) que pode ser explorada. | Query SQL montada por concatenação de texto do usuário.   |
| **Ameaça**        | Algo ou alguém com potencial de explorar uma vulnerabilidade.             | Um atacante na internet testando formulários de login.    |
| **Risco**         | A chance de uma ameaça explorar uma vulnerabilidade **e** o dano resultante. | Vazamento da base de usuários via o formulário vulnerável. |

De forma simplificada:

> **Risco = Probabilidade × Impacto**

Sem vulnerabilidade não há o que explorar; sem ameaça, não há quem explore;
sem impacto, a exploração não importa. Gestão de risco é reduzir um ou mais
desses fatores — e corrigir a vulnerabilidade costuma ser o mais eficaz.

## 2. A tríade CID

| Pilar                | Pergunta-chave                                      | Ataque típico que o quebra             |
|----------------------|-----------------------------------------------------|----------------------------------------|
| **Confidencialidade** | Só quem deve consegue **ler** a informação?          | Vazamento de dados, SQL Injection      |
| **Integridade**      | A informação está **correta e não foi adulterada**?  | Alteração de registros, bypass de login |
| **Disponibilidade**  | O sistema está **acessível** quando necessário?      | DoS, exclusão de dados, ransomware     |

Toda análise de impacto deve dizer quais pilares são afetados e com que intensidade.

## 3. Frameworks de referência

### OWASP Top 10
Lista, mantida pela OWASP Foundation, das **categorias de risco mais críticas
em aplicações web**. Serve como linguagem comum e checklist de prioridades.
Ex.: **A03:2021 – Injection**, A01:2021 – Broken Access Control,
A07:2021 – Identification and Authentication Failures.

### CWE (Common Weakness Enumeration)
Catálogo, mantido pelo MITRE, de **tipos de fraquezas** em software e hardware.
É mais granular que o OWASP: descreve *o erro de programação/projeto*.
Ex.: **CWE-89** – SQL Injection, CWE-79 – XSS, CWE-916 – Hash de senha fraco.

### MITRE ATT&CK
Base de conhecimento das **táticas e técnicas usadas por adversários reais**.
Ajuda a enxergar a falha do ponto de vista de quem ataca — e, portanto, a
planejar detecção e resposta.
Ex.: **T1190** – Exploit Public-Facing Application, T1110 – Brute Force.

**Como se complementam:** OWASP diz *a categoria do risco*, CWE diz *qual é o
erro no código*, ATT&CK diz *como o adversário usaria isso*, e a tríade CID
diz *o que se perde*.

## 4. Princípios de defesa

- **Menor privilégio:** cada usuário, processo e conta de banco recebe
  apenas as permissões estritamente necessárias. Se algo for comprometido,
  o estrago fica contido. Ex.: a aplicação de login só precisa de `SELECT`
  na tabela de usuários.
- **Validação de entrada:** toda entrada externa é não confiável. Valide
  tipo, tamanho, formato e faixa — preferindo **lista de permitidos**
  (allowlist) a lista de proibidos. Validação é uma camada extra, **não**
  substitui a correção da causa raiz.
- **Separar dado de comando:** nunca deixe dados do usuário virarem parte
  do código executado (SQL, shell, HTML, LDAP...). Use APIs que mantêm os
  dois separados: queries parametrizadas, `subprocess` com lista de
  argumentos, escape contextual em templates.
- **Defesa em profundidade:** várias camadas independentes (validação,
  parametrização, menor privilégio, WAF, monitoramento), para que a falha
  de uma não comprometa tudo.
- **Falhar de forma segura:** em caso de erro, negar acesso e não expor
  detalhes internos (stack traces, mensagens do banco).
- **Proteger segredos:** senhas armazenadas com hash lento e com salt
  (PBKDF2, bcrypt, scrypt, Argon2), nunca em texto puro.
