# Flask Security Lab — Red Team ⚔ Blue Team

> Uma aplicação Flask onde **cada vulnerabilidade vem acompanhada do ataque, da correção e da detecção.** Feita para ser estudada, atacada e defendida.

[![CI](https://github.com/limarios/flask-security-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/limarios/flask-security-lab/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![OWASP Top 10](https://img.shields.io/badge/OWASP%20Top%2010-7%2F10%20cobertas-orange.svg)](docs/threat-model.md)

🇬🇧 **[Read in English](README.md)**

---

> ### ⚠️ Uso exclusivamente educacional
> Este projeto contém **vulnerabilidades intencionais**. **Nunca** deve ser colocado em produção ou exposto além da sua máquina local. As ferramentas ofensivas são **restritas ao loopback por design**. Atacar sistemas que você não possui ou não tem autorização escrita para testar é crime (Brasil: Lei 12.737/2012 "Carolina Dieckmann" e Lei 14.155/2021; EUA: CFAA; Reino Unido: Computer Misuse Act). Veja o [SECURITY.md](SECURITY.md).

---

## Por que existe

A maioria dos projetos de "app vulnerável" só mostra o código quebrado. Este foi construído em torno de uma ideia: **para cada falha, você deveria conseguir ver os três lados dela.**

- 🔴 **Red Team** — o ataque que quebra o endpoint ingênuo (`/vulnerable/*`)
- 🔵 **Blue Team** — o gêmeo defendido que derrota o mesmo ataque (`/secure/*`)
- 🛰️ **Detecção** — o logging por assinatura, em tempo de request, que identifica o ataque acontecendo

Os dois lados vivem em **módulos espelhados** (`src/lab/vulnerable/sql_injection.py` ↔ `src/lab/secure/sql_injection.py`), então a diferença entre o *errado* e o *certo* é estrutural, não enterrada em texto. E é **verificável**: a suíte de testes prova que cada ataque funciona contra o código ingênuo e falha contra a correção.

## A demonstração, em um comando

Suba o lab e rode todo o catálogo de ataques contra ele:

```console
$ python -m red_team all --target http://127.0.0.1:5000

Target: http://127.0.0.1:5000  (loopback verified)

=== SQL Injection ===
  Red  (/vulnerable): leaked 3 row(s) incl. credentials: [{'username': 'admin123', ...}]
  Blue (/secure)    : HTTP 403 (input rejected / parameterized)

=== Reflected XSS ===
  Red  (/vulnerable): payload reflected unescaped
  Blue (/secure)    : payload escaped

=== Brute Force ===
  Red  (/vulnerable): password cracked: 'admin123'
  Blue (/secure)    : 3/8 attempts rate-limited (HTTP 429)

=== IDOR ===
  Red  (/vulnerable): read another user's note: 'Master recovery code: 8F3K-9920-ZZ'
  Blue (/secure)    : HTTP 403 (ownership check denied access)

   ... e SSTI, Command Injection, Path Traversal, SSRF, Deserialização, JWT, load test L7
```

Cada linha é a saída real de uma requisição real. O atacante vence à esquerda; o defensor vence à direita.

## Matriz de vulnerabilidades

Dez vulnerabilidades cobrindo **7 das 10 categorias do OWASP Top 10 (2021)**. Cada uma com um material focado.

| # | Vulnerabilidade | OWASP | CWE | Defesa principal | Docs |
|---|---|---|---|---|---|
| 1 | SQL Injection | A03 Injection | CWE-89 | Query parametrizada | [↗](docs/vulnerabilities/01-sql-injection.md) |
| 2 | XSS Refletido | A03 Injection | CWE-79 | Escape de saída + CSP | [↗](docs/vulnerabilities/02-xss.md) |
| 3 | Brute Force / Auth Quebrada | A07 Auth Failures | CWE-307 | Rate limit + hash de senha | [↗](docs/vulnerabilities/03-brute-force.md) |
| 4 | Path Traversal | A01 Broken Access Control | CWE-22 | `safe_join` + checagem de realpath | [↗](docs/vulnerabilities/04-path-traversal.md) |
| 5 | Command Injection (RCE) | A03 Injection | CWE-78 | `subprocess` sem shell + validação | [↗](docs/vulnerabilities/05-command-injection.md) |
| 6 | Server-Side Template Injection | A03 Injection | CWE-1336 | Input como dado, não como template | [↗](docs/vulnerabilities/06-ssti.md) |
| 7 | IDOR | A01 Broken Access Control | CWE-639 | Checagem de propriedade/autorização | [↗](docs/vulnerabilities/07-idor.md) |
| 8 | SSRF | A10 SSRF | CWE-918 | Allowlist de scheme + bloqueio de IP privado | [↗](docs/vulnerabilities/08-ssrf.md) |
| 9 | Deserialização Insegura | A08 Integrity Failures | CWE-502 | JSON no lugar de pickle | [↗](docs/vulnerabilities/09-insecure-deserialization.md) |
| 10 | Bypass de Assinatura JWT | A02 Cryptographic Failures | CWE-347 | Verificar assinatura + fixar algoritmo | [↗](docs/vulnerabilities/10-jwt-signature-bypass.md) |

A09 (Logging e Monitoramento) é coberta pela própria camada Blue Team. Veja o mapeamento completo no **[threat model](docs/threat-model.md)**.

## A chave `BLUE_TEAM_ENABLED`

O mesmo app roda em dois modos, controlados por uma única flag — é isso que torna possível a história "antes / depois" sem manter duas bases de código:

| Modo | Comportamento |
|---|---|
| `BLUE_TEAM_ENABLED=false` | App ingênuo: sem security headers, sem detecção, sem WAF. Os ataques simplesmente funcionam. |
| `BLUE_TEAM_ENABLED=true` | Defesas ligadas via hooks de request: **logging estruturado de ataques em JSON**, um **mini-WAF por assinatura** (bloqueia `/secure/*` e deixa `/vulnerable/*` explorável de propósito), **security headers** (CSP, `X-Frame-Options`, …) e **rate limiting**. |

Quando o WAF detecta um ataque, ele emite uma linha de log estilo SOC — é o OWASP A09 bem feito:

```json
{"event": "attack_detected", "categories": ["sql_injection"], "path": "/secure/sql",
 "remote_addr": "127.0.0.1", "blocked": true, "level": "warning", "timestamp": "..."}
```

## Como rodar

### Local (Python 3.10+)

```bash
git clone https://github.com/limarios/flask-security-lab.git
cd flask-security-lab

python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

python wsgi.py                       # lab defendido em http://127.0.0.1:5000
```

Abra `http://127.0.0.1:5000` para o painel, depois ataque:

```bash
python -m red_team sqli              # um ataque
python -m red_team all               # o catálogo inteiro
```

### Docker

Sobe os dois modos lado a lado — defendido em `:5000`, ingênuo em `:5001` (publicados só no loopback):

```bash
docker compose up
```

## Como é construído

```
src/
├── lab/
│   ├── __init__.py        # Application Factory: create_app()
│   ├── config.py          # configs Dev / Lab / Test + a flag BLUE_TEAM_ENABLED
│   ├── db.py              # camada SQLite enxuta (parametrizada vs crua)
│   ├── catalog.py         # fonte única da lista de vulnerabilidades
│   ├── vulnerable/        # 🔴 blueprints ingênuos  -> /vulnerable/*
│   ├── secure/            # 🔵 gêmeos defendidos      -> /secure/*
│   ├── blue_team/         # detecção, mini-WAF, security headers, logging JSON
│   ├── templates/ static/ # o painel com tema SOC
├── red_team/              # CLI de ataque loopback-only (guard.py impõe 127.0.0.1)
tests/                     # test_vulnerable (ataque funciona) + test_secure (defesa segura) + test_blue_team
docs/                      # arquitetura, threat model, ADRs, materiais por vulnerabilidade
```

As decisões de arquitetura estão registradas como **[ADRs](docs/adr/)**; o design está explicado em **[docs/architecture.md](docs/architecture.md)**.

## Testes

A suíte materializa a tese do projeto — cada vulnerabilidade tem um teste que **prova que o ataque funciona** e outro que **prova que a correção segura**:

```bash
pytest                       # tudo
pytest -m vulnerable         # só os testes de ataque-funciona
pytest -m secure             # só os testes de defesa-segura
pytest -m blue_team          # WAF / detecção / headers
```

## Documentação

- **[Arquitetura](docs/architecture.md)** — factory, camadas, fluxo de request
- **[Threat model](docs/threat-model.md)** — mapeamento completo do OWASP Top 10
- **[Materiais por vulnerabilidade](docs/vulnerabilities/)** — um por vulnerabilidade: teoria, exploit, correção, detecção
- **[ADRs](docs/adr/)** — por que o projeto tem o formato que tem

## Contribuindo e segurança

Contribuições são bem-vindas — veja o **[CONTRIBUTING.md](CONTRIBUTING.md)** para o setup de desenvolvimento e o padrão de adicionar uma nova vulnerabilidade. Leia o **[SECURITY.md](SECURITY.md)** antes: as vulnerabilidades aqui são intencionais e não devem ser reportadas como bugs.

## Licença

MIT © Matheus Lima — veja [LICENSE](LICENSE).
