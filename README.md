# 🔐 Projeto de Simulação de Ataques em Flask

Este projeto demonstra **vulnerabilidades comuns** encontradas em aplicações web, utilizando o framework **Flask** em Python. O objetivo é **educacional**, mostrando **como funcionam os ataques**, **como simulá-los** e **como aplicar medidas de segurança**.

---

## ⚠️ Aviso Legal

> Este projeto **não deve ser utilizado para atacar sistemas reais**. É exclusivamente para **estudo e testes locais**. Utilizar esse tipo de código contra servidores ou aplicações sem autorização **é crime** e viola políticas de uso ético.

---

## 📚 Vulnerabilidades Simuladas

| Tipo de Ataque           | Rota               | Descrição                                                                 |
|--------------------------|--------------------|---------------------------------------------------------------------------|
| SQL Injection            | `/usuario?id=1`    | Injeção de código SQL via parâmetros de URL                               |
| Cross-Site Scripting (XSS) | `/xss?nome=...`     | Injeção de scripts maliciosos no HTML da resposta                         |
| Brute Force (Força bruta) | `/login`            | Ataque de tentativa e erro para descobrir senhas                         |
| Path Traversal           | `/file?nome=...`   | Acesso a arquivos fora do diretório permitido                            |
| Remote Code Execution (RCE) | `/ping?host=...`    | Execução remota de comandos via parâmetros                               |
| DDoS (Layer 7) | `python ddos_layer_7.py` | Executa o script Python que simula um ataque DDoS na camada de aplicação (HTTP Flood), enviando múltiplas requisições simultâneas ao servidor alvo. |


---

## 🚀 Como Rodar o Projeto

### 1. Clone o repositório

```bash
git clone https://github.com/limarios/flask-vuln-simulator.git
cd ddos
```

### 2. Criando um ambiente virutal

```bash
python -m venv venv
source venv/bin/activate  # ou venv\Scripts\activate no Windows
```

### 3. Instale as dependências

```bash
pip install -r requirements.txt
```

### 4. Execute o servidor Flask
```bash
python server_all.py
```
 >O servidor estará disponível em ```http://127.0.0.1:5000```


## 🧪 Exemplos de Ataques

🔸 SQL Injection

```bash
http://127.0.0.1:5000/usuario?id=1 OR 1=1
```


🔸 XSS
```bash
http://127.0.0.1:5000/xss?nome=<script>alert("xss")</script>
```


🔸 Brute Force

> Use um script Python para tentar várias senhas contra /login.


🔸 Path Traversal
```bash
http://127.0.0.1:5000/file?nome=../../etc/passwd
```

🔸 RCE
```bash
http://127.0.0.1:5000/ping?host=127.0.0.1;ls
```

## 🛡️ Recomendações de Correção

Cada rota contém vulnerabilidades propositalmente. Veja no código como seriam feitas as correções recomendadas usando boas práticas como:

Parâmetros preparados com SQLite

Escapamento de HTML com Jinja2

Limitação de tentativas com Flask-Limiter

Validação e sanitização de entrada

Substituição de os.system por subprocess.run com shell=False

## 📁 Estrutura do Projeto
```bash
.
├── servidor_vulneravel.py    # Aplicação Flask com rotas vulneráveis
├── app/
│   └── ddos_layer_7.py       # Arquivo exemplo para ataque ddos real
│   └── ddos.py               # Arquivo exemplo para ataque ddos básico
│   └── server_all.py         # Arquivo do servidor Flask com vulnerabilidades
│   └── server_layer.py       # Arquivo 2 do servidor Flask com vulnerabilidade para layer 7
│   └── server.py             # Arquivo do servidor Flask básico para ddos básico.
├── requirements.txt          # Arquivos de dependencias do ambiente virtual
├── README.md                 # Este arquivo
```

## 🧠 Objetivo Didático

Este projeto pode ser utilizado para:
<li>- Aulas de segurança de aplicações web</li>
<li>- Laboratórios de cibersegurança</li>
<li>- Testes em ambientes isolados</li>
<li>- Estudo individual de boas práticas de Flask</li>



## 📄 Licença
Distribuído sob a licença MIT. Veja ```LICENSE``` para mais informações.



## ✍️ Autor

Desenvolvido por Matheus Lima.
>Sinta-se livre para colaborar, sugerir melhorias ou adaptar ao seu curso/projeto!
