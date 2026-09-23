# Safe Surface Scanner

Aplicação web local, sem dependências externas, para avaliação **autorizada**, passiva e não destrutiva de uma URL HTTP/HTTPS. O projeto combina uma interface simples no navegador com uma API que inspeciona a superfície pública de uma aplicação e produz um relatório de hardening.

> Use somente em sistemas que você possui ou para os quais tem autorização explícita. O scanner não substitui um teste de segurança completo.

## O que o projeto verifica

- Headers de segurança: CSP, HSTS, proteção contra clickjacking, MIME sniffing, `Referrer-Policy` e `Permissions-Policy`.
- Cookies enviados pela resposta: `Secure`, `HttpOnly` e `SameSite`.
- Configuração CORS permissiva, incluindo a combinação de curingas com credenciais.
- Divulgação de tecnologia por `Server` e `X-Powered-By`.
- Formulários de senha servidos por HTTP.
- Possíveis referências de conteúdo misto em páginas HTTPS.
- Disponibilidade de `robots.txt` e `/.well-known/security.txt`.
- Status, tempo de resposta, IP conectado e metadados básicos de TLS.
- Acessibilidade de HTTP sem redirecionamento para HTTPS, quando o alvo HTTPS usa a porta padrão.

O scanner não executa exploração, brute force, enumeração agressiva, fuzzing, autenticação, alteração de estado ou envio de payloads destrutivos.

## Requisitos

- Python 3.10 ou superior.
- Nenhum pacote externo: a aplicação usa apenas a biblioteca padrão do Python.

## Execução

Na raiz do projeto:

```bash
python3 app.py
```

O servidor fica disponível somente na interface local:

<http://127.0.0.1:8787>

Também é possível verificar a disponibilidade da aplicação:

```bash
curl http://127.0.0.1:8787/healthz
```

Resposta esperada:

```json
{"ok": true}
```

## Uso da API

### Executar um scan

`POST /api/scan` recebe um objeto JSON com o campo `url`:

```bash
curl -sS -X POST http://127.0.0.1:8787/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com"}'
```

Se o esquema não for informado, `https://` será assumido:

```json
{"url":"example.com"}
```

O resultado contém, entre outros campos:

```json
{
  "target": "https://example.com/",
  "finished_at": "2026-01-01T00:00:00+00:00",
  "duration_ms": 421,
  "requests": 3,
  "response": {
    "status": 200,
    "content_type": "text/html"
  },
  "summary": {
    "total": 0,
      "counts": {
      "CRÍTICA": 0,
      "ALTA": 0,
      "MÉDIA": 1,
      "BAIXA": 0,
      "INFORMATIVA": 0
    }
  },
  "findings": [],
  "observations": [],
  "errors": [],
  "scope": "Somente verificações passivas..."
}
```

Cada item em `findings` informa `id`, `title`, `severity`, `category`, `evidence`, `recommendation` e `confidence`. As severidades são ordenadas de `CRÍTICA` a `INFORMATIVA`.

Erros de validação ou de destino retornam HTTP `400` com o formato:

```json
{"error":"mensagem explicando o problema"}
```

## Regras de segurança do scanner

As validações ocorrem antes da conexão de rede e limitam o escopo do scan:

- Apenas esquemas `http` e `https` são aceitos.
- Usuário e senha embutidos na URL são rejeitados.
- Destinos públicos são aceitos; endereços privados, reservados, multicast e link-local são bloqueados.
- `localhost` e endereços de loopback explícitos são permitidos para testes locais, desde que resolvam para loopback.
- Redirecionamentos para outro hostname são bloqueados.
- São seguidos no máximo 3 redirecionamentos.
- Cada conexão possui timeout de 8 segundos.
- O corpo da resposta é limitado a 512 KiB.
- O corpo de uma requisição para a API é limitado a 16 KiB.
- O servidor escuta em `127.0.0.1:8787`, não em todas as interfaces.

Essas proteções reduzem o risco de SSRF e de consumo excessivo de recursos, mas não devem ser tratadas como uma fronteira de segurança para expor a aplicação diretamente à internet.

## Estrutura do projeto

```text
.
├── app.py                 # Servidor HTTP local, UI e endpoint da API
├── scanner.py             # Validação, requisições e verificações passivas
├── static/
│   ├── index.html         # Interface da aplicação
│   ├── app.js             # Envio do scan e renderização do relatório
│   └── style.css          # Estilos da interface
└── tests/
    └── test_scanner.py    # Testes das validações de segurança
```

## Testes

Execute a suíte com:

```bash
python3 -m unittest discover -s tests -v
```

Os testes cobrem, principalmente, normalização de URLs, rejeição de credenciais e esquemas inválidos, bloqueio de destinos privados e permissão controlada para `localhost`.

## Limitações e uso em produção

Este projeto é um baseline de observabilidade e hardening. Ele não cobre, por exemplo, autenticação, autorização, lógica de negócio, APIs autenticadas, vulnerabilidades de aplicação, dependências, configuração do servidor de origem ou testes DAST completos.

Antes de expor a API além do loopback, implemente pelo menos autenticação, autorização, auditoria, rate limiting por usuário, fila de jobs, isolamento de rede, limites de concorrência e uma política explícita de escopo. Revise também a validação contra DNS rebinding e o modelo de resolução de endereços para o ambiente de implantação.

## Licença

Este projeto está licenciado sob a [licença MIT](LICENSE). Consulte o arquivo `LICENSE` para o texto completo.
