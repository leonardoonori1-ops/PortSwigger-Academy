# PortSwigger Web Security Academy — Writeup & Report

Raccolta di **writeup tecnici e report** dei laboratori della [PortSwigger Web Security Academy](https://portswigger.net/web-security), svolti a scopo formativo nell'ambito del mio percorso in **Cybersecurity & Ethical Hacking**.

Ogni cartella contiene un writeup in Markdown (metodologia, payload, impatto, remediation) e, dove presente, un report tecnico in PDF impaginato in stile professionale.

> **Nota** — Tutte le attività sono state condotte esclusivamente sulle istanze di laboratorio messe a disposizione da PortSwigger (dominio `*.web-security-academy.net`), in un ambiente autorizzato e isolato. Nessun sistema di produzione è stato coinvolto.

---

## Indice dei laboratori

| # | Laboratorio | Categoria | Severità | Writeup |
|---|---|---|:---:|:---:|
| 01 | SQL injection — Database version (MySQL/MSSQL) | SQLi · CWE-89 | High | [📄](./01-sqli-database-version-mysql-mssql/) |
| 02 | SQL injection — Enumerazione DB (PostgreSQL) | SQLi · CWE-89 | Critical | [📄](./02-sqli-listing-db-postgresql/) |
| 03 | Reflected XSS — AngularJS sandbox escape + CSP | XSS · CWE-79 | High *(Expert)* | [📄](./03-xss-angularjs-sandbox-csp/) |
| 04 | SSRF — Bypass di filtro whitelist | SSRF · CWE-918 | High | [📄](./04-ssrf-whitelist-filter-bypass/) |

---

## Competenze dimostrate

- **SQL injection** UNION-based: conteggio colonne, fingerprinting DBMS, enumerazione via `information_schema`, estrazione credenziali.
- **Cross-site scripting** avanzato: client-side template injection, AngularJS sandbox escape, bypass di Content Security Policy.
- **Server-Side Request Forgery**: bypass di filtri whitelist tramite *parser differential*, accesso a servizi interni.
- **Metodologia**: reconnaissance, identificazione autonoma della vulnerabilità (mystery lab), sviluppo iterativo dell'exploit, redazione di report tecnici con impatto e remediation.
- **Strumenti**: Kali Linux, Burp Suite (Proxy, Repeater), analisi del traffico HTTP.

---

## Contatti

**Leonardo Onori** — Junior Penetration Tester / Vulnerability Analyst
📧 leonardoonori1@gmail.com · 🔗 [LinkedIn](https://linkedin.com/in/leonardo-onori) · 💻 [GitHub](https://github.com/leonardoonori1-ops)

---

*I contenuti di questo repository sono pubblicati a scopo educativo. Le soluzioni dei laboratori PortSwigger sono condivise in conformità con la pratica della community, incoraggiata da PortSwigger stessa.*
