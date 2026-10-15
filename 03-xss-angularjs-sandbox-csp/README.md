# Reflected XSS — AngularJS sandbox escape + bypass della CSP

> **Autore:** Leonardo Onori — Junior Penetration Tester
> **Fonte:** PortSwigger Web Security Academy — *Reflected XSS with AngularJS sandbox escape and CSP*
> **Target:** `0a3b003d03c1773580aa03ec00ef0018.web-security-academy.net`
> **Categoria:** OWASP A03:2021 – Injection (XSS) · CWE-79
> **Severità:** High · **Difficoltà:** Expert

---

## 1. Sintesi

L'applicazione riflette l'input del parametro di ricerca all'interno di una pagina che utilizza **AngularJS** ed è protetta da una **Content Security Policy**. L'attacco combina tre bypass in un unico payload per eseguire `alert(document.cookie)` nel browser della vittima, aggirando contemporaneamente la CSP, il sandbox di AngularJS e il controllo sull'oggetto `window`.

| | |
|---|---|
| **Parametro riflesso** | `search` (GET `/`) |
| **AngularJS** | versione 1.4.4 (`<body ng-app ng-csp>`) |
| **CSP** | `default-src 'self'; script-src 'self'; style-src 'unsafe-inline' 'self'` |
| **Modalità di consegna** | Exploit server → vittima |

---

## 2. Analisi del contesto

Due header/attributi determinano la strategia:

- **CSP** `script-src 'self'` → nessuno script esterno, nessun inline classico, nessun dominio di terze parti whitelistato da sfruttare per JSONP.
- **`ng-csp`** → AngularJS gira in modalità CSP-compatibile: `$eval()` è disabilitato, quindi il sandbox escape classico via `{{$eval...}}` **non funziona**.

L'input viene riflesso come testo nei risultati di ricerca (`1 search results for '...'`), in una zona compilata da Angular.

> Un primo tentativo con `{{$on.constructor('alert(1)')()}}` è stato **riflesso come testo letterale, non valutato**: conferma che con `ng-csp` la semplice interpolazione non basta e serve iniettare HTML con un handler Angular.

## 3. Il vettore: `ng-focus` + `orderBy`

La soluzione inietta un elemento `<input>` con l'attributo AngularJS `ng-focus`. Poiché Angular compila l'attributo come handler di template (non come evento DOM `on*`), **la CSP non lo blocca**. Il frammento `#x` nell'URL porta il focus automatico sull'elemento `id=x`, scatenando l'evento.

Il meccanismo di escape:

- `|` in AngularJS è un'operazione di **filtro** (`orderBy`), non un OR bitwise.
- `$event.composedPath()` restituisce l'array di elementi che hanno propagato l'evento; l'ultimo elemento è l'oggetto `window`.
- L'assegnazione `(z=alert)` invoca `alert` **nello scope di `window` senza nominarlo esplicitamente**, aggirando il controllo di AngularJS sull'oggetto window.

> **Aggiornamento browser** — dalla versione Chrome 109 la proprietà `path` è stata rimossa: la soluzione funzionante usa `composedPath()`.

## 4. Payload

Da incollare nell'**exploit server** (sostituendo il proprio `YOUR-LAB-ID`), poi *Store* → *Deliver exploit to victim*:

```html
<script>
location='https://YOUR-LAB-ID.web-security-academy.net/?search=%3Cinput%20id=x%20ng-focus=$event.composedPath()|orderBy:%27(z=alert)(document.cookie)%27%3E#x';
</script>
```

Il parametro `search` decodificato contiene:

```html
<input id=x ng-focus=$event.composedPath()|orderBy:'(z=alert)(document.cookie)'>#x
```

## 5. Catena dei tre bypass (sintesi)

| Difesa | Come viene aggirata |
|---|---|
| **CSP** `script-src 'self'` | Iniezione di HTML con handler Angular `ng-focus` (template, non evento DOM) |
| **Sandbox AngularJS** (`$eval` disabilitato da `ng-csp`) | `$event.composedPath()` + filtro `orderBy` per raggiungere `window` |
| **Window detection** di Angular | Assegnazione `(z=alert)`: chiama `alert` nello scope di window senza nominarlo |

## 6. Impatto

Esecuzione di JavaScript arbitrario nel contesto della vittima: furto di cookie di sessione e token, azioni per conto dell'utente, account takeover. Essendo *reflected* e consegnabile via link, l'attacco richiede solo che la vittima apra l'URL.

## 7. Remediation

- **Encoding contestuale** dell'output riflesso; non inserire input utente in pagine processate da template engine lato client.
- **Aggiornare/dismettere AngularJS** (1.x è end-of-life): le versioni recenti non espongono il sandbox, già rimosso perché non considerato una barriera di sicurezza.
- **CSP rigorosa e priva di aggiramenti**, abbinata alla sanificazione dell'input — la CSP è una difesa in profondità, non sostituisce l'encoding.

## 8. Riferimenti

- OWASP Top 10 — A03:2021 Injection (XSS)
- CWE-79 — Cross-site Scripting
- PortSwigger Research — *AngularJS CSP bypass*
- PortSwigger Web Security Academy — *Reflected XSS with AngularJS sandbox escape and CSP*
