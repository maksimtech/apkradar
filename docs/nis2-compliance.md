# APKRadar: risposte alle sette domande NIS2 sul software

Revisione 1 · 2026-10-11 · vale per il ramo `main` e per le release successive alla 2026.45

Questo documento risponde alle domande che un cliente soggetto alla direttiva NIS2
(UE 2022/2555, recepita in Italia con il d.lgs. 138/2024) può porre a un fornitore di
software. Ogni affermazione verificabile nel repository è controllata dai test in
`tests/test_nis2_evidence.py`: se il codice cambia e il documento no, la CI fallisce.
Quello che il repository non può dimostrare è indicato con la data in cui è stato
verificato, oppure dichiarato assente.

La NIS2 non prevede una certificazione di prodotto: gli obblighi della direttiva
ricadono sui soggetti, non sugli strumenti che usano. Quello che segue sono le prove
che il fornitore è in grado di dare, non un attestato di conformità.

## 1. Di cosa è fatto il software

- Dipendenze dichiarate in `pyproject.toml`; risoluzione completa in `uv.lock`. La CI
  (workflow Quality) fallisce se `uv.lock` non corrisponde più a `pyproject.toml`.
  Fra le dipendenze ci sono MailRadar e CookieRadar, due strumenti dello stesso
  fornitore che APKRadar usa per l'analisi completa (punto 3).
- Ogni release su GitHub porta in allegato due SBOM in formato CycloneDX 1.5:
  quella dell'immagine Docker, pacchetti di sistema inclusi, e quella dell'ambiente
  Python del pacchetto installato da sorgente (vedi la tabella al punto 6).
- Provenienza: le release sono costruite e pubblicate da GitHub Actions. Sulla
  versione 2026.45, verificato il 2026-10-11, la wheel e il sorgente su PyPI hanno
  un'attestazione PEP 740 che indica come origine il workflow `publish.yml` di
  `maksimtech/apkradar`, e l'immagine `maksimtech/apkradar:v2026.45` su Docker Hub ha
  per entrambe le piattaforme un'attestazione di provenienza SLSA generata da
  BuildKit al momento del push.
- Licenze: il workflow License Check fallisce se la licenza dichiarata da una
  dipendenza contiene GPL, AGPL o LGPL. Le dipendenze di APKRadar, installate in un
  ambiente pulito il 2026-10-11, superano il controllo.

## 2. Chi può vedere cosa, dentro l'applicazione

APKRadar è uno strumento a riga di comando che analizza file Android (`.apk`, `.xapk`,
`.apkm`) sul sistema di chi lo esegue. Non ha account, sessioni, ruoli né
un'interfaccia multiutente, quindi non implementa controlli di accesso: l'accesso al
sistema su cui gira è responsabilità dell'operatore. Una matrice ruoli-permessi non
esiste perché non ci sono ruoli.

L'immagine Docker gira come utente non privilegiato `apkradar`, UID 1000.

## 3. Se succede qualcosa, si può ricostruire chi ha fatto cosa

APKRadar non tiene un registro proprio: scrive i risultati sul terminale e, se
richiesto, nei file indicati (vedi sotto); la conservazione dei log è a carico di chi
lo esegue. Non contiene telemetria e non invia nulla al fornitore: nessuno degli host
elencati in questa sezione appartiene al fornitore.

Il file analizzato non lascia mai la macchina, e nemmeno il suo hash, salvo dentro la
lettera di `apkradar send` (più sotto). Escono invece il nome del pacchetto, verso
Google Play e DuckDuckGo, e i domini che il file indica, che vengono contattati con
`--full` e, per il dominio del publisher, con `send`. Il cliente deve saperlo per
valutarne l'uso.

### Quale comando contatta cosa

<!-- commands:start -->
| Comando | Contatti di rete |
| --- | --- |
| `apkradar audit` | le fonti normative, quando ci sono rilievi da citare, anche con `--offline`; con `--full` anche Google Play (salvo `--offline`), DuckDuckGo se Google Play non ha la scheda dell'app, e i domini analizzati come descritto più sotto |
| `apkradar batch` | nessuno; con `--full` i domini analizzati di ciascuna app, senza interpellare Google Play |
| `apkradar batch-excel` | nessuno |
| `apkradar search` | con un nome di pacchetto, Google Play e, se l'app non è elencata, DuckDuckGo; con un nome di app nessuno: stampa il link alla ricerca sullo store |
| `apkradar send` | Google Play (salvo `--offline`) e DuckDuckGo se Google Play non ha la scheda; il dominio del publisher, con la verifica "in vendita", MailRadar e SSL; il server SMTP indicato, salvo `--dry-run` |
<!-- commands:end -->

### Host contattati dal codice di APKRadar

<!-- hosts:start -->
| Host | Quando | Cosa riceve |
| --- | --- | --- |
| `api.duckduckgo.com` | `search`, e `audit --full` e `send` senza `--offline`, solo quando Google Play risponde che l'app non è elencata | la ricerca `<pacchetto> removed banned Google Play Store` |
| `publications.europa.eu` | `audit`, in ogni modalità, quando ci sono rilievi da citare | l'identificativo CELEX dell'atto da citare (GDPR, direttiva 2019/770) |
| `eur-lex.europa.eu` | come sopra, se publications.europa.eu non restituisce il testo | come sopra |
| `www.normattiva.it` | come sopra, per il Codice del Consumo | l'URN dell'atto e il numero dell'articolo citato |
<!-- hosts:end -->

Gli atti richiesti dipendono dai rilievi trovati; il testo viene poi letto sulla
macchina locale. Un'analisi senza rilievi non contatta nessuna fonte normativa.

Le richieste alle fonti normative si presentano con lo User-Agent
`APKRadar/<versione> (+https://github.com/maksimtech/apkradar)`. Le altre richieste
HTTP di APKRadar usano lo User-Agent predefinito della libreria che le fa.

### Host contattati attraverso le dipendenze

APKRadar chiama tre funzioni di librerie che vanno in rete:
`google_play_scraper.app`, `mailradar.checker.analyze_domain` e
`cookieradar.scanner.scan`. La tabella elenca gli host fissi che i moduli eseguiti da
quelle chiamate nominano, letti dalla versione installata delle librerie: se una nuova
versione ne aggiunge uno, i test falliscono. Di MailRadar APKRadar usa solo
`analyze_domain`: gli altri host di MailRadar, che il suo documento NIS2 elenca per
l'uso autonomo (per esempio crt.sh e rdap.org del comando `discover`, e le fonti
normative), non vengono raggiunti da APKRadar.

<!-- hosts-deps:start -->
| Host | Attraverso | Quando | Cosa riceve |
| --- | --- | --- | --- |
| `play.google.com` | `google_play_scraper.app` | `search` con un nome di pacchetto; `audit --full` e `send` senza `--offline` | il nome del pacchetto, la lingua e il paese dello store: quelli di `--lang` e `--country` con `search`, `en` e `us` negli altri casi |
| `keys.openpgp.org` | `mailradar.checker.analyze_domain` | ogni volta che MailRadar analizza un dominio | fino a cinque indirizzi di ruolo del dominio, nell'ordine security@, dpo@, admin@, postmaster@, privacy@; la ricerca si ferma alla prima chiave trovata |
| `keyserver.ubuntu.com` | come sopra | come sopra | gli stessi indirizzi |
<!-- hosts-deps:end -->

La libreria google-play-scraper, quando viene importata, disattiva la verifica dei
certificati per le richieste HTTPS fatte con `urllib`
(`ssl._create_default_https_context = ssl._create_unverified_context`, in
`google_play_scraper/utils/request.py`). APKRadar la importa attraverso
`_import_play_scraper`, che rimette la verifica predefinita appena l'import è finito:
dal 2026-10-11 anche la richiesta a play.google.com verifica il certificato del
server. Fino a quel giorno non lo verificava, e chi controllava la rete poteva leggere
il nome del pacchetto e alterare la risposta, compreso il sito dello sviluppatore che
APKRadar usa come candidato per il dominio del publisher. Le altre connessioni HTTPS di
APKRadar non usano `urllib` e verificano il certificato; la verifica "in vendita",
descritta più sotto, ripiega su `http://` in chiaro quando HTTPS fallisce.

### I domini analizzati con `--full` e con `send`

Con `audit --full` e `batch --full` APKRadar analizza, per ogni app:

- il dominio del publisher, al massimo uno: il sito indicato nella scheda Google Play
  oppure il nome del pacchetto letto al contrario (`org.wikipedia` → `wikipedia.org`);
  `batch` non interpella Google Play e usa solo il secondo;
- per ogni tracker rilevato, i domini noti del suo SDK, presi da questo elenco fisso
  in `apkradar/utils.py` (`SDK_DOMAINS`):
  <!-- sdk-domains:start -->
  `adjust.com`, `amplitude.com`, `appcenter.ms`, `applovin.com`,
  `appmetrica.yandex.com`, `appsflyer.com`, `baidu.com`, `branch.io`, `bugsnag.com`,
  `bytedance.com`, `chartboost.com`, `datadoghq.com`, `doubleclick.net`,
  `facebook.com`, `fbcdn.net`, `firebase.google.com`, `firebaseapp.com`,
  `google.com`, `googleadservices.com`, `googleapis.com`, `hicloud.com`,
  `inmobi.com`, `instabug.com`, `ironsrc.com`, `mixpanel.com`, `mopub.com`,
  `newrelic.com`, `onesignal.com`, `segment.com`, `segment.io`, `sentry.io`,
  `snapchat.com`, `supersonic.com`, `tiktok.com`, `unity.com`,
  `unityads.unity3d.com`, `vungle.com`, `xiaomi.com`;
  <!-- sdk-domains:end -->
- gli host dei deep link dichiarati nel manifest, esclusi quelli di piattaforme
  (store, social, hosting condiviso), e nessuno se sono più di dieci.

Gli host trovati nelle stringhe del codice DEX sono invece elencati nel report e non
vengono mai contattati.

Su ciascun dominio analizzato APKRadar esegue:

- solo per il dominio del publisher, la verifica "in vendita": una richiesta GET a
  `https://<dominio>` e, se fallisce, a `http://<dominio>`, seguendo i redirect;
- MailRadar (`mailradar.checker.analyze_domain`): interrogazioni DNS attraverso il
  resolver del sistema (DMARC, SPF, DKIM, BIMI, MTA-STS, TLS-RPT); se il dominio
  pubblica un record MTA-STS, `https://mta-sts.<dominio>/.well-known/mta-sts.txt`; se
  il record BIMI indica un'immagine a un indirizzo https pubblico, quell'immagine, su
  qualunque host; i due keyserver della tabella precedente;
- il controllo SSL: una connessione alla porta 443 del dominio e un handshake TLS, che
  trasmette il nome del dominio; passa per il proxy indicato in `HTTPS_PROXY`,
  `ALL_PROXY` o `HTTP_PROXY`, se impostato;
- solo con `--full`, CookieRadar (`cookieradar.scanner.scan`): avvia Chromium senza
  interfaccia tramite Playwright e carica `https://<dominio>` in tre sessioni pulite,
  senza interazione, dopo "accetta tutto" e dopo "rifiuta tutto". Il browser scarica
  la pagina e tutto ciò che la pagina richiede, compresi script di terzi. Nell'immagine
  Docker questo browser non c'è: il pacchetto Python di Playwright contiene solo il
  driver, e il Dockerfile non esegue `playwright install chromium`, il comando che
  scarica il browser.

`send` esegue la verifica "in vendita", MailRadar e SSL solo sul dominio del
publisher, compreso quello indicato con `--publisher-domain`, anche con `--offline` e
con `--dry-run`; non esegue CookieRadar. Nessuna di queste richieste contiene il file
analizzato, il suo hash o il nome del pacchetto, ma chi osserva la rete o il resolver
DNS può dedurre dall'insieme dei domini contattati quali SDK contiene l'app e chi la
pubblica.

### La lettera di `apkradar send`

`apkradar send` è l'unico comando che recapita un documento a un destinatario, e lo
fa solo su richiesta esplicita. Analizza l'app, poi si collega al server SMTP indicato con
`--smtp-host`, sulla porta `--smtp-port` (465 se non indicata): sulla porta 465 con
TLS dall'inizio, su ogni altra porta con STARTTLS prima dell'autenticazione, e se il
server non lo offre il comando si ferma. In entrambi i casi il certificato e il nome
del server vengono verificati con le autorità di certificazione predefinite del
sistema. L'autenticazione usa `--smtp-user` e una password chiesta sul terminale al
momento dell'invio: non è un'opzione del comando e non viene salvata.

Il server SMTP riceve le credenziali, il mittente (`--from`), il destinatario (`--to`)
e la lettera; il destinatario riceve la lettera. La lettera contiene il nome, il
pacchetto e la versione dell'app, la data, i tracker, i permessi sensibili e i
fornitori extra-UE rilevati, il nome del publisher (`--publisher`), il nome,
l'organizzazione e l'indirizzo del mittente, l'identificativo NOYB e l'etichetta TLP
se indicati, la versione di APKRadar e l'indirizzo del repository. Il SHA-256 del file
analizzato compare solo quando sono stati rilevati tracker; il dominio del publisher,
il punteggio MailRadar e lo stato del certificato solo se il dominio è accertato. Con
`--dry-run` la lettera viene stampata e non inviata.

### Cosa resta su disco

- La cache dei testi di legge citati, in `~/.apkradar/law_cache.json` (oppure nella
  cartella indicata da `APKRADAR_HOME`), scritta da `audit` quando scarica un testo.
  Contiene il testo degli articoli, il loro hash e le date, nessun dato sulle app
  analizzate. Nell'immagine Docker la cartella è il volume `/home/apkradar/.apkradar`.
- I report, dove l'utente li chiede: `audit --output` (`.txt`, `.html`, `.svg`),
  `batch --output <cartella>` (un `.txt` per app). `batch-excel` scrive sempre un file
  Excel: `<nome>_report.xlsx` accanto al file letto, quello indicato con `--output`,
  oppure, con `--augment`, il file letto stesso.
- I file `.xapk` e `.apkm` vengono estratti in una cartella temporanea `apkradar_*`
  della cartella temporanea di sistema, cancellata al termine dell'analisi.
- La lettera di `send` non viene salvata.
- Chromium, quando CookieRadar lo avvia, usa file temporanei propri gestiti da
  Playwright, che questo documento non ha misurato.

## 4. Come arrivano gli aggiornamenti, e in quanto tempo

La politica completa è in `SECURITY.md`: fonti di monitoraggio, tempi di risposta,
notifica ai clienti, procedura di rollback. In sintesi:

- le correzioni escono con la release successiva, che può arrivare fino a un mese dopo
  la precedente; per una vulnerabilità con CVSS pari o superiore a 9.0 il cliente che
  ha indicato un contatto di sicurezza viene avvisato entro 48 ore dalla presa in
  carico, anche se la correzione non è ancora pronta;
- le vulnerabilità accettate, con motivazione e data di revisione, sono in
  `SECURITY-EXCEPTIONS.toml`;
- ogni versione ha un tag Docker dedicato (es. `maksimtech/apkradar:v2026.45`) e un
  digest SHA256 immutabile. Il tag viene pubblicato quando la release viene creata;
  una ricostruzione manuale della release (workflow `docker.yml` avviato a mano)
  pubblica lo stesso tag su un'immagine nuova, quindi per tornare esattamente a
  un'immagine conviene fissarne il digest;
- l'immagine non viene ricostruita a intervalli regolari: le patch di sicurezza di
  Debian, installate con `apt-get upgrade` durante la costruzione, arrivano con la
  release successiva;
- Dependabot è attivo sul repository per gli avvisi e gli aggiornamenti di sicurezza
  (impostazioni lette il 2026-10-11), e `.github/dependabot.yml` chiede ogni settimana
  gli aggiornamenti delle dipendenze Python e delle GitHub Actions.

Contatto per le segnalazioni: <security@maksimtech.com>.

## 5. Il codice viene controllato prima di andare in produzione

Analisi automatiche, ciascuna con il proprio workflow in `.github/workflows`:

<!-- scanners:start -->
| Strumento | Cosa controlla | Quando |
| --- | --- | --- |
| `CodeQL` | analisi statica del codice | ogni pull request, ogni push su `main`, ogni settimana |
| `Bandit` | analisi statica di sicurezza Python | ogni pull request, ogni push su `main`, ogni settimana |
| `Trivy` | vulnerabilità note, alte e critiche, nei file del repository | ogni pull request, ogni push su `main`, ogni settimana |
| `Snyk` | il codice, le dipendenze e un'immagine costruita dal Dockerfile; fa fallire la pull request solo per una vulnerabilità alta o critica nelle dipendenze che la pull request introduce | ogni pull request, ogni push su `main`, quando il token Snyk è disponibile |
| `SonarCloud` | qualità, duplicazioni e copertura | ogni pull request, ogni push su `main`, quando il token SonarCloud è disponibile |
| `Docker Scout` | vulnerabilità note, alte e critiche, nell'immagine `latest` pubblicata su Docker Hub | ogni push su `main`, ogni settimana, a richiesta |
| `Security Posture` | raccoglie gli avvisi pubblicati dagli altri e fallisce se un avviso alto o critico non ha un'eccezione motivata | ogni pull request, ogni push su `main`, ogni settimana |
| `CodSpeed` | prestazioni: esegue i benchmark del repository e pubblica sulla pull request il confronto con `main`; non blocca il merge | ogni pull request che tocca codice, test o `pyproject.toml`, ogni push su `main` |
| `mutmut` | mutation testing: verifica che i test si accorgano delle modifiche al codice | ogni settimana |
<!-- scanners:end -->

A questi si aggiungono i test automatici (pytest su Python 3.11, 3.12, 3.13 e 3.14,
con copertura inviata a Codecov), ruff e mypy nel workflow Quality. Sul repository
sono attivi anche il secret scanning di GitHub e la push protection (impostazioni
lette il 2026-10-11).

Le regole del ramo `main`, lette dalle impostazioni del repository il 2026-10-11,
vietano la cancellazione e la riscrittura della storia, richiedono una storia lineare,
una pull request con zero approvazioni richieste e unione solo per rebase, e due
controlli superati: Tests e Quality. CodeQL e Security Posture girano su ogni pull
request ma non sono tra i controlli obbligatori. L'account del manutentore
(`maksimtech`) è configurato per poter scavalcare queste regole.

APKRadar ha un manutentore unico. Non c'è nessuna revisione obbligatoria da parte di
una seconda persona: le pull request vengono unite dal manutentore stesso. È un
limite noto di un progetto con una sola persona.

## 6. Qualcuno dall'esterno ha provato a entrare

Non è stato eseguito un penetration test. Esiste una scansione automatica continua
delle vulnerabilità note, descritta al punto 5, ma non è un penetration test: non ha un
ambito concordato, non è condotta da un tester indipendente e non produce un rapporto
con vulnerabilità trovate e correzioni datate.

Ogni release porta in allegato i risultati datati di quella scansione, insieme alle
SBOM:

<!-- assets:start -->
| File allegato alla release | Contenuto |
| --- | --- |
| `sbom-image-<versione>.cdx.json` | SBOM CycloneDX 1.5 dell'immagine Docker della versione |
| `sbom-source-<versione>.cdx.json` | SBOM CycloneDX 1.5 dell'ambiente Python del pacchetto |
| `trivy-image-<versione>-<data>.json` | vulnerabilità note nell'immagine, scansione Trivy |
| `trivy-fs-<versione>-<data>.json` | vulnerabilità note nei file del repository al tag, scansione Trivy |
| `EVIDENCE-<versione>.md` | cosa sono questi file, quando e da quale commit e immagine sono stati prodotti |
<!-- assets:end -->

Se a un tag il repository non contiene un file che Trivy sappia analizzare, come un
lockfile, il rapporto `trivy-fs` di quella release è vuoto. Un rapporto vuoto non
indica l'assenza di vulnerabilità, e in quel caso la nota `EVIDENCE` lo dice.

## 7. E se il fornitore sparisce

Il codice sorgente è pubblico su <https://github.com/maksimtech/apkradar> con licenza
MIT, e resta accessibile indipendentemente dalle sorti commerciali del fornitore. Le
versioni pubblicate restano su PyPI e su Docker Hub.

Il fornitore non riceve né conserva dati del cliente: tutto l'output è prodotto
sull'infrastruttura di chi esegue APKRadar, quindi non c'è nulla da esportare.

Una clausola contrattuale su questo punto va concordata caso per caso e fatta rivedere
da un legale.
