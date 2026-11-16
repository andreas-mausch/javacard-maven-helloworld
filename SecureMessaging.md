# Secure Messaging (SM) für dieses Projekt

Recherche- und Dokumentationsstand: 2026-11-14

**Ausgangslage / Anforderung:** Eine App auf dem Handy kommuniziert per NFC mit
einer JavaCard. Die App soll **keine** symmetrischen Karten-Keys (MAC/DEK/ENC)
kennen müssen — trotzdem soll die Kommunikation abgesichert sein.

**TL;DR:** Wir brauchen einen Kanal ohne vorab ausgetauschte Geheimnisse in der
App. Das Standardmittel dafür ist **SCP11** (GlobalPlatform, ECDH +
Zertifikate), Variante **SCP11b**: Die App besitzt gar keine dauerhaften
Schlüssel, nur ephemere (Einweg-)Schlüssel pro Session; die Karte
authentifiziert sich mit einem **öffentlichen** Key, den die App pinnt. Als erste Ausbaustufe empfohlen:
ein **eigener, edukativer Handshake im SCP11b-Stil** (P-256 ECDH →
AES-Session-Keys → pro Kommando MAC + Verschlüsselung). Alternativen sind unten
dokumentiert (Server als kryptografischer Partner, PAKE/SPAKE2+, OPA-CRE,
Hardware-Keystore-Attestierung der App, NFC-SEC, PACE).

---

## 1. Was ist Secure Messaging überhaupt?

Eine Smartcard spricht APDUs: ein Kommando-APDU (`CLA INS P1 P2 [Daten]`) und
ein Antwort-APDU (`Daten SW1 SW2`). Über NFC (ISO 14443 / ISO-DEP) liegt die
Funkschicht offen: Jede Antenne im Empfangsbereich kann prinzipiell

- **mitsneiden** (Vertraulichkeit),
- **verändern** (Integrität),
- **nachbauen/wiederholen** (Replay),
- **eine gefälschte Karte oder ein gefälschtes Lesegerät vorgeben**
  (Impersonation — z. B. ein „Börse"-Klon, der der App eine echte Karte
  vorspielt).

**Secure Messaging** = beide Seiten verpacken APDUs in einen verschlüsselten
und MAC-geschützten Container, nachdem sie sich in einem **Handshake** auf
einen **Sitzungsschlüssel** geeinigt haben.

Wichtig: SM ist kein Protokoll, sondern eine *Technik*. Die Protokolle, die SM
definiern, sind u. a. GlobalPlatform SCP02/SCP03/SCP11, ISO 7816-4 SM (nur
Hüllformat, ohne Schlüsselmanagement), ICAO PACE (ePassport), NFC-SEC (ECMA).

### Das CLA-Bit ist keine Garantie (klassischer Anfängerfehler)

In APDUs signalisiert Bit `0x04` im CLA-Byte („secure messaging is used").
Eine naive Prüfung

```java
if ((CLA & 0x04) == 0) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
```

ist **wertlos**: Jeder kann dieses Bit setzen. Die *einzige* Garantie, dass ein
Kommando „nachweislich über SM" kam, ist, dass die Karte das **C-MAC
(Command-Message-Authentication-Code) kryptografisch verifiziert** hat — mit
einem Sitzungsschlüssel, den nur die Karte und der Handshake-Partner kennt.
Ohne gültiges MAC → Fehler (`6982` security status not satisfied, `6A88`
data object missing o. ä.). **Nur dann darf `9000` folgen.**

Und für die *Antwort* gilt das andersherum genauso: ohne **R-MAC** (Response
MAC) könnte ein Angreifer zwischen App und Karte ein altes echtes `9000`
wiederverwenden, ohne die Karte überhaupt zu treffen. Die harte Garantie
„9000 kam garantiert über SM" braucht deshalb drei Dinge:

| Mechanismus                                              | Schützt gegen                                                                                                         |
|----------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------|
| **C-MAC** mit Sitzungsschlüssel                          | Wer ohne Key ist, dessen Kommandos lehnt die Karte ab                                                                 |
| **SSC** (Secure Session Counter, im MAC-Eingabewert)     | Replay *innerhalb* der Session                                                                                        |
| **R-MAC** bzw. ein kryptografisch gebundener Antwortwert | Replay der *Antwort*; App erkennt, dass die Antwort wirklich von der (echten!) Karte und von *diesem* Kommando stammt |

### Was SM **nicht** kann

- **Relay-Angriffe**: Ein Angreifer verlängert NFC mit zwei Geräten in
  verschiedene Räume („Betrüger im Laden, Opfer zu Hause"). SM merkt das nicht.
  Dagegen hilft nur Distanz-Bounding (z. B. NFC STC-a / Timing-basierte
  Verfahren) — in der Praxis selten implementiert, separates Thema.
- **Angriffe auf die Implementierung**: Side-Channels, schlechte Zufallszahlen,
  logische Fehler im Applet. Sicherheit steckt im Detail (und in der
  Implementierungs- und App-Integrität: Was nützt der beste Kanal, wenn die
  App-Logik gehackt wird und Secrets ausgibt?).

---

## 2. Die Kernfrage: Woher nehmen, wenn nicht stehlen (die Keys)?

Es gibt genau **zwei** Wege, einen Sitzungsschlüssel zu bekommen:

1. **Pre-shared Secret**: Beide Seiten besitzen längst denselben (abgeleiteten)
   Schlüssel. → GlobalPlatform **SCP03**. Problem bei uns: Das Geheimnis muss
   in der App stecken. Eine Handy-App ist aber ein angreifbares Ziel — jeder,
   der die App auspackt (und das kann jeder, der sie installiert hat), findet
   den Key. Also: **SCP03 scheidet aus** (ok wäre er nur, wenn die App den Key
   in einem Hardware-Backed Keystore hielte und die Karte *pro App-Instanz*
   individualisiert wäre — siehe §4.5).
2. **Asymmetrischer Schlüsselaustausch**: Die Seiten besitzen Schlüsselpaare
   (privat/öffentlich) und erzeugen per **ECDH** *frisch* ein gemeinsames
   Geheimnis — ohne dass je ein symmetrischer Key ausgetauscht werden musste.
   Authentizität kommt aus Signaturen/Zertifikaten oder Public-Key-Pinning.
   → **SCP11**, oder ein Eigenbau nach demselben Muster. Genau das wollen wir.

Dazu kommt eine dritte, architektonische Möglichkeit:

3. **Die App ist gar nicht der kryptografische Peer** — ein Backend-Server ist
   es, die App leitet nur die APDU-Bytes weiter (Pipe). Der Server darf ruhig
   SCP03-Keys besitzen (er läuft in unserer Infrastruktur). → §4.4.

---

## 3. GlobalPlatform SCP11 im Detail (der Standardweg)

**SCP11** = GlobalPlatform Secure Channel Protocol '11': Handshake per ECDH
(P-256) + X.509-Zertifikaten, danach **dieselbe** AES-SM-Maschinerie wie SCP03
(C-MAC, R-MAC, C-ENC, R-ENC, SSC). Entwickelt für Szenarien, in denen „die
beiden Entitäten nicht als striktes Paar mit verteilten Secret Keys
ausgerollt werden" — exakt unser Fall. Drei Varianten:

|                           | SCP11a                                     | SCP11b                                  | SCP11c                                        |
|---------------------------|--------------------------------------------|-----------------------------------------|-----------------------------------------------|
| App braucht               | statischen EC-Key + OCE-Zertifikat         | **nichts** (nur ephemere Keys)          | statischen EC-Key + Zertifikat                |
| Karte authentifiziert App | ✅ (Zertifikat/Allowlist)                   | ❌                                       | ✅                                             |
| App authentifiziert Karte | ✅                                          | ✅                                       | ✅                                             |
| Forward Secrecy           | ✅                                          | ✅                                       | ❌                                             |
| Typischer Einsatz         | YubiKey-GP-Domänen-Management mit OCE-Zert | Karte↔Terminals ohne Terminal-Identität | Offline-Skripte für Karten-Gruppen (RSP/eSIM) |

**SCP11b-Fluss (unser Kandidat):**

```
App (OCE)                                   Karte (SD/Applet)
   |  1.INITIALIZE UPDATE  (host challenge, SCP-ID)      |
   | --------------------------------------------------->|  Karte: ephemeres + statisches ECDH-Paar
   |  2. Response: [ePK.Karte, PK.Karte (Zert),          |  erzeugen, Kette/Receipt vorbereiten
   |                Karten-Challenge, krypt. Parameter]  |
   |<----------------------------------------------------|
   App: Zert prüfen (CA) → PK.Karte;                     |
   ephemeres Paar erzeugen; ECDH-Geheimnisse             |
   ShSes = ECDH(eSK.App,  PK.Karte)                      |
   ShSee = ECDH(eSK.App,  ePK.Karte)                     |
   Session-Keys via X9.63-KDF aus (ShSes||ShSee, Nonces) |
   |  3. EXTERNAL/MUTUAL AUTHENTICATE                    |
   |     [ePK.App + kryptografischer Beleg] ------------->|  Karte: gleiche Keys berechnen,
   |                                                      |  Beleg prüfen, Receipt erzeugen
   |  4. Response: [Receipt (R-MAC über den Handshake)]  |
   |<----------------------------------------------------|
   App: Receipt prüfen → Kanal steht, SSC hochzählen     |
   |  5. Nutzbefehle: SCP03-SM (C-ENC, C-MAC, R-MAC, SSC)|
   | <==================================================> |
```

Die kryptografischen Bausteine (ECDH P-256, SHA-256, AES-CMAC, AES-CBC, KDF)
sind alle **ab JavaCard 3.0.4** als Standard-API vorhanden und laufen im
JCardSim. Was auf der Karte mehr Aufwand ist: **X.509/BER-TLV-Zertifikate
parsen und ECDSA-Signaturen der CA verifizieren**. Deshalb für v1:

**Public-Key-Pinning statt Zertifikaten (v1-Empfehlung):**
Die App enthält den **öffentlichen** Karten-Key (bzw. dessen Hash) fest
einbeten. Public Keys sind keine Geheimnisse — die App *darf* sie enthalten,
auch wenn sie ausgepackt wird. Die Karte muss für v1 dann nichts signieren,
und wir sparen uns Zertifikats-Parsing auf der Karte. Der Preis (was wir uns
dabei nicht leisten): Rollout mehrerer Karten mit einem App-Build (jede Karte
hätte einen eigenen Pin) und Key-Rotation ohne App-Update. v2-Ausbau: Karte
präsentiert `CERT.SD.ECKA`, App verifiziert gegen embedded CA-Root; dann
braucht es für beliebig viele Karten und Rotation kein App-Update mehr.

**„Aber die Karte weiß doch nicht, wer spricht?"** — Korrekt, und das ist bei
SCP11b so gewollt (wie TLS ohne Client-Zertifikat). Ein Angreifer darf
problemlos einen eigenen Kanal zur Karte aufbauen; er sieht dann nur, was ein
*unauthentifizierter* Nutzer sehen darf. Wenn die Karte den **Nutzer**
authentifizieren soll: **PIN via `VERIFY` innerhalb des SM-Kanals** (der PIN
ist dann durch C-ENC geschützt — das ist exakt das SCP11b-Annex-A-Modell).
Wenn sie die **App-/Geräteidentität** wissen soll: OCE-Zertifikate (§4.5) oder
Server-Architektur (§4.4).

---

## 4. Alternativen zu SCP (und warum)

### 4.1 Edukativer Eigenbau im SCP11b-Stil — **empfohlen für dieses Repo**

Kein GP-Framing (keine `MANAGE SECURITY CHANNEL`-TLVs, keine
Zertifikatsketten), aber derselbe Sicherheitskern: ephemere-App-ECDH +
statischer Karten-Key (gepinnt) + AES-GCM-Session … **Achtung**: JavaCard hat
**kein AES-GCM** in der Standard-API; wir bauen wie SCP03 mit
**AES-CBC-CMAC (`Signature.ALG_AES_CMAC`) + AES-CBC-Verschlüsselung + SSC**.
Vorteile: kompletter Lernpfad, alles in diesem Repo + JCardSim testbar,
kleiner Code, klare Sicherheitsargumente. Später aufrüstbar auf volles SCP11b
(Handshake-Austausch, dann ist SCP03-SM ohnehin identisch) — Interoperabilität
mit Host-Bibliotheken wie **OpenSCP-Java** (Apache-2.0) bleibt möglich, wenn
wir konform werden wollen.

### 4.2 Volles GP-konformes SCP11b im Applet

Theoretisch „richtiger", praktisch: Zertifikats-Parsing auf der Karte,
GP-APDU-Framing, Receipt-Definition, KDF nach TR-03111 — ohne Referenzkarte
schwer zu testen. Offene Referenz (card-side): `ThothTrustCom/SCP11B`
(BSD-3, JavaCard-Applet + Java-Client, seit 2021 nicht gepflegt, Qualität
ungeprüft). Host-seitig: **Samsung/OpenSCP-Java** (Apache-2.0, SCP03 v1.2 +
SCP11 v1.4, **nur** Off-Card/Host). Für ein Lernprojekt zu viel Spec-Fricke,
für Produktion revisitable.

### 4.3 NFC-SEC (ECMA-385 / ISO 13157-2) & NFC Forum NAP

ECDH-P-192-basierter „Secure Channel Service" für NFC — standardisiert
ausdrücklich für „zwei NFC-Geräte, die vorher kein gemeinsames Geheimnis
haben". Aber: Zielgruppe war **Peer-to-Peer** (NFC-DEP), nicht
Reader/Writer-APDUs gegen JavaCard-Tags; in der Praxis so gut wie nie
implementiert (Android/iOS stellen die APIs für diesen Zweck nicht sinnvoll
bereit). Nur der Vollständigkeit halber gelistet.

### 4.4 Backend als kryptografischer OCE (Relay-Architektur)

Die App ist eine reine APDU-Pipe; der kryptografische Partner der Karte ist
**unser Server** (TLS zwischen App und Server, SCP03 zwischen Server und
Karte, mit pro Karten-ID abgeleiteten Keys). Die App kennt **wirklich
keine** Keys. Das ist die Architektur von CardRelay & Co. und sehr
praxistauglich, wenn es ohnehin ein Backend gibt. Nachteil: ohne Netz läuft
nichts, und die Karte muss die Server-Keys kennen
(Provisioning-Infrastruktur). Auch
hybrid möglich: Offline-Kanal via SCP11b (Karte→App), Online-Verwaltung via
Server (SCP03).

### 4.5 App-Key mit Hardware-Attestierung (Android Keystore / iOS Secure Enclave)

Die App erzeugt einen Schlüsselpaar **im Hardware-Backed Keystore**
(StrongBox/TEE/Secure Enclave, nicht exportierbar) und lässt sich vom
OS/Backend ein **Attestations-Zertifikat** geben; die Karte vertraut
attestierten Geräten (ggf. nach Registrierung/Login beim Backend).
Effektiv „SCP11a mit OCE-Zertifikaten, wo die CA das Geräte-Ökosystem ist".
Vorteil: echte Geräte-Bindung, Revocation möglich. Nachteile:
Plattform-Abhängigkeit, Registrierungs-Infrastruktur, Attestations-Keys von
Google/Apple als neue Vertrauenswurzel. Guter v3-Kandidat, wenn
Benutzerkonten ins Spiel kommen.

### 4.6 PAKE / SPAKE2+ (Passwort als Trust-Anker)

Ein **PAKE** (Password Authenticated Key Exchange) leitet Session-Keys aus
einem kleinen menschlichen Geheimnis ab (PIN/Pairing-Code), ohne dass ein
Dictionary-Angriff möglich ist — Matter (Smart-Home) nutzt SPAKE2+ fürs
Device-Pairing. Für uns relevant, falls „Nutzer tippt 6-stelligen Code" als
Authentisierung genügt: Karte kennt den Code (bzw. Verifikator), App auch,
keine PKI nötig. JavaCard hat **keine PAKE-API**; SPAKE2+ auf P-256 wäre als
Applet machbar (Punktmultiplikation via `KeyAgreement`-Tricks oder JCMathLib),
ist aber Krypto-Eigenbau und damit sicherheitstechnisch anspruchsvoll — nur mit
Review. Eher exotisch für dieses Projekt, hier der Vollständigkeit wegen.

### 4.7 OPA-CRE / OPACEC (Akademisch, für genau diese Domäne)

„Open Protocol for Access Control over Contactless JavaCard (Enhanced)"
(Dzurenda/Hajný/Malina et al., Brno): ECDH-basiertes SM-Protokoll für
Zugangskontrolle mit kontaktlosen JavaCards, entworfen für Terminal-
Authentisierung per Passwort **oder** Terminal-Zertifikat, mit Offline-
Terminal-Authentisierung als Feature. Implementierungen stammen aus dem
akademischen Umfeld (CRoCS MUNI / BUT, Abschlussarbeiten/Paper-Begleitcode)
und sind nicht als gepflegte, leicht einbindbare Bibliotheken verfügbar (Stand
der Recherche: kein verifizierbares, aktiv gepflegtes Repo auffindbar). Als
Design-Vorlage gut; als Dependency schwierig.

### 4.8 ICAO PACE (ePassport)

Leitet Session-Keys per ECDH aus einem schwachen geteilten Geheimnis (MRZ-
Nummer im Reisepass) ab — „pre-shared, aber der Mensch trägt's". Konzeptell
wichtig (und zeigt: schwaches Secret + PAKE-artige Derivation geht), aber
reisepass-spezifisch; JavaCard-seitig gibt's JMRTD-Applet-Code dazu. Für uns
nur Inspirationsquelle.

### 4.9 Kommerzielle Secure-Tags (NTAG 4xx DNA, ST25D/ST25DA, MIFARE DESFire)

Gleiche Problemstellung („Handy ohne Keys ↔ sicherer Chip"), aber als
Produktklasse mit proprietären/herstervertrauenswürdigen Modellen (SUN-Messages,
SDT, Hersteller-Roots). Wenn „JavaCard" verhandelbar wäre, wären ST25D-Secure-
Chips (ECDSA/ECDH, SPAKE2+, Matter) der bequeme Weg — mit
Hersteller-Infrastruktur (NXP/ST) statt eigener Krypto-Infrastruktur. Hier
nur als Reminder.

---

## 5. Empfehlung (Entwurf v1)

**Edukativer SCP11b-inspirierter Kanal, Public-Key-Pinning, AES-SM nach
SCP03-Muster.**

### 5.1 Krypto-Bausteine

| Zweck                 | Primitive                   | JavaCard-API (≥ 3.0.4)                                                              | jcardsim                  |
|-----------------------|-----------------------------|-------------------------------------------------------------------------------------|---------------------------|
| Schlüsselvereinbarung | ECDH P-256                  | `KeyAgreement.ALG_EC_SVDP_DH_PL`                                                    | vorhanden (verifizieren!) |
| Karten-Identität (v2) | ECDSA P-256                 | `Signature.ALG_ECDSA_SHA_256`                                                       | vorhanden                 |
| Session-Key-Ableitung | HKDF-ähnlich                | `MessageDigest.ALG_SHA_256`; HMAC ab JC 3.0.5 via `Signature.ALG_HMAC_SHA_256`      | vorhanden                 |
| C-MAC / R-MAC         | AES-CMAC                    | `Signature.ALG_AES_CMAC`                                                            | vorhanden                 |
| C-ENC / R-ENC         | AES-CBC (+ISO-9797-Padding) | `AESCipher.ALG_AES_BLOCK_128_CBC_NOPAD`                                             | vorhanden                 |
| Zufall                | CSPRNG                      | `RandomData.getInstance(RandomData.ALG_SECURE_RANDOM)`                              | vorhanden                 |

⚠️ Fallen:

- `ALG_EC_SVDP_DH` (ohne Suffix) liefert **SHA-1(x)** — veraltet; wir wollen
  `_PL` (plain x) bzw. `_PL_XY` (unkomprimierter Punkt). Vendor-spezifische
  Varianten (JCOP: `KeyAgreementX`) bewusst vermeiden → `_PL` + eigene
  Punkt-Encodierung. Auf manchen alten Karten gibt's `_PL` nicht → bevor du
  Serienkarten produzierst, die Karte mit **ECTester** vermessen.
- MAC und Verschlüsselung selbst zu kombinieren ist heikel
  (Padding-Oracles, Encrypt-then-MAC-Fehler) → Reihenfolge wie SCP03: erst
  verschlüsseln, dann MAC über Header+Ciphertext; MAC-Eingabe immer inkl. SSC.
- Session-Keys und ephemere Private Keys als **`transient`** Arrays mit
  `CLEAR_ON_DESELECT`/`CLEAR_ON_RESET` führen.
- ECDH-Secret niemals direkt als Key nehmen — immer KDF mit Kontext
  (beide Public Keys + Nonces), sonst Key-Confirmation-Probleme.
- Zeit-/Leistungsverhalten auf NFC: pro Kommando 2 AES + 1 SHA-Aufwand ist
  trivial; der Handshake kostet eine EC-Schlüsselgenerierung (~100 ms-Bereich,
  Karte-zu-Karte sehr unterschiedlich → messen).

### 5.2 Protokollskizze (CLA `0x80`, eigene INS-Codes)

```
INIT_SM (INS 0x20):
  App →  [hostNonce (16)]
  Karte→  [cardNonce (16), ePK.Karte (65, uncompressed)]
  (Karte erzeugt ephemeres + hält statisches P-256 Paar; Session-State = WAIT)

AUTH_SM (INS 0x22):
  App →  [ePK.App (65), C-MAC über Handshake-Transkript]
  Karte: ShS = ECDH(esk_karte_static, ePK.App) || ECDH(eph_sk_karte, ePK.App)
         Keys = KDF(ShS, hostNonce||cardNonce, ePKs/PKs)   // X9.63-artig
         MAC prüfen → Session-State = ACTIVE, SSC = 0
  Karte→ [R-MAC (Receipt über Transkript an App)]

GET HELLO (INS 0x00) NUR mit SM:
  CLA Bit 0x04 gesetzt sein MUSS, sonst 6982
  Daten: DO 87 (AES-CBC-verschlüsseltes Payload + Padding),
         DO 97 (Le), DO 99 + C-MAC (über Header||87||97, SSC als IV-Anteil)
  Karte: SSC+1; C-MAC prüfen (else 6982/6A88); entpacken; verarbeiten;
         Antwort: DO 87 + SW + R-MAC
```

**Die Garantie, die du wolltest:** `GET HELLO` mit `9000` liefert die Karte
**nur**, wenn C-MAC über SSC-gebundenes Kommando gültig war. Ohne
stattgefundenen Handshake existieren die Keys nicht; ohne Keys kein gültiges
MAC; gefälschte Bits im CLA reichen nicht. Die App erkennt über das R-MAC
(Receipt bei AUTH_SM, R-MAC an jeder Antwort), dass die Antworten von der
echten Karte (Besitzerin des gepinnten Static Keys) und frisch sind.

### 5.3 Was die App kennt (und warum das sicher ist)

- **Nur** den öffentlichen Karten-Key (Pin) oder dessen SHA-256 — öffentlich.
- Alles andere (ephemere App-Keys) ist Session-flüchtig und weg, wenn die App
  stirbt.
- Selbst ein vollständiger App-Dump liefert nichts Verwertbares: den
  Karten-Public-Key (public!), allenfalls Mitschnitte alter Sessions — die sind
  nutzlos, weil die Session-Keys an die ephemeren Schlüssel beider Seiten
  gebunden sind (Forward Secrecy) und der SSC jedes Kommando an seine Position
  in der Session bindet.

### 5.4 Testbarkeit in diesem Repo

- Host-Seite (simuliert das Handy): reines Java + BouncyCastle (jcardsim
  bundled BC ohnehin, besser explizite `org.bouncycastle:bcprov-jdk18on`
  Dependency, `test` scope) — Pin-Vergleich, ECDH, CMAC wie auf der Karte.
- JCardSim deckt EC + AES-CMAC ab; für Realkarten: ECTester-Kapazitätscheck
  und `docker-javacard`-Umgebung (siehe `JavacardSimulator.md`).
- Mind. Testfälle: Happy-Path; Befehl vor Handshake → `6982`; falsches MAC →
  `6982`; Replay desselben Kommandos → `6982` (SSC); CLA ohne SM-Bit →
  `6982` (auch nach Handshake); Manipulation eines Ciphertext-Bytes → `6982`.

### 5.5 Ausbaustufen

1. **v1** (dieses Repo): Handshake + Pin + C-MAC/R-MAC/SSC, `GET HELLO` nur
   über SM; Tests in JCardSim.
2. **v2**: X.509 `CERT.SD.ECKA` + CA-Verifizierung (App-Update-freier
   Kartenrollout, Rotation); optional `VERIFY`-PIN im Kanal.
3. **v3**: OCE-Zertifikate/Geräte-Bindung (§4.5) oder Backend-Relay (§4.4),
   je nachdem ob Karten-seitige App-Authentisierung nötig wird.
4. **optional**: SCP11b-Konformität anstreben (dann OpenSCP-Java als Host).

---

## 6. Quellen (Auswahl)

- GlobalPlatform: *Secure Channel Protocol '11'* (GPC_SPE_093, v1.2/v1.3),
  *Amendment F (SCP11c)*, *Amendment D (SCP03)* — globalplatform.org/specs-library
- BSI TR-03111 (ECDH/KDF-Grundlagen SCP11), NIST SP 800-56A, SP 800-108,
  SP 800-38B (AES-CMAC), ISO/IEC 7816-4 (SM-Hüllformate DO 87/97/99/E0)
- JavaCard Classic API 3.0.4+/3.0.5 (`KeyAgreement`, `Signature.ALG_AES_CMAC`,
  `AESCipher`) — Oracle `oracle_javacard_sdks`
- Samsung/OpenSCP-Java (Host SCP03/SCP11, Apache-2.0) — github.com/Samsung/OpenSCP-Java
- ThothTrustCom/SCP11B (Card-side+Host SCP11b Referenz, BSD-3, ⚠️ ungepflegt)
- crocs-muni/ECTester (ECC-Kapazitäten von JavaCards vermessen),
  OpenCryptoProject/JCMathLib (EC-Mathematik falls Standard-API nicht reicht)
- martinpaljak/GlobalPlatformPro (Host-SCP03-Werkzeug, Referenz für
  Realkarten-Interoperabilität); g0ddest/javacard-express (jüngere Java-
  Toolkit-Familie mit SCP02/03 + simulierter GP-Karte)
- Dzurenda/Hajný/Malina: OPACEC/OPA-CRE, *Open Protocol for Access Control
  over Contactless JavaCard Enhanced* (SECRYPT 2016) — Literatur
- ECMA-385 / ISO/IEC 13157-2 (NFC-SEC), NFC Forum NAP 1.0
- NXP NTAG DNA / ST ST25D-Datenblätter (kommerzielle „Secure Tag"-Antwort auf
  dieselbe Problemstellung)
