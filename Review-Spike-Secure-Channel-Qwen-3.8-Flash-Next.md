# Review 01 — SecureChannelApplet

- **Datum:** 2026-11-17
- **Scope:** `src/main/java/helloworld/SecureChannelApplet.java` (primär), `HelloWorldApplet.java`,
  `SecureChannelClient.java` (Test-/Referenz-Client), `pom.xml`, README-Sicherheitsclaims
- **Methode:** Line-by-line Review der Krypto- und State-Machine-Pfade, validiert gegen
  Java-Card-3.0.5-Semantik und die dokumentierte Dual-Runtime-Portabilität; PoC gegen jcardsim ausgeführt.

## Gesamturteil

Handwerklich hochwertig: Encrypt-then-MAC korrekt (MAC vor Decryption), saubere HKDF-Trennung
mit per-Suite-Labels, transcript-gebundene beidseitige Key Confirmation, Suite hard am Install
fixiert (kein Downgrade), ordentliches Key-Wiping, Install-Zeit-KAT auf exakt dem Runtime-Pfad —
das ist deutlich über Demo-Niveau. **Aber:** Die dokumentierte Replay-Protection hat eine
hochwertige Lücke, die ich mit PoC belegt habe (F1). Als Demo okay, als produktionsreifer
Secure Channel aktuell **nicht** sicher.

| ID | Schwere | Findung |
|----|---------|---------|
| F1 | **Hoch** | Handshake-Replay: EXCHANGE ohne INIT akzeptiert → Sequence-Counter werden zurückgesetzt → ausgeführte Protected Commands sind erneut replaybar (**PoC-verifiziert**) |
| F2 | Mittel | Client prüft Response-Seq nicht auf Monotonie (Response-Replay unentdeckt) |
| F3 | Mittel | EC-Point-Validierung komplett an die Runtime delegiert (`setW`); Portabilitätsannahme undocumented |
| F4 | Niedrig | GCM-IV-Uniqueness über Sessions hängt an 32 Bit Zufall; rx/tx teilen sich denselben Key |
| F5 | Niedrig | Wipe-Asymmetrie: Prefix/Seq-Fehler wischt nicht, MAC-Fehler wischt → unterscheidbarer Oracle |
| F6 | Niedrig | `openGcm`-Fallback ist exception-getrieben und fragil; Feature-Detection gehört zur Install-Zeit |
| F7 | Niedrig | `exchange()` setzt `sessionActive=true` vor dem Seal der Antwort; Seal-Fehler hinterlässt aktive Session |
| F8 | Niedrig | `parseSuiteParam` ohne Bounds-Check gegen `bLength` |
| F9 | Info | `probe` fängt `ClassCastException` beim `AEADCipher`-Cast nicht |
| F10 | Info | Retry-Ambiguität bei nicht-idempotenten Commands (Seq-Check vor MAC, kein „executed?“-Semantik) |
| Nits | — | `TRANSRIPT_LEN`-Tippfehler, verwaister Javadoc-Block, README-Claim „replay protection“ zu absolut |

---

## F1 (Hoch): Handshake-Replay setzt Sequence-Counter zurück — Replay-Schutz unterlaufen

**Root-Cause:** `exchange()` (Zeile 639) hat keinerlei Zustandsprüfung. Ein EXCHANGE wird
jederzeit akzeptiert — auch mehrfach hintereinander ohne zwischenzeitliches INIT. Da
`d_card` und `N_card` ohne INIT unverändert bleiben, leitet die Karte deterministisch
dieselben Session-Keys ab; das bestätigte Client-Token ist damit weiter gültig, und die Karte
setzt `lastRxSeq` und `txSeq` auf 0 zurück (Zeilen 723–725).

**Angriff** (On-Path-Angreifer, der den etablierten Kanal mitgeschnitten hat — z. B. NFC-Sniffing/Relay;
er braucht keine Geheimnisse):

1. Handshake + Commands der ehrlichen Session mitlesen (EXCHANGE-APDU, Protected Commands).
2. Innerhalb derselben SELECT-Session die alte EXCHANGE-APDU erneut senden → Karte akzeptiert
   (`9000`), Counter-Reset.
3.beliebige bereits ausgeführte Protected Commands erneut senden → werden **erneut ausgeführt**.

**PoC** (jcardsim, Suite 01; sinngemäß auch Suite 02, da identische State-Machine):

```text
1) original command       -> SW 9000
2) naive command replay   -> SW 6982 (expected 6982)   ← Sequenzzähler funktioniert
3) replayed EXCHANGE      -> SW 9000                     ← BUG: Karte akzeptiert und resettet
4) command replay #2      -> SW 9000 (MUST be 6982!)     ← Replay der Zahlung "transfer 100"
```

Das ist exakt der Fall, den der Test `testNewInitInvalidatesPendingExchange` *beinahe* fängt —
er testet nur die Gegenrichtung (INIT invalidiert altes EXCHANGE), nicht altes EXCHANGE bei
aktiver Session. Die Doku (Klasse, Zeile 86–88; README Zeile 129) behauptet „Replay protection:
strictly increasing sequence numbers“ — formal korrekt, aber die Counter sind durch den
Handshake-Replay **resettbar**, und damit ist die Kern-Claims gebrochen.

**Fix (minimal, ~4 Zeilen):**

```java
/** INIT war seit dem letzten successfulen EXCHANGE gesehen. */
private boolean handshakePending;

// initChannel():   handshakePending = true;
// exchange() am Anfang:
if (!handshakePending) {
  ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
}
// exchange() nach erfolgreichem Token-Check: handshakePending = false;
// wipeSession(): handshakePending = false;
```

Damit ist EXCHANGE exakt einmal pro INIT gültig. Zusätzlich in die Testsuite:
„EXCHANGE doppelt senden → zweites Mal 6982“ und „nach Etablierung altes EXCHANGE → 6982“
(bei aktiver Session muss der Token-Check zwar durchlaufen werden, aber das `handshakePending`-
Flag wirft vorher — nice: kein Crypto-Aufwand für den Angreifer). Optional härtend:
`lastRxSeq` bei re-etablierter Session nie unter den letzten Stand setzen (Epoch-Monotonie),
falls je doch ein zweiter Handshake-Pfad dazukommt.

## F2 (Mittel): Client verifiziert Response-Sequenz nicht

`SecureChannelClient.open()` prüft nur den `txPrefix`, nicht, dass `iv[4..12)` gegenüber der
letzten Response strikt steigt. Eine replizierte/verfrühte Antwort wird kryptografisch zwar
nicht „gefälscht“, aber der Client kann Response-Replays nicht erkennen — dabei stecken die
Informationen (Prefix + Seq) schon im IV. Zwei Bytes State im Client reichen.
Karten-seitig ist es richtig gemacht (`txSeq` streng monoton); der Referenz-Client, der als
Template für die Mobile App dient, sollte die Gegenprüfung ebenfalls zeigen.

## F3 (Mittel): Point-Validation implizit bei der Runtime

`peerPub.setW(...)` (Zeile 651) verlässt sich darauf, dass die Runtime das Peer-Point
against Invalid-Curve/Invalid-Encoding validiert. Das macht die Spec nicht überall
eindeutig; jcardsim und Oracle validieren i. d. R., aber „i. d. R.“ ist bei Krypto dünn.
Mildernd: beide Keys sind ephemeral → Invalid-Curve-Leaks wären kurzlebig; P-256 hat Cofactor 1,
Small-Subgroup-Attacken entfallen bei On-Curve-Prüfung. Empfehlung: Annahme explizit im
Security-Abschnitt dokumentieren (und idealerweise per KAT bei `probe()` testen: ungültiger
Punkt muss `CryptoException` liefern — sonst Install failen, statt unsichere Runtime zu riskieren).

## F4 (Niedrig): IV-Uniqueness-Marge über Sessions hinweg (GCM)

Session-IV = 4 B Zufall (`N_[card|peer][0..4)`) || 8 B Counter. Pro Session ist dasIV eindeutig
(strictly increasing seq) ✓. Über Sessions hinweg trennen nur 32 Zufallsbits: Präfix-Kollision
~ n²/2³² (bei ~65 k Sessions pro Karten-Key-Ära nicht mehr vernachlässigbar), und rx/tx teilen
sich `msgKey` — ein zufälliger rx/tx-Präfix-Zusammenstoß (p = 2⁻³²) plus überlappende Seq
wäre GCM-Nonce-Wiederverwendung unter demselben Key, also Totalverlust. Praktisch aktuell
vernachlässigbar, aber GCM-Nonce-Hygiene sollte man nicht dem Zufall überlassen:
richtungsgetrenne Schlüssel ableiten (eigene Labels `"-msgc"`/`"-msgs"`, TLS-Manier) oder die
Präfix-Länge/Session-Bindung dokumentieren. Für CBC-Suite (Determinismus bei IV-Wiederholung
unter gleichem Key + EtM) gilt Analoges, mit geringerer Konsequenz.

## F5 (Niedrig): Wipe-Asymmetrie als unterscheidbarer Oracle

In `secretPing`: Prefix-/Seq-Verstoß → `6982` ohne Wipe; MAC-Verstoß → `6982` **mit** Wipe.
Ein Angreifer kann das unterscheiden (nach einem Nicht-Wipe funktionieren folgende echte
Commands weiter). Gezielt präparierte Nachrichten können so prefix/seq-Zustand testen, ohne
die Session zu töten. Praktisch harmlos (Prefix ist für jeden Mitschnitt-Leser ohnehin klar,
und ohne Key folgt nur der Wipe-Branch), aber Prinzip: *alle* Authentizitätsfehler sollten
uniform behandeln. Entweder immer wischen (dann aber legitime Re-Transmits explizit erlauben,
siehe F10) oder die Unterscheidung bewusst dokumentieren.

## F6 (Niedrig): `openGcm`-Dual-Pfad ist clever, aber fragil

Die Analyse des Fallbacks (Zeile 964–987) stimmt — auf Spec-Runtimes verwirft der
`dlen == ctLen`-Check den BC-Retry, der Install-KAT fährt denselben Pfad. Aber:
(a) exception-getriebene Verhaltensverzweigung pro Nachricht ist审计-feindlich;
(b) fängt nur `CryptoException` — eine Runtime, die bei Tag-Mismatch einen anderen
RuntimeException wirft, würde bis zur Framework-Ebene durchreichen (kein Wipe!);
(c) auf BC-Runtimes kostet jeder *fehlgeschlagene* Open zwei volle Decryptions.
Empfehlung: Beim `probe()` einmalig die Semantik feststellen (existiert `verifyTag`
funktional? wirft `doFinal(ct)`?) und als `boolean bcStyle` ins Objekt; im Prozess dann
ein einziger deterministischer Pfad.

## F7 (Niedrig): `exchange()` — Seal der Antwort nach `sessionActive=true` ungeschützt

Zeile 725–733: Erst `sessionActive = true`, dann `seal(...)` ohne `try/catch` (im Gegensatz zu
`secretPing`). Wirft der Seal (CryptoException), bleibt eine aktive Session ohne vollendeten
Handshake — der Client weiß von nichts. Klein, aber Konsistency-halber wie in `secretPing`
behandeln (wipe + 6982) oder Seal vor das `sessionActive = true` ziehen.

## F8 (Niedrig): `parseSuiteParam` ohne Bounds-Check

Zeile 339–351 läuft die TLV-Kette durch, ohne `i + 1` gegen `bOffset + bLength` zu prüfen.
Ein malformed INSTALL (trusted Channel, aber Robustheit) kann statt des sauberen `0x9E01/0x9E02`
eine `ArrayIndexOutOfBoundsException` (Install-Fehlschlag mit generischem Fehler) produzieren.
Einmal `require(i + 2 <= bOffset + bLength)` reicht.

## F9 (Info): `ClassCastException` in `probe()`

Zeile 402: `(AEADCipher) Cipher.getInstance(AEADCipher.ALG_AES_GCM, false)` — wirft das
Runtime hier ein nicht-AEADCipher-Objekt, gibt's eine ungefangene `ClassCastException` statt
der sauberen `0x9F..`-Bitmaske. try/catch um den Cast.

## F10 (Info): Re-Transmit-Semantik

Da der Seq-Check *vor* der MAC-Verifikation liegt, erhält ein legitimer Re-Transmit einer
verlorengegangenen Response (gleicher Seq) ein `6982` — der Client weiß nicht, ob der Command
ausgeführt wurde. Für den Ping-Demo egal, für zustandsbehaftete Commands Design-Thema
(idempotency / „last seq“-Antwort statt Fehler). Bewusst entscheiden und dokumentieren.

---

## Was richtig gut ist

- **Encrypt-then-MAC** mit MAC-Verifikation **vor** der Decryption (Zeile 902–928);
  Padding-Fehler können gar nicht erst als Oracle dienen. Kein MAC-then-pad, kein CBC-MAC-Unfug.
- **HKDF** mit getrennten Labels pro Schlüssel und Suite; PRK/Z/Salt/tmp/hmacInner werden
  konsequent und zeitnah gelöscht (Zeile 688–691).
- **Key Confirmation** beidseitig, an volles Transcript inkl. Suite-Byte und Direction-Byte
  gebunden → keine Suite-/Richtungs-Verwechslung.
- **Suite-Fixierung beim Install** statt Verhandlung: kein Downgrade möglich, unbekannte
  Parameter failen die Installation hart.
- **Install-Zeit-KAT**, der exakt den späteren Runtime-Pfad (inkl. Portabilitäts-Dance)
  durchläuft und Tamper-Verwerfung prüft — vor `register()`, also kein halbfertiges Applet.
  Das habe ich so noch selten gesehen und es ist eine sehr gute Idee.
- **Transient-DESSELECT** für Schlüssel/Nonce/Counter, explizites `wipeSession()` bei jedem
  Integritätsfehler und bei Deselect.
- AAD bindet Header **inkl. Lc** (Truncation-Extension versperrt); Counter-Behandlung
  (strictly increasing, unsigned-Vergleich via `Util.arrayCompare`) korrekt; `increment`
  für Big-Endian richtig.
- Eigenbau-HMAC auf `MessageDigest` statt portabler `HMACKey` — Begründung (Bits-vs-Bytes
  Inkonsistenz) nachvollziehbar, Implementierung (RFC-2104-Pads, Ein-Schuss-Digeste) korrekt,
  Workspace-Überlappungen durchdacht (innere/äußere Blöcke, `macOff`-Check).
- Die Security-Notes der Klasse sind ungewöhnlich ehrlich (MITM-Disclaimer).

## Test-Lücken

1. **F1**: Doppeltes EXCHANGE ohne INIT (bei aktiver Session) — fehlt komplett, und die
   existierenden Replay-Tests (`runReplayRejected`) laufen direkt nach dem ersten Handshake
   und übersehen genau die Reset-Route.
2. Response-Replay auf Client-Seite (zu F2).
3. Extended/Edge-Längen: `lc`-Grenzen (`lc < ivLen + TAG_LEN` in `secretPing` bei
   P3 > tatsächlicher Datenmenge), CBC-mit-nicht-blockmultipler `ctLen` (funktioniert,
   wäre aber als expliziter Test gut).
4. Kein Test für `probe()`-Fehlerrouten (Schwerpunkt Simulator — auf echter Karte nachziehen).

## Empfohlene Reihenfolge

1. **F1** fixen + Regressionstest (Blocker für jeden produktiven Einsatz).
2. README/Doku-Klausur: „replay protection“ nur mit F1-Fix halten; F3-Annahme dokumentieren.
3. F2 (Client-Seq-Check — wandert als Referenz in die Mobile App).
4. F5–F7 bei nächster Gelegenheit; F8/F9 als Robustheits-Härtung.

## Fazit

Als Lern-/Demonstrationsobjekt für Secure Channels sehr solide und um Größenordnungen
sorgfältiger als die meisten Applet-Beispiele. Für den Einsatz in einem echten System:
F1 muss zuerst weg — die Replay-Protection ist das Rückgrat des Protokolls, und die ist
aktuell über einen simplen State-Machine-Fehler außer Kraft gesetzt. Ohne aktive
Netzwerk-Authentifizierung (dokumentiert) bleibt das Ganze ohnehin ein Kanal gegen
passive/passiv-injektive Angreifer, kein Identitätsnachweis.
