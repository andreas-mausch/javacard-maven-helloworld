# Review: Spike Secure Channel

## Umfang und Urteil

- Reviewdatum: 2026-11-17.
- Geprüfter Stand: `origin/spike/secure-channel`, Commit `6529227`, im Vergleich zu `main` (`59259a8`); Dateipfade und Zeilenangaben unten beziehen sich auf den Spike.
- Schwerpunkt: Applet, beide Host-Implementierungen, Integrationstests, Simulator-Smoke-Test und Build-/Protokolldokumentation.

**Urteil: Als Machbarkeitsnachweis brauchbar, als Vorlage für einen produktiven Secure Channel noch nicht freigeben.** Vor allem Handshake-Replay und fehlender Antwort-Replay-Schutz müssen behoben werden. Die CBC-Suite benötigt ein anderes IV-Konzept.

Positiv sind die festgelegte Suite ohne automatischen Downgrade, getrennte Verschlüsselungs-/MAC-Schlüssel bei CBC, MAC-Prüfung vor Entschlüsselung sowie die Tests gegen zwei unterschiedliche Java-Card-Laufzeiten. Die fehlende Gegenstellenauthentifizierung wird ausdrücklich dokumentiert: Das ist eine bekannte Grenze des Spikes, kein neu entdeckter Implementierungsfehler. Für Produktion bleibt sie dennoch ein Ausschlusskriterium.

## Findings

### 1. Hoch: Wiederholtes EXCHANGE reaktiviert alte Schlüssel und setzt Replay-Zähler zurück

**Ort:** `src/main/java/helloworld/SecureChannelApplet.java:639–739`, insbesondere `723–725`.

`exchange()` ist weder an einen ausstehenden INIT-Zustand gebunden noch auf eine einmalige Ausführung beschränkt. Nach einem erfolgreichen Handshake bleiben Karten-ECDH-Schlüssel und `nCard` unverändert. Ein aufgezeichnetes, gültiges EXCHANGE lässt sich daher erneut senden: ECDH, Salt und HKDF ergeben dieselben Schlüssel, der Client-Token validiert erneut, beide Zähler werden auf null gesetzt.

**Folgen:** Alte geschützte Requests werden wieder akzeptiert. Außerdem erzeugt die Karte erneut Antworten mit bereits verwendeten IVs unter demselben `K_msg`. Bei GCM ist diese Nonce-Wiederverwendung ein kryptografischer Sicherheitsbruch; unterschiedliche Antwortklartexte sind etwa durch Wiederholung älterer Requests in anderer Reihenfolge möglich. Dafür muss der Angreifer keine Sitzungsschlüssel kennen.

**Reproduktion:** INIT und EXCHANGE aufzeichnen; zwei unterschiedliche PINGs senden; das EXCHANGE erneut senden; den zweiten aufgezeichneten PING zuerst senden. Dieser wird wieder angenommen und seine Antwort verwendet Antwortsequenz 1 statt ursprünglich 2.

**Empfehlung:** Explizite Zustände `IDLE / INIT_PENDING / ACTIVE` einführen. EXCHANGE darf genau einmal pro frischem INIT erfolgen; den Pending-Zustand vor der kryptografischen Verarbeitung konsumieren. Bei Fehlern Schlüssel und Zustand verwerfen. Alten ephemeren privaten Schlüssel nach erfolgreicher Ableitung löschen, soweit die API dies erlaubt.

**Regressionstest:** Wiederholtes EXCHANGE während ACTIVE und nach einem Integritätsfehler muss scheitern; ein aufgezeichneter Request darf dadurch nicht wieder gültig werden. Für beide Suites testen.

### 2. Hoch: Host akzeptiert wiederholte und falsch zugeordnete Antworten

**Ort:** `src/test-integration/java/helloworld/integration/SecureChannelClient.java:189–209`; `simulator/OracleSimulatorSmokeTest.java:219–230`.

Beide `open()`-Implementierungen prüfen den IV-Präfix und den Tag/MAC, aber nicht die Antwortsequenz. Eine alte gültige Antwort für denselben INS kann beliebig oft als neue Antwort akzeptiert werden. Ein Tag schützt vor Veränderung, nicht vor Replay. Bei mehreren offenen Requests fehlt außerdem eine authentifizierte Zuordnung zum jeweiligen Request.

**Folgen:** Ein Transportangreifer kann aktuelle Ergebnisse durch alte Ergebnisse ersetzen. Der dokumentierte Replay-Schutz gilt damit nicht in beiden Richtungen. Besonders relevant ist, dass der Testclient ausdrücklich als Vorlage für eine mobile App bezeichnet wird.

**Empfehlung:** Empfangssequenz auf Hostseite verwalten und erst nach erfolgreicher Authentifizierung fortschreiben. Bei strikt sequenziellen APDUs die erwartete nächste Antwortsequenz verlangen; zusätzlich Request-Sequenz und Ergebnisstatus in die authentifizierten Antwortdaten aufnehmen. Fehlerstatus prüfen und bei einem gescheiterten Handshake lokale Session-Verwendung sperren.

**Regressionstest:** Dieselbe Antwort zweimal öffnen; eine ältere Antwort nach einer neueren einspeisen; Antworten zweier Requests vertauschen. Alle unerwarteten Antworten müssen abgewiesen werden.

### 3. Hoch: Vorhersehbare CBC-IVs erfüllen die Vertraulichkeitsanforderung nicht

**Ort:** `src/main/java/helloworld/SecureChannelApplet.java:781–793`; `src/test-integration/java/helloworld/integration/SecureChannelClient.java:383–388`; IV-Schema in `README.md`.

Für Suite 02 wird der IV aus öffentlichem Nonce-Präfix, monotonem Zähler und vier Nullbytes gebildet. Damit ist der nächste CBC-IV vorhersagbar. CBC benötigt für die übliche Sicherheit gegen gewählte Klartexte einen unvorhersagbaren IV; Eindeutigkeit allein genügt hier nicht. Encrypt-then-MAC behebt dieses Vertraulichkeitsproblem nicht.

**Konkretes Problem:** Für einen beobachteten ersten Klartextblock `P` mit IV `V` kann bei bekanntem nächsten IV `V'` der Block `P' = P XOR V XOR V'` gewählt werden. Identische erste Ciphertextblöcke verraten dann die entsprechende Klartexthypothese. Das ist kein Padding-Oracle, sondern ein Problem der Verschlüsselung vor der MAC-Bildung.

**Empfehlung:** Zufällige 16-Byte-IVs je CBC-Nachricht erzeugen und weiterhin mit authentifizieren. Replay-Sequenz als separates authentifiziertes Feld führen. Alternativ IVs über eine geeignete PRF mit separatem Schlüssel ableiten; nicht einfach das GCM-Zählerschema auf CBC übertragen.

### 4. Mittel: GCM verwendet denselben Nachrichtenschlüssel in beiden Richtungen ohne garantierte Nonce-Trennung

**Ort:** `src/main/java/helloworld/SecureChannelApplet.java:675–684, 719–724, 781–793`; `SecureChannelClient.java:159–160`.

Beide Richtungen verwenden `K_msg`. Ihre Nonces unterscheiden sich nur durch die ersten vier Bytes von `N_card` bzw. `N_peer`. Sind diese Präfixe gleich, kollidieren die GCM-Nonces bei gleichen Sequenznummern. Bei zufälligen Nonces beträgt diese Wahrscheinlichkeit pro Sitzung `2^-32`, nicht `2^-96`. Unterschiedliche AAD verhindert keinen Nonce-Reuse unter demselben Schlüssel.

**Empfehlung:** Richtungsabhängige Schlüssel mit separaten HKDF-Labels ableiten, etwa `msg-c2s` und `msg-s2c` (analog für MAC-Schlüssel), oder eine garantiert disjunkte Nonce-Domäne mit festem Richtungsbit definieren. Nicht auf zufällig unterschiedliche 32-Bit-Präfixe verlassen.

**Regressionstest:** Host-Nonce mit identischem Vier-Byte-Präfix wie Karten-Nonce erzwingen; die Konstruktion muss weiterhin garantiert getrennte Schlüssel/Nonce-Domänen besitzen.

### 5. Mittel: Empfang einer APDU wird fälschlich als atomar angenommen

**Ort:** `src/main/java/helloworld/SecureChannelApplet.java:641–650, 748–767`.

`setIncomingAndReceive()` liefert die Anzahl der zunächst empfangenen Bytes, nicht zwangsläufig die gesamte Lc. Weitere Daten können `receiveBytes()` erfordern, auch bei kurzen APDUs. Im EXCHANGE wird deshalb eine gültige, fragmentiert angelieferte Nachricht als falsche Länge verworfen. Beim PING wird aus der ersten Teilmenge eine falsche Ciphertext-/Tag-Länge berechnet, was sogar die aktive Sitzung löschen kann.

**Empfehlung:** Gesamtlänge über `getIncomingLength()` prüfen und alle Daten mit einer Empfangsschleife vollständig einsammeln. Kurze APDUs, maximale Payload und erforderliche Puffergröße ausdrücklich festlegen; Extended APDUs entweder implementieren oder sauber abweisen.

**Regressionstest:** Gültiges EXCHANGE und gültigen PING in mehreren Empfangsteilen zustellen. Happy-Path-Tests mit nur wenigen Klartextbytes decken diese Transportannahme nicht ab.

### 6. Mittel: Simulator-Smoke-Test kann ohne getesteten Secure Channel erfolgreich enden

**Ort:** `simulator/OracleSimulatorSmokeTest.java:76–86`; `.github/workflows/ci.yml:233`.

Jeder fehlgeschlagene SELECT einer Secure-Channel-Instanz wird als SKIP behandelt, unabhängig vom Statuswort. Fehlen beide Instanzen, können allein die HelloWorld-Prüfungen einen erfolgreichen Prozessabschluss liefern. Auch ein unerwarteter SELECT-Fehler wird dadurch verdeckt. Die vorherigen GP-Installationskommandos reduzieren das Risiko im aktuellen CI-Ablauf, beseitigen aber nicht die Schwäche des eigenständig nutzbaren Smoke-Tests.

**Empfehlung:** Im CI-Modus beide Suites zwingend verlangen. Für reale Karten einen expliziten Parameter für die erwartete Suite anbieten; mindestens eine Secure-Channel-Suite muss tatsächlich getestet werden. Nur einen ausdrücklich erlaubten „Instanz fehlt“-Fall überspringen, andere SELECT-Fehler als Fehler zählen.

## Weitere Hinweise und Testlücken

- **MAC-Vergleich:** `SecureChannelApplet.java:918` bezeichnet `Util.arrayCompare()` als constant-time. Die Java-Card-API garantiert das nicht. Die Hostclients verwenden ebenfalls `Arrays.equals()`. Die Kommentare sollten keine entsprechende Zusicherung machen; für sicherheitskritische Vergleiche eine geeignete Implementierung bzw. plattformspezifisch belegte primitive verwenden. Die tatsächliche Ausnutzbarkeit eines Timingkanals wurde nicht untersucht.
- **Ephemere Schlüssel sind persistent:** `ecdhPriv` wird mit `TYPE_EC_FP_PRIVATE` angelegt und von `wipeSession()` nicht gelöscht. Session-AES-Schlüssel und Scratch werden dagegen sinnvoll transient gehalten bzw. gewischt. Die Forward-Secrecy-Aussage sollte das Zeitfenster bis zum Überschreiben/Löschen des ECDH-Schlüssels berücksichtigen; außerdem erzeugt jedes INIT persistente Key-Updates.
- **Install-Probe:** `probe()` erzeugt anschließend nicht wiederverwendete Crypto-/Key-Objekte und Transient-Puffer. Die Dokumentation räumt dies ein. Auf Karten ohne Garbage Collection sollte die Probe möglichst auf den später verwendeten Objekten laufen und der RAM-/EEPROM-Verbrauch gemessen werden. „KAT“ ist hier überwiegend ein Roundtrip-/Tamper-Test, kein Vergleich mit extern bekannten Ciphertext-/Tag-Testvektoren.
- **Zustand und Fehler:** Ein malformed EXCHANGE während ACTIVE kann vor dem eigentlichen Tokencheck abbrechen oder Schlüssel teilweise verändern, ohne konsistent `sessionActive` zurückzusetzen. Ein expliziter Handshake-Zustandsautomat aus Finding 1 vereinfacht auch diese Fehlerbehandlung. Der Session-Flag selbst ist persistent; Reset-Verhalten sollte zusätzlich zu Deselect gezielt geprüft werden.
- **Grenzen:** Tests für maximale Payloads, CBC-Blockgrenzen, leere Nachrichten, ungültige EC-Punkte, manipulierte Header/IVs, fehlerhafte Bestätigungstoken und Zählerüberlauf fehlen. `increment()` läuft still auf null über; vor einem möglichen IV-Reuse muss die Sitzung enden.
- **Tests präzisieren:** Installations-Negativtests akzeptieren beliebige `Throwable` statt des vorgesehenen Fehlers. Der Tamper-Test verändert mit `raw.length - 3` einen Tag-/MAC-Byte, nicht wie kommentiert einen Ciphertext-Byte. Ciphertext, Tag und IV separat manipulieren und die jeweils erwartete Zustandswirkung prüfen.

## Verifikation und Grenzen dieses Reviews

Die Prüfung erfolgte statisch an einer isolierten Kopie des Spike-Stands. `mvn verify -B` wurde dort versucht, brach aber beim Maven-Enforcer ab: `java.compiler.main.path` (JDK 8) und `javacard.sdk.path` waren nicht gesetzt. Es wurden daher **keine Integrationstests, kein CAP-Build und keine neuen Karten-/Oracle-Simulator-Tests erfolgreich ausgeführt**. Die dokumentierten Hardware-Ergebnisse sind Berichte aus dem Spike, keine eigene Verifikation dieses Reviews. Die Reproduktionen oben sind aus dem Code abgeleitete Regressionstest-Szenarien, nicht ausgeführte PoCs.

## Empfohlene Reihenfolge

1. Einmaligen, zustandsgebundenen Handshake und Replay-Tests implementieren.
2. Richtungsschlüssel, Antwortsequenzprüfung und authentifizierte Request-Zuordnung festlegen.
3. CBC-IV-Schema korrigieren und Protokolldokumentation/Clients gemeinsam aktualisieren.
4. APDU-Empfang und Grenzfalltests härten; Smoke-Test im CI strikt machen.
5. Vor Produktion Gegenstellenauthentifizierung ergänzen und das geänderte Protokoll erneut sicherheitstechnisch reviewen.
