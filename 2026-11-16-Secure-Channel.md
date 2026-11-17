# Spike „Secure Channel" — Stand 2026-11-16

## Was der Spike macht

Ein **Secure Channel auf Applet-Ebene** (Arbeitsname **SC v1.1**) zwischen
Host und Java Card: verschlüsselte + integre Kommandos ohne SCP des
ISD, mit Standard-Krypto, bewusst schlank. Umgesetzt als zweite Applet
(`SecureChannelApplet`) im gleichen CAP neben HelloWorld.

**Handshake (2 APDUs):**

1. `INIT (INS 0x10)`: Host sendet ephemeren ECDH-P-256-Public-Key + Nonce;
   Karte antwortet mit eigenem ephemeren Key + Nonce + Suite-Byte.
2. `EXCHANGE (INS 0x12)`: beidseitiger Key-Confirmation-Token-Beweis.
   Shared Secret aus ECDH, daraus HKDF-SHA-256 getrennte Cipher-/MAC-Keys;
   der gesamte Handshake-Transcript (beide Keys, beide Nonces, Suite,
   Richtung) fließt in die Ableitung ein → Session-Keys sind an genau
   diesen Handshake gebunden.

**Geschützte Kommandos (`CLA 0x80`, z. B. `INS 0xB0` Secret Ping):**
Drahtformat `iv ‖ ct ‖ tag`; der IV trägt einen strikt monotonen
8-Byte-Folgezähler (Replay-Schutz); Antwort genauso gebaut. Ohne aktive
Session wird mit `0x6982` abgewiesen. Bei Manipulation, Replay oder
Deselect wird die Session komplett gewischt (Keys aus dem RAM).

**Zwei Cipher-Suiten, hart beim Install festgelegt** (GP-Install-Param,
1 Byte, **kein Default, kein Fallback, keine Laufzeit-Verhandlung**):

| Suite | Konstruktion | Warum |
|---|---|---|
| `01` | AES-256-GCM | bevorzugt, AEAD |
| `02` | AES-256-CBC (ISO9797-M2) + HMAC-SHA-256, Encrypt-then-MAC, Tag auf 16 B trunciert, MAC **vor** Decryption geprüft | Fallback für Karten ohne GCM — z. B. unsere echte Testkarte |

Fehlender Param → Install-Fehler `0x9E01`, unbkannter → `0x9E02`.
Mehrere Instanzen mit verschiedenen Suiten koexistieren im gleichen CAP
(`…0507` = GCM, `…0508` = CBC+HMAC).

**Install-Selbsttest:** Beim Install prüft die Applet jede für die
gewählte Suite nötige Primitive (inkl. funktionalem KAT über den
Produktionspfad); fehlt etwas, schlägt INSTALL mit Vendor-SW
`0x9F00|Bitmaske` fehl (z. B. `0x9F20` = Cipher fehlt). Fail-closed
by design — eine Applet mit unbrauchbarer Krypto entsteht gar nicht erst.

## Was noch fehlt

1. **Karten-Authentifizierung** — die offene Lücke: ein aktiver
   Angreifer im Lesekanal kann sich gegenüber dem Host als Karte
   ausgeben (kein Card-Auth in v1). Design für v2 steht in
   `TODO-Auth.md` (statischer ECDSA-P-256-Identity-Key, Signatur über
   den Handshake, Pflicht-Pinning am Host); ECDSA-Verfügbarkeit auf der
   echten Karte ist noch ungetestet.
2. **Nur Short APDUs** — max. ~227 B Nutzdaten pro Kommando; große
   Daten brauchen Extended APDU/Chaining.
3. **Kein Status-INS** (`GET_DATA`: Session aktiv? Version?) — nice to have.
4. Externe Review (Opus) steht aus; Ergebnisse einarbeiten.
5. PR/Auswertung des Spikes; `TODO-Auth.md` ist noch uncommittet.
6. Randthemen (in `.opencode/TODOs.md`): jcdk-Stale-CAP-Falle,
   CAP-Dateiname-nach-Package-AID-Frage.

## Einordnung

Bewusst **kein** GP-SCP11-konformes Protokoll, sondern ein edukativer
Eigenbau im SCP11b-Geist (siehe `SecureMessaging.md` §4.1 und
TODO-Auth.md). Ziel war Machbarkeit + Ehrlichkeit über Grenzen:
funktionierender Kanal auf echter Hardware, dokumentierte Lücken statt
vorgetäuschter Vollständigkeit.
