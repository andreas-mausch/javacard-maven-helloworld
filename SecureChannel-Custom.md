GridPlus/safe-card untersuchen, um einen fertigen Secure-Channel-Ansatz kennenzulernen.

https://github.com/GridPlus/safe-card
https://github.com/mobilesec/secure-channel-srp-android-lib

## 2. Ablauf des Secure Channels

Ein möglicher Ablauf:

1. Die App erzeugt ein ephemeres ECDH-Schlüsselpaar.
2. Das Applet erzeugt ebenfalls ein ephemeres ECDH-Schlüsselpaar.
3. Beide tauschen ihre öffentlichen Schlüssel über APDUs aus.
4. Beide berechnen unabhängig voneinander dasselbe Shared Secret.
5. Daraus werden Sitzungsschlüssel abgeleitet.
6. Alle weiteren APDUs werden verschlüsselt und authentifiziert übertragen.

Wichtig: ECDH allein schützt nicht vor Man-in-the-Middle-Angriffen. Du brauchst zusätzlich eine Authentifizierung der Gegenstelle, beispielsweise über ein langfristiges Geräteschlüsselpaar und Zertifikate oder einen vorinstallierten gemeinsamen Schlüssel.

## 3. Welchen Algorithmus würde ich nehmen?

Eine wichtige Einschränkung: AES-GCM ist nicht auf jeder JavaCard-Version bzw. jedem Kartenchip verfügbar. Deshalb würde ich die konkrete Kartenplattform berücksichtigen.

Meine Empfehlung:

| Verfahren | Empfehlung |
| --- | --- |
| ECDH P-256 | Schlüsselaustausch |
| HKDF-SHA-256 | Sitzungsschlüssel ableiten |
| AES-128/256 | Verschlüsselung |
| AES-CMAC | Integrität und Authentifizierung |
| Zufällige Nonces / Counter | Replay-Schutz |

Falls AES-GCM unterstützt wird, kannst du es alternativ als AEAD-Verfahren einsetzen.

## 4. Aufbau der APDUs

Du könntest beispielsweise folgende eigene APDU-Kommandos definieren:

| INS | Kommando | Zweck |
| --- | --- | --- |
| `0x10` | INIT | Session starten |
| `0x11` | GET\_PUBLIC\_KEY | Öffentlichen Schlüssel abrufen |
| `0x12` | EXCHANGE\_KEY | ECDH-Schlüsselaustausch |
| `0x20` | SECURE\_COMMAND | Verschlüsselte Daten senden |
| `0x21` | SECURE\_RESPONSE | Verschlüsselte Antwort empfangen |

Nach dem Handshake enthält die APDU nicht mehr die eigentlichen Nutzdaten, sondern beispielsweise:

text

```text
CLA INS P1 P2 Lc
    Session Counter
    Nonce
    Encrypted Data
    Authentication Tag
```

Die Applet-Seite entschlüsselt und überprüft die Daten, bevor sie den eigentlichen Befehl ausführt.

Wichtig sind eindeutige Nonces, Counter-Synchronisierung, Replay-Schutz und eine saubere Behandlung von Verbindungsabbrüchen.
