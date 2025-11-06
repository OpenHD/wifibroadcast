# Retransmission über UART bei Paketverlust

Dieser Leitfaden beschreibt die grundlegende Funktionsweise und enthält eine detaillierte Aufgabenliste, wie eine Retransmission für verlorene Pakete mittels UART implementiert werden kann. Die Kommunikation erfolgt dabei zwischen Empfänger und Sender über zwei UART-Schnittstellen.

## Grundsätzliche Funktionsweise

1. **Paketnummerierung:** Jedes gesendete Paket erhält eine fortlaufende Sequenznummer.
2. **Überwachung beim Empfänger:** Der Empfänger protokolliert die eingehenden Sequenznummern und erkennt fehlende Pakete.
3. **Anfrage über UART:** Erkennt der Empfänger eine Lücke in der Sequenz, sendet er eine Retransmissionsanfrage über UART an den Sender. Die Anfrage enthält mindestens die Sequenznummer des fehlenden Pakets.
4. **Antwort des Senders:** Der Sender lauscht auf Befehle am UART, sucht das angeforderte Paket im Puffer und überträgt es erneut über den Funkkanal.
5. **Bestätigung (optional):** Nach erfolgreichem Empfang kann der Empfänger eine Bestätigung über UART senden oder erneut um Übertragung bitten, falls das Paket noch fehlt.

## Detaillierte Aufgabenliste

### 1. Paketverwaltung und Sequenzierung
- [ ] Sequenznummern für alle gesendeten Pakete vergeben.
- [ ] Am Empfänger eine Struktur zum Nachhalten der zuletzt empfangenen Sequenznummern anlegen.
- [ ] Erkennen von Lücken in der Sequenz (z. B. durch einen Ringpuffer oder eine Hashmap für "vermisste" Pakete).

### 2. UART-Kommunikation vorbereiten
- [ ] Geeignete Baudrate und UART-Parameter für beide Seiten festlegen.
- [ ] UART-Schnittstelle initialisieren (Sender und Empfänger).
- [ ] Einfaches Protokoll für Retransmissionsbefehle definieren (z. B. `0xAA <seq_high> <seq_low> 0x55`).

### 3. Retransmissionsanfrage am Empfänger
- [ ] Beim Feststellen eines fehlenden Pakets den UART-Befehl mit Sequenznummer auslösen.
- [ ] Zeitstempel oder Wiederholungszähler anlegen, falls die Anfrage erneut gesendet werden muss.
- [ ] Optional: Puffer für mehrere offene Anfragen führen, um mehrere Paketverluste parallel zu behandeln.

### 4. Befehlsverarbeitung am Sender
- [ ] UART im Sender kontinuierlich auf eingehende Daten prüfen.
- [ ] Befehlspaket parsen und Sequenznummer extrahieren.
- [ ] Gespeicherte Pakete in einem Puffer oder Ringpuffer vorhalten, damit verlorene Pakete erneut gesendet werden können.
- [ ] Angefordertes Paket erneut über den Hauptübertragungskanal (z. B. WiFi) senden.

### 5. Optionale Bestätigungen
- [ ] Empfänger bestätigt per UART, dass das nachgesendete Paket erfolgreich empfangen wurde.
- [ ] Sender verwirft das Paket aus dem Puffer nach erfolgreicher Bestätigung oder nach einem Timeout.

### 6. Fehlerbehandlung und Timeouts
- [ ] Wenn der Sender das angeforderte Paket nicht mehr besitzt, Fehlermeldung oder Negativbestätigung über UART senden.
- [ ] Wiederholte Retransmissionsanfragen begrenzen, um Endlosschleifen zu vermeiden.
- [ ] Logging und Debug-Ausgaben implementieren, um Paketverlust und Retransmissionen nachvollziehen zu können.

### 7. Tests und Validierung
- [ ] UART-Verbindung im Labor testen (Loopback oder zwei Geräte).
- [ ] Paketverluste gezielt erzeugen (z. B. durch Dropping im Code) und sicherstellen, dass Retransmission ausgelöst wird.
- [ ] Performance messen: zusätzliche Latenz durch Retransmission und UART-Overhead beobachten.
- [ ] Stress-Test mit vielen gleichzeitigen Anfragen durchführen.

## Ausblick

Die beschriebenen Schritte bilden einen Ausgangspunkt. Erweiterungen könnten eine Priorisierung von kritischen Paketen, Verschlüsselung der UART-Kommandos oder eine adaptivere Strategie für wiederholte Paketverluste umfassen.

