# WiFiBroadcast – Architektur und Zusammenspiel der Komponenten

## Überblick
WiFiBroadcast ist eine C++‑Bibliothek für Video‑ und Telemetrie‑Streaming über WLAN. Sie bietet Multiplexing, optionale Verschlüsselung sowie ausführliche Debug‑Statistiken.

## Kernkomponente: `WBTxRx`
`WBTxRx` stellt die niedrigstufige Schnittstelle zum WLAN‑Adapter bereit. Die Klasse kapselt Senden und Empfangen, verwaltet Schlüssel und erlaubt mehrere gleichzeitige Streams über einen sogenannten *radio_port*. Wichtige Eigenschaften:

- Selektive Verschlüsselung und Validierung pro Paket (Overhead ~16 Byte)
- Registrierung von Callbacks für eingehende Pakete oder spezifische Streams
- Statistiken zu Paket‑ und Bitraten für TX und RX

## Streams auf höherer Ebene
### `WBStreamTx`
Der Sender für einen einzelnen Stream baut auf `WBTxRx` auf und kann FEC einsetzen oder deaktivieren. Über optionale Warteschlangen werden Pakete oder Frames verarbeitet und bei Bedarf mehrfach injiziert, um Paketverluste zu reduzieren. Statistiken liefern Informationen über Durchsatz und verworfene Pakete.

### `WBStreamRx`
Der Empfänger ergänzt `WBTxRx` um die Rekonstruktion von Daten. Er dekodiert FEC‑geschützte Blöcke oder arbeitet im einfachen Sequenzmodus und kann optional in einem separaten Thread laufen. Umfangreiche Zähler erfassen Eingangs‑ und Ausgangsbitrate sowie FEC‑Ergebnisse.

### `WBVideoStreamTx`
Für Videodaten existiert der spezialisierte `WBVideoStreamTx`, der komplette Frames entgegennimmt, sie in Fragmente zerlegt und per FEC absichert. Ein eigener Thread zieht Frames aus einer Queue und injiziert sie über `WBTxRx`.

## Unterstützende Module
- **FECDisabled (`SimpleStream.hpp`)** – fügt Sequenznummern hinzu und verwirft Duplikate, erlaubt aber Pakete außerhalb der Reihenfolge, was für Telemetrie geeignet ist
- **FunkyQueue** – threadsichere Queue für das Producer/Consumer‑Muster; bietet spezielle Operationen zum Leeren bei Überlastung oder zeitgesteuertes Dequeueing
- **WiFiCard** – schlanke Abstraktion der verwendeten WLAN‑Karten inklusive Emulationsmodi für Tests
- **Externe Bibliotheken** – FEC‑ und Radiotap‑Implementierungen stammen aus externen Projekten und werden unter `lib/` mitgeführt

## Beispielprogramme
Das Repository enthält mehrere ausführbare Beispiele. `example_hello` zeigt den grundlegenden Austausch von Textnachrichten zwischen Luft‑ und Bodenstation. `example_udp` leitet UDP‑Pakete über einen Wifibroadcast‑Stream weiter und unterstützt optional FEC. Weitere Beispiele wie `benchmark` demonstrieren Performance‑Messungen.

## Datenfluss
1. Anwendung erzeugt Nutzdaten (z. B. Frame oder Telemetriebefehl).
2. Ein Sender (`WBStreamTx` oder `WBVideoStreamTx`) fragmentiert die Daten, wendet optional FEC und Verschlüsselung an und übergibt sie an `WBTxRx`.
3. `WBTxRx` fügt Radiotap- und IEEE80211‑Header an, injiziert das Paket über den WLAN‑Adapter und führt Statistiken.
4. Auf der Empfängerseite verteilt `WBTxRx` Pakete anhand des `radio_port` an die jeweiligen `WBStreamRx`‑Instanzen, die Daten rekonstruieren und an die Anwendung weitergeben.

## Fazit
Durch die klare Trennung zwischen der basalen Link‑Verwaltung (`WBTxRx`) und den darauf aufsetzenden Streams erlaubt WiFiBroadcast flexible Kombinationen von Video‑ und Telemetriebefehlen bei geringer Latenz und optionaler Fehlerkorrektur.
