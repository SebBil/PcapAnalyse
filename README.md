# PcapAnalyse
PcapAnalyse ist ein python projekt das sich auf das Parsen von TLS Netzwerktraffik bezieht und daraus eine Anzahl von verschiedenen Statistiken erstellt um zu ermitteln welche Root Zertifizierungsstellen auf dem einem System verwendet werden. Die Auswertungen sollen darüber auskunft geben, ob und welche der ca 400 Root CA's in dem Zertifikatsspeicher zu "verbieten".

> Echtzeitbasierte Netzwerkdatenanalyse zur Ermittlung verwendeter Root Zertifikate

### Anforderungsanalyse
1. Die Zertifikate der Root Zertifizierungstellen sollen in das Programm eingelesen werden.
2. Das Programm soll über Argumentenparameter entweder eine Pcap-datei erhalten oder eine Netzwerkadresse an der das Programm dann in echtzeit den Netzwerkverkehr mitschneiden kann.
3. In beiden Fällen von zwei (Datei/Netzwerkadresse) sollen dann die TLS-Handshake Nachrichten extrahiert werden (-> inspiriert/angelehnt an Peter Moosmann Github)
4. Im verlauf des Programms werden dann die Zertifikatsnachrichten expliziert inspiziert und das jeweilige Rootzertifikat gesucht. 

Diese Anforderungen sollen in einem Python Program umgesetzt werden. Dazu dienen folgende Bibliotheken als Hilfe und der implementierte Code in angelehnt and PeterMosman's TLS protocol analyzer. Aufbau und Struktur des PcapAnalyzers:

PcapAnalyse.py
Parser.py
GetRootCAs.py
RootCATree.py
Constants.py



_Methode:_



_Ergebnisse:_



### Parser
Der Parser ist für das Parsen und wiederherstellen der TCP Streams zuständig. Er übernimmt das Extrahieren des kompletten TLS Handshakes und gibt diese auf der Konsole aus wenn eines der Pakete übereinstimmt. Dazu kommt das dieser das extrahieren der Zertifikatskette übernimmt und diese an eine definierte Datenstruktur überträgt.

### Tree and Cert Klassen
Beim einlesen der Root Zertifikate wird aus jedem 

### Dependencies
* pcapy (It depends on the platform { Windows: winpcap developer (wdpack); *nix: sudo apt-get install libpcap-dev } )
* dpkt


**PcapAnalysis only works with regular pcap files not with the wireshark pcapng files. For that it exists a converter that is builtin in wireshark**
====================================================================================================================================================

### Usage
Simple analysis of a pcap file
```bash
python3 PcapAnalyse.py -f example.pcap
```
List all possible interfaces for sniffing
```bash
python3 PcapAnalyse.py --list-interfaces
```
