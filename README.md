# PcapAnalyse
PcapAnalyse ist ein python projekt das sich auf das Parsen von TLS Netzwerktraffik bezieht und daraus eine Anzahl von verschiedenen Statistiken erstellt um zu ermitteln welche Root Zertifizierungsstellen auf dem einem System verwendet werden. Die Auswertungen sollen darüber auskunft geben, ob und welche der ca 400 Root CA's in dem Zertifikatsspeicher zu "verbieten".

> Echtzeitbasierte Netzwerkdatenanalyse zur Ermittlung verwendeter Root Zertifikate

### Anforderungsanalyse
1. Die Zertifikate der Root Zertifizierungstellen sollen in das Programm eingelesen werden.
2. Das Programm soll über Argumentenparameter entweder eine Pcap-datei erhalten oder eine Netzwerkadresse an der das Programm dann in echtzeit den Netzwerkverkehr mitschneiden kann.
3. In beiden Fällen von zwei (Datei/Netzwerkadresse) sollen dann die TLS-Handshake Nachrichten extrahiert werden (-> inspiriert/angelehnt an Peter Moosmann Github)
4. Im verlauf des Programms werden dann die Zertifikatsnachrichten expliziert inspiziert und das jeweilige Rootzertifikat gesucht. 
5. 

In dem Hauptprogramm soll es möglich seine eine Liste an Root Zertifikaten einzulesen (aus einem Ordner der als Parameter an das Program übergeben wird), Außerdem soll es möglich seine eine Website anzugeben (diese muss aber von der CCADB zur Verfügung gestellt sein (https://ccadb-public.secure.force.com/microsoft/IncludedCACertificateReportForMSFT) und von dort die Zertifikate herunterzuladen.
Es soll auch möglich sein Netzwerkdaten in echtzeit zu analysieren und am Ende eine Auswertung darüber zu bekommen. 
### Parser
Der Parser ist für das Parsen und wiederherstellen der TCP Streams zuständig. Er übernimmt das Extrahieren des kompletten TLS Handshakes und gibt diese auf der Konsole aus wenn eines der Pakete übereinstimmt. Dazu kommt das dieser das extrahieren der Zertifikatskette übernimmt und diese an eine definierte Datenstruktur überträgt.
### Tree and Cert Klassen
Beim einlesen der Root Zertifikate wird aus jedem 

### Requirements
* treelib
* cryptography
* bs4
* requests
* coloredlogs
* dpkt
* netifaces
* pcapy

### Usage
**__PcapAnalysis only works with regular pcap files not with the wireshark pcapng files. For that it exists a converter that is builtin in wireshark__**
Simple analysis of a pcap file
```bash
python3 PcapAnalyse.py -f example.pcap
```
List all possible interfaces for sniffing
```bash
python3 PcapAnalyse.py --list-interfaces
```
