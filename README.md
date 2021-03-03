# PcapAnalyse
PcapAnalyse ist ein python projekt das sich auf das Parsen von TLS Netzwerktraffik bezieht und daraus eine Anzahl von verschiedenen Statistiken erstellt um zu ermitteln welche Root Zertifizierungsstellen auf dem einem System verwendet werden. Die Auswertungen sollen darüber auskunft geben, ob und welche der ca 400 Root CA's in dem Zertifikatsspeicher zu "verbieten".

PcapAnalysis only works with regular pcap files not with the wireshark pcapng files. For that it exists a converter that is builtin in wireshark

> Echtzeitbasierte Netzwerkdatenanalyse zur Ermittlung verwendeter Root Zertifikate

### Prerequirements:
For sniffing with pcapy its nessersary that you install
+ Ubuntu/Debian:
    > sudo apt-get install libpcap-dev
+ Windows:
    > Installation of win-pcap: https://www.winpcap.org/devel.htm
+ For module netifaces you need to install
    > sudo apt-get install python3-dev

### Anforderungsanalyse
1. Die Zertifikate der Root Zertifizierungstellen sollen in das Programm eingelesen werden.
2. Das Programm soll über Argumentenparameter entweder eine Pcap-datei erhalten oder eine Netzwerkadresse an der das Programm dann in echtzeit den Netzwerkverkehr mitschneiden kann.
3. In beiden Fällen von zwei (Datei/Netzwerkadresse) sollen dann die TLS-Handshake Nachrichten extrahiert werden (-> inspiriert/angelehnt an Peter Moosmann Github)
4. Im verlauf des Programms werden dann die Zertifikatsnachrichten expliziert inspiziert und das jeweilige Rootzertifikat gesucht. 

Diese Anforderungen sollen in einem Python Program umgesetzt werden. Dazu dienen folgende Bibliotheken als Hilfe und der implementierte Code in angelehnt and PeterMosman's TLS protocol analyzer. Aufbau und Struktur des PcapAnalyzers:

* PcapAnalyse.py: Hauptprogramm das unter anderem die Statistiken plottet
* Parser.py: Der Parser ist für das Parsen und wiederherstellen der TCP Streams zuständig. Er übernimmt das Extrahieren des kompletten TLS Handshakes und gibt diese auf der Konsole aus wenn eines der Pakete übereinstimmt. Dazu kommt das dieser das extrahieren der Zertifikatskette übernimmt und diese an eine definierte Datenstruktur überträgt.
* GetRootCAs.py: Klasse für das herunterladen der Root CA Zertifikate und um diese in das Programm zu laden. 
* RootCATree.py: Abgeleitet von der treelib.Tree Klasse. Notwendig für das "anhängen" der Zertifikatsketten.
* CertNode.py: Abgeleitet von der treelib.Node Klasse um weitere für diese Entwicklung benötigte Eigenschaften hinzuzufügen.
* Constants.py: Die Constants Klasse beinhaltet die gängigen Cipher Suites und deren hexadezimalen Wert, sodas diese bei verarbeitung der Packets gemappt werden können.

Eine detailierte Auflistung der Funktionen und Eigenschaften der Klassen finden Sie im Anhang (UML/classes.png). 

__Methode:__

__Ergebnisse:__

### Dependencies
* pcapy (It depends on the platform { Windows: winpcap developer (wdpack); *nix: sudo apt-get install libpcap-dev } )
* dpkt

### Usage
Simple analysis of a pcap file
```bash
python3 PcapAnalyse.py -f example.pcap
```
List all possible interfaces for sniffing
```bash
python3 PcapAnalyse.py --list-interfaces
```

### TODO
* Logging the debug log in a file for a better overview in the stdout
* first seen of the certificates and the plot belongs to it
