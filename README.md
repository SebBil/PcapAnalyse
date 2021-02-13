# PcapAnalyse
PcapAnalyse ist ein python projekt das sich auf das Parsen von TLS Netzwerktraffik bezieht und daraus eine Anzahl von verschiedenen Statistiken erstellt um zu ermitteln welche Root Zertifizierungsstellen auf dem einem System verwendet werden. Die Auswertungen sollen darüber auskunft geben, ob und welche der ca 400 Root CA's in dem Zertifikatsspeicher zu "verbieten".

> Echtzeitbasierte Netzwerkdatenanalyse zur Ermittlung verwendeter Root Zertifikate

### Main
In dem Hauptprogramm soll es möglich seine eine Liste an Root Zertifikaten einzulesen (aus einem Ordner der als Parameter an das Program übergeben wird), Außerdem soll es möglich seine eine Website anzugeben (diese muss aber von der CCADB zur Verfügung gestellt sein (https://ccadb-public.secure.force.com/microsoft/IncludedCACertificateReportForMSFT) und von dort die Zertifikate herunterzuladen.
Es soll auch möglich sein Netzwerkdaten in echtzeit zu analysieren und am Ende eine Auswertung darüber zu bekommen. 
### Parser
Der Parser ist für das Parsen und wiederherstellen der TCP Streams zuständig. Er übernimmt das Extrahieren des kompletten TLS Handshakes und gibt diese auf der Konsole aus wenn eines der Pakete übereinstimmt. Dazu kommt das dieser das extrahieren der Zertifikatskette übernimmt und diese an eine definierte Datenstruktur überträgt.
### Tree and Cert Klassen
