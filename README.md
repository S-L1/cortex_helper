# Cortex Helper Scripts

*- English Version Below -*

### Beschreibung

Dieses Repository enthält einige Skripte, die verwendet werden können, um mehrere oder alle Einträge in der Cortex XSOAR Anwendung zu aktualisieren.
Jedes der Skripte startet mit einer kurzen Beschreibung was es tut und der Option, die aktuelle Ausführung abzubrechen.
In der [config.json](/config/config.json) werden die zu aktualisierenden Einträge aufgelistet und die Einstellungen für die API der Anwendung festgehalten.<br/>
Die Skripte können mit wenig Aufwand angepasst oder erweitert werden.

Diese Arbeit unterliegt den Bestimmungen einer MIT-Lizenz.<br/>
© 2023-2025 S. Liedtke.


### Quellen

Es werden teilweise Informationen von der [MITRE-Webseite](https://attack.mitre.org/) verwendet.<br/>
Teilweise werden Informationen von [ransomware.live](https://ransomware.live/#/) über die [API](https://api.ransomware.live/groups) abgerufen.


### Benötigte Python-Bibliotheken

 - json
 - ssl
 - BeautifulSoup
 - demisto_client
 - requests
 - os
 - odf.opendocument, odf.style, odf.text
 - datetime, time

## English Version

### Description

This repository contains some scripts which can be used to batch-update several or all records in the Cortex XSOAR application.
Each of the scripts starts with a short description of what it is doing and an option to stop the current execution.
In the [config.json](/config/config.json) the entries to be updated are listed and the settings to access the API of the Cortex Application are defined.<br/>
The scripts may be adjusted or extended with very little effort.

This work is licensed under an MIT License.<br/>
© 2023-2025 S. Liedtke.


### Sources

Some information is taken from the [MITRE-Website](https://attack.mitre.org/).<br/>
Some information is also called from [ransomware.live](https://ransomware.live/#/) via [API request](https://api.ransomware.live/groups).


### Python Libraries needed:

 - json
 - ssl
 - BeautifulSoup
 - demisto_client
 - requests
 - os
 - odf.opendocument, odf.style, odf.text
 - datetime, time
