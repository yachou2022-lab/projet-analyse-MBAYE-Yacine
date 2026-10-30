# Rapport d'analyse : journaux du pare-feu (semaine du 5 au 11 octobre 2026)

## Résumé
Après nettoyage (60 doublons exacts supprimés, protocoles normalisés en majuscules, 166 `bytes_sent` manquants remplacés par la médiane de 1 710 octets), le journal compte **5 440 connexions**. Le trafic est dominé par HTTPS (port 443), HTTP (80) et DNS (53), avec une part importante de MQTT (1883) liée aux objets connectés. **13,57 %** des connexions sont bloquées (DENY). Le trafic est régulier sur la journée (environ 200 connexions par heure), sauf un pic anormal à minuit. Deux comportements se détachent nettement du reste du réseau : un **scan de ports** et une **exfiltration de données** depuis une caméra.

## Comportements suspects

### 1. Scan de ports depuis `192.168.1.99` (PC)
- **400 connexions en 15 minutes** (le 8 octobre entre 00:00 et 00:15), toutes vers `10.0.0.5`.
- **328 ports de destination distincts** contactés, contre 7 à 8 pour toutes les autres IP (figure `05_ports_distincts_par_ip.png`).
- **383 connexions sur 400 refusées** par le pare-feu (95,75 %) : le pare-feu a bloqué la quasi-totalité du balayage, mais 17 connexions sont passées.
- Ce scan explique le pic de 610 connexions à l'heure 0 (`02_connexions_par_heure.png`).

### 2. Exfiltration de données depuis la caméra `192.168.1.11`
- **259,9 Mo envoyés** sur la semaine, soit environ **99 % du volume sortant de toutes les caméras** (262 Mo). Les autres caméras envoient environ 0,5 Mo chacune (figures `03_octets_par_appareil.png` et `06_octets_par_ip.png`).
- **38 gros transferts de 1 Mo ou plus** (jusqu'à 8,7 Mo chacun), tous **autorisés** et tous vers `8.8.8.8`, essentiellement sur le port **8080**. Le reste de son trafic est normal (médiane de 2 Ko par connexion).
- Une caméra n'a aucune raison d'envoyer de tels volumes vers l'extérieur : appareil probablement compromis.

### Autre point à surveiller
- Le **port 23 (Telnet)** est utilisé 100 fois par 29 IP sources, dont 26 connexions autorisées. Telnet transmet les identifiants en clair et n'a rien à faire sur ce réseau.

## Recommandations de sécurité
1. **Isoler `192.168.1.11`** du réseau, analyser son firmware, changer ses identifiants et le réinstaller. Examiner aussi la machine `8.8.8.8` contactée et vérifier si un service sortant 8080 est légitime.
2. **Segmenter les objets IoT** dans un VLAN dédié, avec un filtrage sortant strict : seuls les serveurs (MQTT, NTP, DNS interne) nécessaires sont autorisés. Les caméras ne doivent pas pouvoir joindre Internet librement.
3. **Fermer Telnet (23)** sur tout le réseau et le remplacer par SSH (22) avec authentification par clé.
4. **Bloquer le trafic sortant non nécessaire** (par exemple le 8080) et mettre en place une alerte sur le volume sortant anormal par équipement (seuil par appareil).
5. **Activer la détection de scan** (IDS/IPS) : bloquer automatiquement toute IP qui touche plus de 20 ports distincts en quelques minutes, et enquêter sur le poste `192.168.1.99` (malware ou utilisateur malveillant).
