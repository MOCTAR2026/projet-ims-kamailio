# Projet IMS : cœur IMS avec Kamailio et PyHSS

Travaux pratiques *Réseaux Télécoms Multiservices* — ESMT Dakar (Pr Boudal Niang).
Auteur : OSSENI Mohamed Moctar.

Ce dépôt contient la configuration, les scripts de test et les preuves d'un cœur IMS déployé sans Docker
(trois instances Kamailio 6.1.5 : P-CSCF, I-CSCF, S-CSCF, un HSS PyHSS, bind9, MariaDB et RTPEngine)
sur une seule machine virtuelle Ubuntu (VirtualBox). Document de référence : *Projet_IMS_Kamailio*.

## Résultat

- Enregistrement IMS-AKA complet d'Alice (10001) et de Bob (10002) : REGISTER, 401, REGISTER, 200 OK,
  avec UAR/UAA, MAR/MAA et SAR/SAA sur l'interface Cx.
- Appel complet Alice vers Bob : INVITE, 180 Ringing, 200 OK, ACK, BYE, 200 OK.
- Test reproduit cinq fois : quatre captures réseau (`preuves/appel2.pcap` à `appel5.pcap`) et un essai
  en mode NAT (`preuves/sortie_appel_nat.txt`).

## Architecture

| Fonction | Logiciel | Port(s) |
|---|---|---|
| P-CSCF | Kamailio (instance 1) | SIP 5060, Diameter 3871 |
| I-CSCF | Kamailio (instance 2) | SIP 4060, Diameter 3869 |
| S-CSCF | Kamailio (instance 3) | SIP 6060, Diameter 3870 |
| HSS | PyHSS | Diameter 3868, API 8080 |
| DNS | bind9 | 53 |
| Bases | MariaDB | 3306 |
| Relais média | RTPEngine | 2223 (contrôle) |

Domaine IMS : `ims.mnc001.mcc001.3gppnetwork.org` (MCC 001, MNC 01).

## Contenu du dépôt

    config/kamailio/        configurations des trois CSCF (copie de /etc/kamailio_pcscf, _icscf, _scscf)
    config/pyhss/           config.yaml et default_ifc.xml
    config/dns/             zone bind9 (db.ims), named.conf.local, résolveur
    config/rtpengine/       rtpengine.conf
    db/                     bases MariaDB des CSCF (bases_cscf.sql) et base SQLite de PyHSS (hss.db)
    scripts/                clients de test en Python : ims_aka_register.py et ims_appel.py
    preuves/                captures réseau (.pcap) et sorties des tests d'appel
    docs/                   compte rendu du projet
    verifier_projet.sh      script de vérification automatique
    configurer_mot_de_passe.sh   choix du mot de passe de la base MariaDB des CSCF

## Dépôt public : valeurs de test et mot de passe

Ce dépôt est public. Tout ce qu'il contient est une valeur de test du TP : les clés Ki, OPc et AMF des deux
abonnés (dans `db/hss.db` et dans `scripts/`) et les identifiants IMSI. **Ne pas les réutiliser en production.**

Le mot de passe des comptes MariaDB des CSCF n'est pas publié : dans `config/kamailio/`, il est remplacé par
l'espace réservé `__MOT_DE_PASSE_DB__`. Il se choisit avec le script `configurer_mot_de_passe.sh` (voir plus bas).

## Installer les configurations et choisir le mot de passe

Après l'installation décrite dans le HOWTO du TP (Kamailio 6.1, PyHSS, bind9, MariaDB, RTPEngine) :

1. Copier les configurations Kamailio, la zone DNS et la configuration de PyHSS :

        sudo cp -r config/kamailio/* /etc/
        sudo cp config/dns/db.ims config/dns/named.conf.local /etc/bind/
        sudo cp config/rtpengine/rtpengine.conf /etc/rtpengine/rtpengine.conf
        sudo cp config/pyhss/config.yaml config/pyhss/default_ifc.xml /opt/pyhss/

2. Créer les bases (`db/bases_cscf.sql`) :

        sudo mysql < db/bases_cscf.sql

3. Choisir le mot de passe de la base. Le script demande le mot de passe (8 caractères minimum), met à jour
   les comptes MariaDB `pcscf`, `scscf` et `icscf`, l'écrit dans les trois configurations Kamailio et teste les
   connexions :

        sudo ./configurer_mot_de_passe.sh

4. Redémarrer les trois Kamailio (voir « Démarrage manuel »), puis lancer `./verifier_projet.sh`.

Pour changer ensuite de mot de passe, relancer simplement le script puis redémarrer les trois Kamailio.

## Vérifier que le projet fonctionne

Sur la machine virtuelle, une fois PyHSS et les trois Kamailio démarrés :

    chmod +x verifier_projet.sh
    ./verifier_projet.sh

Le script contrôle l'adresse IP, les services, les ports, les sessions Diameter, le DNS, la syntaxe des trois
configurations Kamailio, puis lance un appel Alice vers Bob. Il se termine par `>>> PROJET IMS FONCTIONNEL`
si tout est correct.

Sans machine virtuelle, les preuves sont lisibles directement : `preuves/*.pcap` (à ouvrir avec Wireshark,
filtre `sip || diameter`) et `preuves/sortie_appel*.txt` (bilan `APPEL COMPLET REUSSI`).

## Démarrage manuel (un terminal par processus)

1. Services de base :

        sudo systemctl restart mariadb bind9 redis-server

2. PyHSS (trois terminaux) :

        cd /opt/pyhss && source .venv/bin/activate && cd services
        python3 diameterService.py
        python3 hssService.py
        python3 apiService.py

3. Kamailio, dans cet ordre (I-CSCF, S-CSCF, P-CSCF) :

        sudo kamailio -DD -E -u kamailio -g kamailio -f /etc/kamailio_icscf/kamailio.cfg -P /var/run/kamailio_icscf/kamailio_icscf.pid
        sudo kamailio -DD -E -u kamailio -g kamailio -f /etc/kamailio_scscf/kamailio.cfg -P /var/run/kamailio_scscf/kamailio_scscf.pid
        sudo kamailio -DD -E -u kamailio -g kamailio -f /etc/kamailio_pcscf/kamailio.cfg -P /var/run/kamailio_pcscf/kamailio_pcscf.pid

4. Test d'appel :

        /usr/bin/python3 scripts/ims_appel.py

## Abonnés de test

| | Alice | Bob |
|---|---|---|
| IMSI | 001010000010001 | 001010000010002 |
| MSISDN | 10001 | 10002 |
| IMPI | 001010000010001@ims.mnc001.mcc001.3gppnetwork.org | 001010000010002@ims.mnc001.mcc001.3gppnetwork.org |

Les clés Ki, OPc et AMF sont les valeurs de test du TP (présentes dans `db/hss.db` et dans les scripts).

## Adresse IP

Les fichiers de ce dépôt utilisent l'adresse de la machine au moment de l'export (mode NAT : `10.0.2.15`).
Si la machine a une autre adresse, remplacer l'ancienne par la nouvelle dans les configurations Kamailio
(`.cfg` et `.xml`), `config.yaml`, `db.ims`, `rtpengine.conf` et les scripts, puis redémarrer bind9, RTPEngine,
PyHSS et les trois CSCF.

## Écarts par rapport au TP et limites

- Options du P-CSCF désactivées comme prévu à l'étape 5.4 (Rx, IPsec) ; liste d'interconnexion du S-CSCF commentée.
- SIPp 3.7.2 n'a pas d'option AKA : l'authentification AKA est réalisée par un client en Python
  (`scripts/`). Un essai avec le softphone IMSDroid sur un téléphone Android physique n'a pas abouti
  (incompatibilité avec la version d'Android du téléphone).
- Le flux audio RTP n'a pas été testé : RTPEngine est actif, mais le client de test n'envoie que la signalisation.
- Sur le premier réseau, l'établissement de l'appel prenait 12 à 21 secondes ; il est d'environ 0,5 seconde sur le
  second réseau. La cause n'a pas été identifiée avec certitude.
