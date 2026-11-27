#!/bin/bash
# verifier_projet.sh : vérifie que le coeur IMS (Kamailio + PyHSS) fonctionne.
# Usage : ./verifier_projet.sh
# Prérequis : PyHSS et les trois Kamailio (P-CSCF, I-CSCF, S-CSCF) doivent être démarrés.

DIR="$(cd "$(dirname "$0")" && pwd)"
DOMAINE="ims.mnc001.mcc001.3gppnetwork.org"
OK=0
KO=0
ok() { echo "[ OK ] $1"; OK=$((OK+1)); }
ko() { echo "[ KO ] $1"; KO=$((KO+1)); }

sudo -v || { echo "sudo est nécessaire (vérification des configurations Kamailio)"; exit 1; }

IP=$(grep -m1 -oE 'listen=udp:[0-9.]+' /etc/kamailio_pcscf/pcscf.cfg | cut -d: -f2)
echo "=== Adresse IMS déclarée dans les configurations : $IP"
if hostname -I | tr ' ' '\n' | grep -qx "$IP"; then
  ok "l'adresse $IP est bien celle de la machine"
else
  ko "l'adresse $IP ne correspond pas à la machine ($(hostname -I))"
fi
LIP=$(grep -m1 -oE 'LOCAL_IP = "[0-9.]+"' "$DIR/scripts/ims_appel.py" | grep -oE '[0-9.]+')
if [ "$LIP" = "$IP" ]; then
  ok "LOCAL_IP de scripts/ims_appel.py = $LIP"
else
  ko "LOCAL_IP de scripts/ims_appel.py ($LIP) différent de l'adresse IMS ($IP)"
fi

echo "=== Services de base"
for s in mariadb bind9 redis-server rtpengine-daemon; do
  if systemctl is-active --quiet "$s"; then ok "service $s actif"; else ko "service $s inactif"; fi
done

echo "=== Ports en écoute"
for p in 4060 5060 6060 3868 8080; do
  if ss -lntu | grep -qE "[:.]$p[[:space:]]"; then ok "port $p en écoute"; else ko "port $p absent"; fi
done
N=$(ss -tn state established '( dport = :3868 )' | tail -n +2 | wc -l)
if [ "$N" -ge 2 ]; then ok "$N sessions Diameter établies vers le HSS"; else ko "sessions Diameter vers le HSS : $N (2 attendues)"; fi

echo "=== DNS"
for h in scscf hss; do
  R=$(dig +short "$h.$DOMAINE" | head -1)
  if [ "$R" = "$IP" ]; then ok "$h.$DOMAINE = $R"; else ko "$h.$DOMAINE = '$R' (attendu $IP)"; fi
done
R=$(dig +short SRV "_sip._udp.$DOMAINE" | head -1)
case "$R" in
  "0 0 4060 icscf."*) ok "SRV _sip._udp = $R" ;;
  *) ko "SRV _sip._udp = '$R'" ;;
esac

echo "=== Configurations Kamailio"
for x in icscf scscf pcscf; do
  if sudo kamailio -c -f /etc/kamailio_$x/kamailio.cfg 2>&1 | grep -q "config file ok"; then
    ok "configuration $x valide"
  else
    ko "configuration $x invalide"
  fi
done
if [ "$(grep -cE '^##!define WITH_(RX|RX_REG|RX_CALL|IPSEC)$' /etc/kamailio_pcscf/pcscf.cfg)" -eq 4 ]; then
  ok "options Rx et IPsec désactivées au P-CSCF"
else
  ko "options Rx/IPsec du P-CSCF dans un état inattendu"
fi

echo "=== Test d'appel Alice (10001) -> Bob (10002)"
SORTIE=/tmp/verif_appel.txt
/usr/bin/python3 "$DIR/scripts/ims_appel.py" > "$SORTIE" 2>&1
if grep -q "APPEL COMPLET REUSSI" "$SORTIE"; then
  ok "appel complet réussi (INVITE, 180, 200, ACK, BYE)"
else
  ko "appel échoué (voir $SORTIE)"
  tail -15 "$SORTIE"
fi

echo
echo "Résultat : $OK contrôles réussis, $KO échecs"
if [ "$KO" -eq 0 ]; then
  echo ">>> PROJET IMS FONCTIONNEL"
  exit 0
else
  echo ">>> PROBLÈME DÉTECTÉ"
  exit 1
fi
