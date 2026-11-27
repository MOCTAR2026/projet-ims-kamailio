#!/bin/bash
# configurer_mot_de_passe.sh : choisit le mot de passe des comptes MariaDB des CSCF
# (pcscf, scscf, icscf) et l'écrit dans les configurations Kamailio de /etc.
# Usage : sudo ./configurer_mot_de_passe.sh   (le mot de passe est demandé, il n'est pas affiché)

if [ "$(id -u)" -ne 0 ]; then
  echo "Lancer avec sudo : sudo $0"
  exit 1
fi

read -r -s -p "Nouveau mot de passe de la base (8 caractères minimum : lettres, chiffres, . _ -) : " NEW; echo
read -r -s -p "Confirmer le mot de passe : " NEW2; echo
if [ "$NEW" != "$NEW2" ]; then
  echo "Les deux mots de passe sont différents."
  exit 1
fi
if ! printf '%s' "$NEW" | grep -qE '^[A-Za-z0-9_.-]{8,}$'; then
  echo "Mot de passe refusé : 8 caractères minimum, uniquement lettres, chiffres, point, tiret et underscore."
  exit 1
fi

echo "=== Comptes MariaDB"
for x in pcscf scscf icscf; do
  for h in localhost 127.0.0.1; do
    if [ "$x" = icscf ] && [ "$h" = 127.0.0.1 ]; then continue; fi
    if mysql -e "CREATE USER IF NOT EXISTS '$x'@'$h' IDENTIFIED BY '$NEW'; ALTER USER '$x'@'$h' IDENTIFIED BY '$NEW'; GRANT DELETE, INSERT, SELECT, UPDATE ON $x.* TO '$x'@'$h'; FLUSH PRIVILEGES;"; then
      echo "compte $x@$h : mot de passe défini"
    else
      echo "compte $x@$h : ERREUR"
    fi
  done
done

echo "=== Configurations Kamailio"
for x in pcscf scscf icscf; do
  F=/etc/kamailio_$x/$x.cfg
  if [ -f "$F" ]; then
    sed -i -E "s#(mysql://$x:)[^@]*@#\1$NEW@#g" "$F"
    echo "$F : $(grep -cF "mysql://$x:$NEW@" "$F") ligne(s) mise(s) à jour"
  else
    echo "$F introuvable"
  fi
done

echo "=== Vérification des connexions à la base"
for pair in "pcscf:127.0.0.1" "scscf:127.0.0.1" "icscf:localhost"; do
  x=${pair%%:*}
  h=${pair##*:}
  if MYSQL_PWD="$NEW" mysql -h "$h" -u "$x" -e "SELECT COUNT(*) FROM version" "$x" >/dev/null 2>&1; then
    echo "[ OK ] connexion $x@$h"
  else
    echo "[ KO ] connexion $x@$h (la base $x existe-t-elle ?)"
  fi
done
echo
echo "Redémarrer maintenant les trois Kamailio (I-CSCF, S-CSCF, P-CSCF) pour appliquer le mot de passe."
