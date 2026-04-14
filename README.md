# NetSentinel

## Installation & Lancement

### Installation


### Lancement


## Rapport d'analyse sécurité

### Surfaces d’attaque restantes
L’outil détecte plusieurs classes d’attaques : **Brute-force**, **injections SQL**, **DDoS** et **scan de vulnérabilités**.
Cependant, certaines surfaces d’attaque restent possibles, la liste qui suit est __non-exhaustive__ :
- *Attaques lentes* : le **détecteur DDoS** repose sur un débit anormal, donc un attaquant très lent peut passer sous le radar.
- *Injections SQL obfusquées* : les patterns simples implémentés peuvent être contournés via encodage, commentaires, etc.
- *Scans distribués* : un scan réparti sur plusieurs IP ne déclenche pas le seuil > 20 URLs 404 par IP *(car une seule IP est surveillée à la fois)*.
- *Brute-force distribué* : même principe, 1 tentative par IP → aucune IP ne dépasse le seuil de 10 échecs.
- *User-agent falsifié* : les outils de scan peuvent changer leur user-agent pour ressembler à Chrome ou Firefox.
- *Endpoints non listés* : le **scan de vulnérabilités** ne surveille que quelques chemins sensibles prédéfinis.
- Corrélation temporelle basique : l’outil ne détecte pas des attaques étalées sur plusieurs heures / jours.

### Contournement des détecteurs
Un attaquant peut contourner les règles actuelles de plusieurs manières :
- Changer d’IP à chaque requête pour éviter les seuils par IP.
- Ralentir volontairement l’attaque pour rester sous les seuils (ex : 1 requête brute-force toutes les 40 secondes).
- Encoder les requêtes SQL (URL-encoding, Base64, hex, commentaires SQL) pour éviter les patterns simples.
- Utiliser un user-agent légitime pour contourner la détection des scanners.
- Scanner des chemins non listés pour éviter la détection des accès sensibles.
- Fragmenter les scans (ex : 5 URLs 404 par IP sur 5 IP différentes).
- Utiliser des attaques applicatives non couvertes (XSS, etc.).

### Propositions d’amélioration
Plusieurs améliorations peuvent renforcer l'outil :
1. Détection comportementale avancée
  - Analyse statistique du trafic (moyennes mobiles, écarts-types, anomalies).
  - Détection de variations soudaines plutôt que seuils fixes.
  - Corrélation temporelle sur plusieurs heures.
2. Détection distribuée
  - Regrouper les IP par pays, plage IP.
  - Détecter les attaques lentes réparties sur plusieurs sources.
3. Analyse plus intelligente des requêtes
  - Normalisation des URLs (décodage multiple).
  - Détection des injections SQL via analyse syntaxique (avec un parser).
  - Détection de patterns obfusqués.
4. Extension des surfaces surveillées
  - Ajouter XSS, Command Injection, etc.
  - Ajouter des endpoints sensibles dynamiques.
5. Intégration avec un firewall
  - Génération de règles iptables / fail2ban.
  - Blocage automatique des IP CRITICAL.
7. Amélioration de la whitelist
  - Whitelist par IP, mais aussi par user-agent, ou plage IP.
  - Whitelist temporaire (expiration automatique).
