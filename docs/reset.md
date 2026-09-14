# Reset et remplacement des wallets de dépôt

Le portail commun Karima propose **ETH**, **SOL**, **BASE**, **BTC**, **LTC**
et **Toutes les blockchains configurées**. Une confirmation `RESET ETH`
(ou la sélection correspondante) est obligatoire. L’action interrompt
temporairement tout le processus de détection, même pour un seul réseau.

Le reset efface l’état actif du réseau choisi : paiements en attente, historique
de détection et de notification, curseurs, cache de blocs/signatures et
affectations Redis, y compris les anciennes réservations. Il ne fait aucun
`FLUSHDB`/`FLUSHALL`. Les autres réseaux et les données métier d’Autoshop
(soldes, transactions, commandes et protections contre les doubles crédits)
sont conservés. Les anciens paiements ne sont plus suivis automatiquement.

- ETH/BASE/SOL : nouveaux wallets et nouvelles clés aléatoires, avec au moins
  autant de places que l’ancien pool (minimum 10). Les anciennes clés et leurs
  affectations sont archivées avant tout remplacement.
- BTC/LTC : nouvelle branche du compte XPUB/XPRIV conservé dans Infisical.
  Les anciennes adresses utilisaient `0/user_id`. Après le premier reset,
  elles utilisent `1/1/0/user_id`, puis `1/2/0/user_id`, etc. L’index transmis
  dans les webhooks reste le même identifiant client. Le fichier
  `<STATE_FILE>.wallet-generation.json` sélectionne la branche active.
- BTC/LTC et ETH/BASE : reprise après la hauteur courante obtenue auprès du
  fournisseur, avec tous les curseurs EVM initialisés à cette hauteur.
- SOL : état vide et nouveaux propriétaires/ATA ; aucune signature des anciens
  wallets n’est reprise. Le slot de coupure est conservé dans l’archive.

Les gas tanks et destinations de sweep restent configurés dans Infisical.
Le reset ne transfère pas leurs fonds et ne modifie pas les soldes clients.
Autoshop redemande l’adresse au détecteur : le prochain affichage obtient
la nouvelle adresse. Une adresse déjà copiée ou affichée avant le reset devient
obsolète. Un dépôt tardif sur cette adresse demande une récupération manuelle
avec les clés archivées, en vérifiant l’historique de crédit Autoshop.

## Stockage et reprise

Les deux démons et le binaire de maintenance partagent un verrou de fichier.
La maintenance exige un verrou exclusif : aucun processus de détection ne doit
encore utiliser ces volumes. Le répertoire `DETECTOR_MAINTENANCE_DIR` vaut
`.detector-maintenance` par défaut, donc `/data/.detector-maintenance` dans
l’image Docker. Tous les processus doivent utiliser le même répertoire sur
le volume persistant. Ne jamais placer ce répertoire dans `/tmp`.

Chaque opération écrit une archive privée dans
`archives/<id>/archive.json` : contenu original des fichiers (octets JSON),
nouveaux fichiers préparés, clés Redis avec `DUMP`/TTL, hauteurs de reprise,
et clés racines BTC/LTC nécessaires pour retrouver les anciennes branches.
Répertoires en `0700`, fichiers en `0600`. Ces fichiers contiennent des clés
privées : les inclure dans les sauvegardes chiffrées des volumes, pas dans Git,
les logs ni le chat. Les anciennes clés ne sont jamais purgées automatiquement.

L’archive est synchronisée sur disque avant le marqueur `pending.json`, lui-même
durable avant les modifications actives. Un échec après ce marqueur bloque
le démarrage des démons. Une reprise vérifie les fichiers et la configuration,
refuse d’écraser une nouvelle affectation Redis, puis termine le même plan.
Le reçu `complete` rend les nouveaux essais du même ID inoffensifs, même si
de nouveaux paiements ont été enregistrés depuis.

Dans le portail, utiliser **Reprendre le reset interrompu**. Le runner conserve
l’ID et la blockchain de l’opération. Il suspend la réconciliation Flux
`prod-app`, arrête les pods crypto, installe un initContainer de maintenance
avec la même image, les mêmes secrets et les mêmes volumes, puis attend le
retour du détecteur. Il retire ensuite l’initContainer et restaure l’état de
suspension initial de Flux. Les autres services continuent à tourner.
En cas d’échec, les autres actions du portail sont bloquées jusqu’à la reprise.
Ne pas retirer le journal, changer les chemins/clés/Redis, réactiver Flux ou
forcer un déploiement CI pendant une opération incomplète.

Le portail active l’action uniquement après avoir testé `crypto-reset-v1`
dans l’image de production exacte, lors d’un déploiement manuel. Une image
ultérieure sans cette vérification désactive à nouveau le bouton.

## Utilisation hors portail

Après avoir arrêté tous les démons, dans le même environnement et avec les
mêmes volumes/configuration :

```sh
crypto_payment_reset --version
crypto_payment_reset --replace-wallets ETH 012345abcdef
```

Choisir un ID hexadécimal unique de 12 à 64 caractères à la première exécution.
Réutiliser **exactement le même ID et la même sélection** après un échec.
L’exemple ci-dessus déclenche réellement un reset ; `--version` n’en déclenche
aucun. Il n’existe aucune route HTTP publique permettant de réinitialiser.

## Vérification locale

```sh
cargo fmt --all -- --check
cargo test --locked --all-targets
```

Le test d’intégration Redis est ignoré par défaut. Il exige un Redis jetable
sur `127.0.0.1:16379`, base 15 vide, et lance le véritable binaire dans un
répertoire temporaire avec configuration isolée et RPC simulé :

```sh
cargo test --locked --test reset_integration -- --ignored
```

Il vérifie le refus si un détecteur tient le verrou, un échec fournisseur sans
mutation, la rotation effective, l’archive, l’isolation des autres réseaux et
la conservation des nouveaux paiements lors d’un nouvel essai du même ID.
