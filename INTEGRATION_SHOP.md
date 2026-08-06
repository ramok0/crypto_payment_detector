# Intégration au shop — nouveautés de configuration du detector

Document destiné à l'équipe backend / panel admin Karima.

## Résumé

Le detector applique désormais des valeurs par défaut pour tous ses réglages
d'infrastructure, ne panique plus quand une chaîne est mal configurée, et expose
un **catalogue de ses réglages** que le panel peut lire pour construire son
formulaire.

**Rien ne casse.** Le contrat existant (`GET /internal/runtime-config?scope=detector`
renvoyant un objet plat `{"CLE": "valeur"}`) est inchangé, et une configuration
qui fonctionne aujourd'hui continue de fonctionner à l'identique. Tout ce qui suit
est optionnel côté shop, **à une exception près** : le changement de `WORKDIR`
Docker (§7).

---

## 1. Ce qui change côté detector

### Moins de variables obligatoires

Le minimum vital par chaîne passe de 5-6 à 3-4 :

| Chaîne | Obligatoire | Auparavant aussi obligatoire |
| --- | --- | --- |
| Solana | `WEBHOOK_URL`, `WEBHOOK_SECRET`, `SOLANA_DEPOSIT_ADDRESS` | `SOLANA_WALLET_POOL_FILE`, `REDIS_URL` |
| Ethereum | + `ETH_GAS_TANK_PRIVATE_KEY`, `ETH_LEDGER_ADDRESS` | `ETH_WALLET_POOL_FILE`, `REDIS_URL` |
| Base | + `BASE_GAS_TANK_PRIVATE_KEY`, `BASE_LEDGER_ADDRESS` | `BASE_WALLET_POOL_FILE`, `REDIS_URL` |
| Bitcoin / Litecoin | `WEBHOOK_URL`, `WEBHOOK_SECRET`, `{BTC,LTC}_XPUB` | — |

Les clés privées et les destinations d'argent restent **toujours obligatoires** :
elles ne sont jamais générées ni devinées.

Nouveaux défauts appliqués quand la valeur n'est pas fournie :

| Variable | Défaut |
| --- | --- |
| `SOLANA_WALLET_POOL_FILE` | `wallet_pool/solana_wallets.json` |
| `ETH_WALLET_POOL_FILE` | `wallet_pool/ethereum_wallets.json` |
| `BASE_WALLET_POOL_FILE` | `wallet_pool/base_wallets.json` |
| `SOLANA_WALLET_POOL_SIZE` | `10` (nouvelle variable) |
| `REDIS_URL` | `redis://127.0.0.1:6379` |

Le fichier de pool Solana **s'auto-crée** désormais s'il est absent, comme le
faisaient déjà Ethereum et Base. Il contient l'unique copie des clés privées des
wallets gérés : il doit être sur un volume persistant et sauvegardé.

### Une chaîne incomplète ne tue plus le process

Auparavant, une variable manquante déclenchait un `panic!` : tout le process
tombait, y compris les chaînes correctement configurées. Désormais chaque chaîne
est construite indépendamment, et le boot affiche **un rapport unique** listant
tout ce qui manque :

```
=== Detector configuration ===
  [ETH] enabled — gas tank 0x2c75…, ledger 0x742d…, 10 wallet(s), 2 ERC-20 token(s)
  [BASE] DISABLED — missing settings:
        BASE_LEDGER_ADDRESS — Cold destination receiving ERC-20 sweeps and the gas tank's excess ETH.
```

Ce rapport sort sur **stderr** et non via `log`, pour rester visible même sans
`RUST_LOG`. Le filtre de log par défaut passe par ailleurs de `error` à `info`
(volume de logs en hausse ; forcer `RUST_LOG=warn` pour revenir en arrière).

### Correction : contrats ERC-20 sur Base

`BASE_ERC20_TOKENS=default` résolvait vers les contrats **Ethereum mainnet**.
Sur Base, le detector surveillait donc des adresses vides et aucun dépôt USDC/USDT
n'était détecté, sans rien dans les logs. `default` suit maintenant la chaîne :

- Base USDC `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` (6 décimales)
- Base USDT `0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2` (6 décimales)

**Action côté shop :** si le panel envoie aujourd'hui `BASE_ERC20_TOKENS` avec les
contrats Base écrits en dur, la valeur reste valide — rien à faire. S'il envoyait
`default` en croyant surveiller USDC sur Base, la détection était cassée et
redevient fonctionnelle sans changement de configuration.

---

## 2. Nouvel endpoint : `GET /internal/config-schema`

Décrit **la forme** de la configuration : chaque réglage, son défaut, s'il est
obligatoire, s'il est secret. Il ne lit jamais l'environnement — aucune valeur
configurée, et donc aucune clé privée, ne peut fuiter par là.

- **Service** : `crypto_payment_api` uniquement (le binaire `crypto_payment_detector`
  n'a pas de serveur HTTP). Port par défaut `3030`.
- **Auth** : en-tête `X-Internal-Service-Token`, comparé à `INTERNAL_SERVICE_TOKEN`
  en temps constant. C'est la même convention que celle utilisée en sortie vers
  `runtime-config`.
- **Codes de retour** :
  - `200` — schéma renvoyé
  - `401` — token absent ou invalide
  - `503` — `INTERNAL_SERVICE_TOKEN` n'est pas configuré côté detector.
    L'endpoint est alors **désactivé** : aucune autre route de ce serveur n'étant
    authentifiée, il refuse de servir une carte du déploiement à un appelant anonyme.

### Réponse

```json
{
  "settings": [
    {
      "key": "SOLANA_DEPOSIT_ADDRESS",
      "chain": "SOL",
      "kind": "address",
      "required": true,
      "secret": false,
      "default": null,
      "description": "Cold destination receiving swept SOL and SPL tokens. Enables the Solana chain."
    },
    {
      "key": "BASE_MIN_CONFIRMATIONS",
      "aliases": ["MIN_CONFIRMATIONS"],
      "chain": "BASE",
      "kind": "integer",
      "required": false,
      "secret": false,
      "default": "5",
      "description": "Confirmations required before sweeping and emitting payment_credited."
    },
    {
      "key": "ETH_GAS_TANK_PRIVATE_KEY",
      "chain": "ETH",
      "kind": "secret",
      "required": true,
      "secret": true,
      "default": null,
      "description": "Hot wallet funding gas top-ups and receiving native sweeps. Enables the chain."
    }
  ]
}
```

| Champ | Type | Sens |
| --- | --- | --- |
| `key` | string | Nom exact de la variable d'environnement. `{P}` est déjà déplié : `ETH_*` et `BASE_*` apparaissent comme deux entrées distinctes. |
| `aliases` | string[] | Noms de repli acceptés, dans l'ordre. **Absent** quand il n'y en a pas. Le panel doit écrire sur `key`, pas sur un alias. |
| `chain` | string \| null | `BTC`, `LTC`, `SOL`, `ETH`, `BASE`, ou `null` pour un réglage global. Sert à grouper le formulaire. |
| `kind` | string | `text`, `url`, `integer`, `decimal`, `boolean`, `address`, `secret`. Indication de rendu / validation. |
| `required` | bool | Sans valeur, la chaîne concernée reste désactivée. |
| `secret` | bool | À masquer dans l'UI et à chiffrer au repos. Un champ `secret` n'a **jamais** de `default`. |
| `default` | string \| null | Valeur appliquée par le detector si rien n'est fourni. Toujours une chaîne, même pour un nombre ou un booléen. |
| `description` | string | Texte d'aide, affichable tel quel. |

Le catalogue compte actuellement **109 entrées**, dont 9 obligatoires :
`WEBHOOK_URL`, `WEBHOOK_SECRET`, `BTC_XPUB`, `LTC_XPUB`, `SOLANA_DEPOSIT_ADDRESS`,
`ETH_GAS_TANK_PRIVATE_KEY`, `ETH_LEDGER_ADDRESS`, `BASE_GAS_TANK_PRIVATE_KEY`,
`BASE_LEDGER_ADDRESS`.

Le nombre et le contenu évoluent avec le detector : **ne pas figer cette liste
côté shop**, la relire au chargement de la page de configuration.

### Exemple d'appel

```bash
curl -s -H "X-Internal-Service-Token: $INTERNAL_SERVICE_TOKEN" \
  http://detector:3030/internal/config-schema
```

---

## 3. Intégration dans le panel Configuration

1. Au chargement de la page, appeler `/internal/config-schema`.
2. Grouper les entrées par `chain` (`null` → section « Global »).
3. Rendre chaque champ selon `kind` ; masquer ceux dont `secret` est `true`.
4. Utiliser `default` comme **placeholder**, pas comme valeur pré-remplie du champ.
   L'opérateur voit ainsi ce que le detector fera s'il laisse vide, et le panel
   n'enregistre que ce qui a été explicitement saisi.
5. Marquer visuellement les `required` : tant qu'ils sont vides, la chaîne
   correspondante ne démarrera pas.
6. À l'enregistrement, ne renvoyer dans `runtime-config` que les clés réellement
   renseignées (voir §4).

Un champ obligatoire suffit à identifier une chaîne « voulue » : c'est ce que le
detector utilise pour distinguer « chaîne non désirée » (silence) de « chaîne à
moitié configurée » (rapport détaillé). Les clés de bascule sont `{BTC,LTC}_XPUB`,
`SOLANA_DEPOSIT_ADDRESS`, `{ETH,BASE}_GAS_TANK_PRIVATE_KEY`.

---

## 4. Ce que le panel peut arrêter d'envoyer

Toutes les clés dont la valeur souhaitée est égale au `default` peuvent être
retirées de la réponse `runtime-config`. Cela réduit la surface de configuration
et fait automatiquement bénéficier le déploiement des futurs ajustements de
défauts.

Candidats typiques : `SOLANA_WALLET_POOL_FILE`, `{ETH,BASE}_WALLET_POOL_FILE`,
`REDIS_URL`, `{ETH,BASE}_CHAIN_ID`, `{ETH,BASE}_RPC_URL`, `SOLANA_RPC_URL`,
`FIAT_CURRENCY`, `*_MIN_CONFIRMATIONS`, `*_POLL_INTERVAL`, `*_STATE_FILE`,
`*_GAS_TANK_TARGET_USD`, `*_MAX_FEE_RATIO`.

Les envoyer quand même reste parfaitement valide — c'est une simplification
possible, pas une obligation.

---

## 5. Points d'attention

### Chaîne vide = non renseigné

Le detector traite désormais une valeur vide ou composée d'espaces **exactement
comme une variable absente** : les alias sont essayés, puis le défaut s'applique.

Concrètement, si le panel envoie `{"SOLANA_WALLET_POOL_FILE": ""}`, le detector
utilisera `wallet_pool/solana_wallets.json`. Auparavant il aurait accepté la chaîne
vide puis échoué plus loin, de façon plus obscure.

**Conséquence à vérifier côté shop :** si le panel sérialise les champs non
renseignés comme `""` plutôt que de les omettre, le comportement est correct mais
il vaut mieux les omettre pour que la distinction « vide » / « absent » reste
lisible dans la configuration stockée.

Cas particulier utile : envoyer `""` pour `{ETH,BASE}_GAS_TANK_PRIVATE_KEY` ou
`SOLANA_DEPOSIT_ADDRESS` **désactive proprement** la chaîne concernée.

### Valeurs numériques invalides

Une valeur non parsable (`ETH_MIN_CONFIRMATIONS=douze`) était jusqu'ici avalée en
silence, indiscernable d'une variable absente. Elle produit maintenant un
`log::warn` avant de retomber sur le défaut. Le panel devrait valider côté
formulaire d'après `kind`.

### Redémarrage sur changement

Inchangé : le watcher détecte toute modification de la réponse `runtime-config` et
provoque un `exit(0)`, en comptant sur le superviseur (`restart: unless-stopped`)
pour relancer. Une chaîne désactivée faute de configuration devient donc active
au cycle suivant dès que le panel fournit la valeur manquante — sans intervention.

### Redis reste requis pour Solana

Aucun mode mémoire n'existe pour Solana, et c'est délibéré : les assignations
d'adresses Solana sont **permanentes** (pas de TTL, contrairement aux réservations
EVM). Les perdre à un redémarrage réattribuerait un wallet déjà donné à un autre
utilisateur, avec un risque de créditer le mauvais compte. Le défaut
`redis://127.0.0.1:6379` couvre le cas simple ; en production, pointer le vrai
Redis.

`{ETH,BASE}_RESERVATION_STORE=memory` reste disponible côté EVM, pour les tests
uniquement.

---

## 6. Compatibilité — récapitulatif

| Sujet | Impact |
| --- | --- |
| Format `runtime-config` | Inchangé (objet plat clé → valeur string) |
| Auth `X-Internal-Service-Token` | Inchangée |
| Clés existantes | Toutes toujours reconnues, alias de repli conservés |
| Valeurs par défaut existantes | Aucune n'a changé de valeur |
| Config complète actuelle | Démarre à l'identique |
| Chaîne vide `""` | Désormais traitée comme « absent » → défaut |
| Volume de logs | En hausse (`info` par défaut au lieu de `error`) |
| `WORKDIR` Docker | **Changement à traiter — voir §7** |

---

## 7. Déploiement — action requise

Le Dockerfile fixe désormais `WORKDIR /data` (auparavant aucun, donc `/`), expose
le bon port (`3030` au lieu de `3000`) et déclare `VOLUME ["/data"]`.

**Risque :** un déploiement existant cherchera ses fichiers d'état relatifs dans
`/data` au lieu de `/`. Un detector qui ne retrouve pas son état **rescanne depuis
la pointe** et peut ré-émettre des webhooks pour des dépôts déjà traités.

Deux mitigations, au choix :

1. Monter le volume existant sur `/data`, en y déplaçant au préalable les fichiers
   d'état et le répertoire `wallet_pool/`.
2. Fixer des chemins absolus avant de déployer : `{BTC,LTC,SOL,ETH,BASE}_STATE_FILE`,
   `SOLANA_WALLET_POOL_FILE`, `{ETH,BASE}_WALLET_POOL_FILE`.

Le port publié doit également passer de `3000` à `3030` (ou `API_BIND` être ajusté).

Rappel : `wallet_pool/*.json` contient l'unique copie des clés privées des wallets
gérés. Volume persistant obligatoire, sauvegarde recommandée avant toute
acceptation de dépôt.

---

## 8. Checklist

- [ ] Le panel appelle `/internal/config-schema` et construit son formulaire dessus
- [ ] Les champs `secret: true` sont masqués et chiffrés au repos
- [ ] Les `default` sont affichés en placeholder, pas enregistrés comme valeurs
- [ ] Les champs `required` sont signalés comme bloquants pour leur chaîne
- [ ] Les champs vides sont omis de `runtime-config` plutôt qu'envoyés en `""`
- [ ] Validation côté formulaire selon `kind`
- [ ] `INTERNAL_SERVICE_TOKEN` configuré côté detector (sinon l'endpoint renvoie 503)
- [ ] Volume monté sur `/data`, fichiers d'état et `wallet_pool/` migrés
- [ ] Port publié passé à `3030`
- [ ] `BASE_ERC20_TOKENS` revu (la correction des contrats Base peut activer une
      détection jusque-là silencieusement inopérante)
