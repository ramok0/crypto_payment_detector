# Notes d'intégration — session du 2026-05-03

Document destiné au shop qui consomme ce détecteur. Liste les changements de comportement, les nouvelles variables d'environnement et les actions à prendre côté ops avant de déployer.

## TL;DR

Deux nouvelles fonctionnalités, **toutes les deux opt-in** :

1. **USDC (et autres SPL tokens) sur Solana** — détection + sweep automatique vers `SOLANA_DEPOSIT_ADDRESS`.
2. **Sweep automatique BTC/LTC** — wallets tampons xpub-dérivés balayés vers une adresse cold après confirmation.

Si les nouvelles variables d'env ne sont pas définies, **le comportement existant reste identique** (BTC/LTC en lecture seule, Solana SOL natif uniquement, ETH/ERC-20 inchangé).

---

## 1. Solana — USDC / SPL tokens + gas tank

### Architecture des wallets

Trois rôles distincts, à séparer pour de vrai (pattern identique au gas tank Ethereum) :

| Rôle | Adresse | Clé privée présente côté serveur ? | Solde typique |
| ---- | ------- | ----------------------------------- | ------------- |
| **Cold / ledger** (`SOLANA_DEPOSIT_ADDRESS`) | wallet froid (idéalement hardware wallet) | ❌ Non — la pubkey suffit | accumule tous les fonds |
| **Gas tank** (`SOLANA_GAS_TANK_PRIVATE_KEY`) | wallet hot intermédiaire | ✅ Oui (clé privée requise) | maintenu autour de `SOLANA_GAS_TANK_TARGET_USD` (~$10) |
| **Wallets gérés** (pool `SOLANA_WALLET_POOL_FILE`) | adresses temporaires réservées aux users | ✅ Oui | quasi-vide entre les sweeps |

### Flux des fonds

```
                  user envoie SOL
                       │
                       ▼
              wallet géré (réservé)
                       │
                       │  sweep après confirmation
                       ▼
                  GAS TANK ($10)
                       │
                       │  maintenance périodique : si balance > target, sweep excess
                       ▼
                COLD / LEDGER
                  (cumule tout)


                  user envoie USDC
                       │
                       ▼
            ATA(wallet géré, USDC)
                       │
                       │  sweep direct (gas tank paie les frais)
                       ▼
              ATA(COLD, USDC)
                  (cumule tout)
```

Points-clés :
- **Le gas tank n'accumule jamais d'USDC** — les tokens vont directement à l'ATA du wallet froid.
- **Le SOL natif transite par le gas tank** : sweepé depuis les wallets gérés vers le gas tank, puis l'excès au-dessus du target part vers le wallet froid à intervalles réguliers (`SOLANA_GAS_TANK_INTERVAL_SECS`, défaut 15 min).
- **Le gas tank doit avoir ≥ target SOL** : sinon les sweeps USDC vont rater faute de SOL pour les frais. Un warning est loggé si le solde tombe sous le target (envisager une alerte d'ops).

### Variables d'environnement à ajouter

```env
# Liste des tokens SPL à surveiller (défaut = USDC mainnet)
SOLANA_SPL_TOKENS=USDC:EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v:6

# Clé privée du gas tank (Base58 ou tableau JSON 64 bytes)
# REQUIS si SOLANA_SPL_TOKENS est non vide
# DOIT être un wallet DIFFÉRENT de SOLANA_DEPOSIT_ADDRESS (sinon warning + funds non séparés)
SOLANA_GAS_TANK_PRIVATE_KEY=<base58_secret_key>

# Solde cible du gas tank en USD (défaut 10) — l'excès est automatiquement envoyé vers le ledger
SOLANA_GAS_TANK_TARGET_USD=10

# Intervalle de maintenance du gas tank en secondes (défaut 900 = 15 min)
SOLANA_GAS_TANK_INTERVAL_SECS=900
```

> ℹ️ Compatibilité : l'ancien nom `SOLANA_FEE_PAYER_PRIVATE_KEY` reste accepté en fallback. Préférer `SOLANA_GAS_TANK_PRIVATE_KEY` pour les nouveaux déploiements.

### Sweep automatique des fonds orphelins au démarrage

À chaque lancement du processus (`crypto_payment_detector` ou `crypto_payment_api`), le détecteur Solana scanne **tous les wallets de son pool**, ignore ceux qui sont actuellement réservés (présents en Redis), et balaie automatiquement :
- Le solde SOL natif → vers le gas tank (ou cold si pas de gas tank)
- Le solde de chaque token configuré (USDC, etc.) → vers l'ATA du wallet froid

Ça récupère les fonds bloqués sur des wallets dont la réservation a expiré avant que le dépôt soit confirmé, ou si le détecteur a crashé entre la détection et le sweep.

Logs au démarrage :
```
[SOL] Orphan sweep starting: 100 managed wallet(s), skipping 3 active reservation(s)
[SOL] Orphan SOL swept: 50000 lamports from <addr> (index 17, tx=...)
[SOL] Orphan USDC swept: 1000000 units from <addr> (index 42, ata=..., tx=...)
[SOL] Orphan sweep complete: 1 SOL sweep(s) (50000 lamports total), 1 token sweep(s)
```

Aucune action ops requise — c'est automatique. Si le scan échoue (Redis injoignable, etc.), le démarrage continue normalement (`log::warn`).

### ⚠️ Actions ops obligatoires avant le premier dépôt USDC

1. **Générer le gas tank** comme un wallet Solana standard (cf. méthodes plus bas), récupérer pubkey + private key.

2. **Créer l'ATA de destination sur le wallet COLD** (pas sur le gas tank) — le détecteur ne la crée pas, pour ne pas payer le rent à chaque sweep raté :
   ```bash
   spl-token create-account <USDC_MINT> \
     --owner <SOLANA_DEPOSIT_ADDRESS> \
     --fee-payer <gas_tank.json>
   ```
   Vérifier :
   ```bash
   spl-token accounts --owner <SOLANA_DEPOSIT_ADDRESS>
   # Doit lister une ligne pour chaque mint configuré
   ```

3. **Funder le gas tank en SOL** — minimum équivalent à `SOLANA_GAS_TANK_TARGET_USD` + une marge :
   ```bash
   solana transfer <GAS_TANK_PUBKEY> 0.1 --from <wallet_source.json>
   ```

4. **Vérifier la séparation cold ≠ gas tank** : la pubkey dérivée de `SOLANA_GAS_TANK_PRIVATE_KEY` doit être différente de `SOLANA_DEPOSIT_ADDRESS`. Le détecteur log un warning au démarrage si elles matchent :
   ```
   [SOL] SOLANA_GAS_TANK_PRIVATE_KEY pubkey ... matches SOLANA_DEPOSIT_ADDRESS; ...
   ```

### Côté shop : changements API

L'endpoint `POST /solana/reserve` répond comme avant : il rend l'adresse propriétaire (pas l'ATA). C'est l'utilisateur qui envoie ses USDC à cette adresse propriétaire, et son wallet (Phantom/Solflare/etc.) crée automatiquement l'ATA et y dépose les fonds. Aucun changement nécessaire dans votre flow utilisateur.

Si vous voulez afficher l'ATA spécifique d'un token au lieu de l'adresse propriétaire (pour les wallets qui ne gèrent pas l'auto-création), vous pouvez la calculer côté shop :

```js
// JS exemple avec @solana/web3.js + @solana/spl-token
import { getAssociatedTokenAddressSync } from "@solana/spl-token";
import { PublicKey } from "@solana/web3.js";

const ata = getAssociatedTokenAddressSync(
  new PublicKey(USDC_MINT),
  new PublicKey(reservation.address)
);
```

---

## 2. BTC/LTC — sweep automatique vers cold storage

### Ce qui change

- Le détecteur peut maintenant **balayer automatiquement** les UTXOs des adresses dérivées de l'xpub vers une adresse cold storage, après `BTC_MIN_CONFIRMATIONS`/`LTC_MIN_CONFIRMATIONS` confirmations.
- Le sweep est **opt-in** : tant que vous ne définissez pas les nouvelles variables, **rien ne change**, le détecteur reste en lecture seule.
- Le webhook `payment_credited` après sweep inclut maintenant `swept_to_address`, `swept_amount_sat`, `swept_amount_coin`, `sweep_txid`.

### Variables d'environnement à ajouter

```env
# === Bitcoin ===
# Extended private key (BIP84) correspondant à BTC_XPUB. SANS lui, pas de sweep.
BTC_XPRIV=xprv9s21ZrQH143K3...

# Adresse cold storage (P2WPKH bech32 obligatoire — bc1q... pour BTC)
BTC_SWEEP_DESTINATION=bc1q...

# Optionnel — taux de fee en sat/vByte (défaut 5)
BTC_SWEEP_FEE_RATE_SATS_PER_VB=10

# Optionnel — montant minimum à balayer en sats (défaut 5000)
# Sous ce seuil, le sweep est skippé (UTXOs accumulés jusqu'à ce que ça vaille la peine)
BTC_SWEEP_MIN_SAT=10000

# === Litecoin === (mêmes options, préfixe LTC_)
LTC_XPRIV=Ltpv71G8qDifUiNet9...
LTC_SWEEP_DESTINATION=ltc1q...
LTC_SWEEP_FEE_RATE_SATS_PER_VB=2
LTC_SWEEP_MIN_SAT=10000
```

### ⚠️ Contraintes importantes

1. **Format de l'adresse de destination** : uniquement **bech32 P2WPKH** :
   - BTC : `bc1q...` (42 caractères)
   - LTC : `ltc1q...` (43 caractères)
   - **Ne marche pas** : adresses legacy (`1...`, `L...`, `M...`, `3...`), Taproot (`bc1p...`), multisig P2WSH (`bc1q...` plus long).
2. **xpriv au format BIP84** correspondant à l'xpub déjà configuré (sinon les clés privées ne matcheront pas les adresses surveillées).
3. **xpriv à protéger** : c'est la clé qui contrôle tous les fonds entrants jusqu'au sweep. Stockage chiffré recommandé (vault, secret manager, etc.). Le détecteur la lit en mémoire au démarrage.
4. **Fee rate adapté à la congestion** : en cas de mempool engorgé, augmenter `BTC_SWEEP_FEE_RATE_SATS_PER_VB`. Pas d'estimation dynamique pour l'instant.
5. **Explorer Esplora requis** : le sweep utilise `/address/{addr}/utxo` et `POST /tx`. Si vous avez configuré uniquement Blockchair (`EXPLORER_API_URLS=https://api.blockchair.com/...`), le sweep ne pourra pas s'exécuter (warning loggé, webhook envoyé sans sweep). Garder au moins un explorer Esplora dans la liste — par défaut c'est `blockstream.info` et `litecoinspace.org`.

### Comment générer/dériver les xpriv

L'xpriv doit correspondre exactement à l'xpub déjà en config (même seed, même path BIP84 : `m/84'/0'/0'` pour BTC, `m/84'/2'/0'` pour LTC).

Si vous avez généré l'xpub depuis un wallet hardware/software, exportez aussi le xpriv correspondant. Avec `bx` (libbitcoin) :

```bash
# Master seed -> xpriv niveau compte
bx hd-new <SEED_HEX> | bx hd-private --hard 84 | bx hd-private --hard 0 | bx hd-private --hard 0
```

Avec `bitcoin-cli` (wallet déjà existant) :
```bash
bitcoin-cli -rpcwallet=hot listdescriptors true
# Cherche le descriptor wpkh(...) avec /84'/0'/0' — l'xprv est dans la chaîne
```

---

## 3. Récap des nouveaux champs dans les webhooks

Les anciens champs sont conservés. Les nouveaux ne sont émis que pour les paiements en token (Solana SPL ou Ethereum ERC-20) :

```jsonc
{
  "event": "payment_credited",
  "data": {
    // Champs existants (inchangés)
    "chain": "solana",
    "ticker": "USDC",                       // <- maintenant peut être USDC/USDT/etc, pas que SOL
    "txid": "...",
    "address": "...",
    "user_id": "...",
    "amount_sat": 1000000,                  // pour USDC : montant en base units (= sats du token)
    "amount_coin": 1.0,                     // 1.0 USDC
    "confirmations": 32,
    "block_height": 12345,
    "derivation_index": 17,

    // Champs sweep (existants — désormais aussi remplis pour BTC/LTC)
    "swept_to_address": "...",
    "swept_amount_sat": 998000,
    "swept_amount_coin": 0.998,
    "sweep_txid": "...",

    // Champs fiat (existants)
    "fiat_amount": 0.92,                    // basé sur le taux SOL/EUR ÷ SOL/USD pour USDC
    "fiat_currency": "EUR",
    "coin_price": 0.92,

    // ▶ Nouveaux champs (uniquement pour les tokens) ◀
    "asset": "USDC",                        // symbole du token
    "asset_decimals": 6,
    "amount_base_units": "1000000",         // string pour éviter la perte de précision sur uint256/u64
    "swept_amount_base_units": "998000",
    "token_contract": "EPjFWdd5..."         // mint Solana ou contract address Ethereum
  }
}
```

**Compatibilité** : ces nouveaux champs sont `Option`, donc absents (pas envoyés du tout) pour les paiements natifs SOL/BTC/LTC/ETH. Les consommateurs existants ne devraient rien casser. Si vous parsez avec un schéma strict, ajoutez ces champs comme optionnels.

---

## 4. Récap : variables d'environnement par chaîne

### Bitcoin / Litecoin (déjà existantes — pour rappel)

```env
BTC_XPUB=xpub6...
LTC_XPUB=Ltub2...
BTC_MIN_CONFIRMATIONS=3
LTC_MIN_CONFIRMATIONS=2
BTC_POLL_INTERVAL=120
LTC_POLL_INTERVAL=30
```

### Bitcoin / Litecoin — nouvelles (sweep)

```env
BTC_XPRIV=xprv9s21ZrQH143K3...
BTC_SWEEP_DESTINATION=bc1q...
BTC_SWEEP_FEE_RATE_SATS_PER_VB=5     # défaut 5
BTC_SWEEP_MIN_SAT=5000               # défaut 5000

LTC_XPRIV=Ltpv...
LTC_SWEEP_DESTINATION=ltc1q...
LTC_SWEEP_FEE_RATE_SATS_PER_VB=5
LTC_SWEEP_MIN_SAT=5000
```

### Solana — nouvelles (USDC + gas tank)

```env
SOLANA_SPL_TOKENS=USDC:EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v:6
SOLANA_GAS_TANK_PRIVATE_KEY=<base58_secret>      # wallet hot distinct du cold
SOLANA_GAS_TANK_TARGET_USD=10                    # défaut 10
SOLANA_GAS_TANK_INTERVAL_SECS=900                # défaut 900 (15 min)
```

### Ethereum (déjà existantes — pour rappel, rien de nouveau cette session)

```env
ETH_ERC20_TOKENS=USDC:0xA0b8...:6,USDT:0xdAC1...:6
ETH_GAS_TANK_PRIVATE_KEY=0x...
ETH_LEDGER_ADDRESS=0x...
```

---

## 5. Checklist déploiement

- [ ] Backup de l'ancien `.env` avant modif.
- [ ] Si vous activez les SPL tokens :
  - [ ] Décider de la liste des tokens et la mettre dans `SOLANA_SPL_TOKENS`.
  - [ ] Générer un **nouveau wallet** pour le gas tank, **différent** de `SOLANA_DEPOSIT_ADDRESS` (cold). Mettre sa private key dans `SOLANA_GAS_TANK_PRIVATE_KEY`.
  - [ ] Créer l'ATA de destination pour chaque mint sur le wallet COLD (`spl-token create-account <MINT> --owner <SOLANA_DEPOSIT_ADDRESS> --fee-payer <gas_tank.json>`).
  - [ ] Funder le gas tank en SOL (≥ équivalent de `SOLANA_GAS_TANK_TARGET_USD`).
  - [ ] Mettre en place une alerte si le solde du gas tank tombe sous le target (le détecteur log un warning mais ne s'auto-renfloue pas).
- [ ] Si vous activez le sweep BTC/LTC :
  - [ ] Récupérer l'xpriv correspondant à l'xpub déjà en config (même seed, même path BIP84).
  - [ ] Générer/choisir l'adresse cold (P2WPKH bech32 — `bc1q...` / `ltc1q...`).
  - [ ] Vérifier que `EXPLORER_API_URLS` n'a pas été restreint à Blockchair seul (sinon le sweep ne marchera pas).
  - [ ] Tester sur un faible montant en premier (envoyer 1000 sats, vérifier que le sweep s'exécute après les confirmations attendues).
- [ ] Vérifier côté receveur de webhook que les nouveaux champs (`asset`, `token_contract`, `swept_*`) sont gérés (au pire, ignorés).
- [ ] Redémarrer le détecteur, surveiller les logs au démarrage : il affiche maintenant
  - `Sweep enabled - destination: ... (fee_rate ... sat/vB, min_sweep ... sat)` pour BTC/LTC,
  - `SPL token count: N` pour Solana.

---

## 6. Rollback

Pour désactiver une fonctionnalité sans toucher au code :

- **Désactiver USDC/SPL** : retirer ou commenter `SOLANA_SPL_TOKENS` (ou `SOLANA_SPL_TOKENS=none`). Les dépôts SOL natifs continuent de fonctionner. Si vous retirez aussi `SOLANA_GAS_TANK_PRIVATE_KEY`, le SOL natif sweep retourne directement vers `SOLANA_DEPOSIT_ADDRESS` (comportement initial, sans gas tank).
- **Désactiver le sweep BTC/LTC** : retirer `BTC_XPRIV` ou `BTC_SWEEP_DESTINATION` (l'un ou l'autre suffit). Le détecteur repasse en lecture seule, les fonds restent sur les adresses dérivées.

Aucun rollback de schéma n'est nécessaire : les fichiers d'état (`btc_detector_state.json`, `eth_detector_state.local.json`, etc.) sont rétro-compatibles.
