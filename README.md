# Projet RT0806 — Boutique sécurisée MQTT

Simulation d'une boutique en ligne dont les échanges sont sécurisés, **codés à la main** (sans utiliser le TLS automatique des bibliothèques).

Projet réalisé par **Sébastien Porfiri** et **Elie Coutelle** — Master 1 Réseaux & Télécommunications.

## Principe

Une boutique avec un vendeur (serveur) et des clients (acheteurs) qui communiquent via MQTT (broker Mosquitto). Toute la sécurité est implémentée manuellement : certificats X.509, signatures RSA, chiffrement AES et échange de clé Diffie-Hellman.

## Architecture : 3 entités séparées

| Fichier | Rôle |
|---|---|
| `pki.py` | Autorité de certification (PKI). Entité **séparée** qui signe les certificats des autres. Tourne en permanence. |
| `vendeur.py` | Serveur de la boutique (catalogue de 10 produits). Demande son certificat à la PKI, traite les commandes. |
| `client.py` | Acheteur. Demande son certificat, consulte le catalogue, passe des commandes. |
| `crypto.py` | Boîte à outils : toutes les fonctions de crypto (RSA, X.509, SHA-1, AES, Diffie-Hellman). Utilisée par les 3 autres. |
| `catalogue.json` | Les 10 produits de la boutique. |

## Les deux scénarios

- **Scénario 1 — Authentification** : le client signe sa commande (SHA-1 + RSA) et joint son certificat. Le vendeur vérifie l'identité, mais les données circulent en clair.
- **Scénario 2 — Confidentialité** : en plus de l'authentification, la commande est chiffrée en AES-128. La clé AES est établie au préalable par un échange Diffie-Hellman.

## Installation

```bash
pip3 install paho-mqtt cryptography
```

Il faut aussi le broker Mosquitto :

```bash
# Mac
brew install mosquitto

# Linux
sudo apt install mosquitto
```

## Lancement

Ouvrir 3 terminaux, dans l'ordre suivant (la PKI doit démarrer en premier) :

```bash
# Terminal 1 — broker + PKI
mosquitto -d
python3 pki.py

# Terminal 2 — vendeur
python3 vendeur.py

# Terminal 3 — client
python3 client.py alice
```

Pour un deuxième acheteur : `python3 client.py bob`

## Utilisation (menu du client)

1. Voir le catalogue
2. Commander en scénario 1 (authentifié)
3. Faire l'échange Diffie-Hellman (avant le scénario 2)
4. Commander en scénario 2 (chiffré)
0. Quitter
