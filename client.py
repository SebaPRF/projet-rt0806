# client.py
# L'acheteur. Demande son certificat a la PKI, puis commande via un menu.
# Lancer : python3 client.py alice   (ou bob, etc.)

import json
import time
import sys
import paho.mqtt.client as mqtt

import crypto

# nom du client passe en argument (alice par defaut)
NOM = sys.argv[1] if len(sys.argv) > 1 else "alice"

cle_privee = None      # ma cle privee RSA
cert = None            # mon certificat (signe par la PKI)
cert_ca = None         # certificat de la PKI
catalogue = None

cle_aes = None         # cle AES (apres diffie-hellman)
cle_dh = None          # ma cle privee DH

mqtt_client = None


def demander_certificat(client):
    # on genere nos cles et on demande un certificat a la PKI
    global cle_privee
    cle_privee = crypto.generer_cles_rsa()
    csr = crypto.creer_csr(cle_privee, NOM)
    client.subscribe("pki/reponse/" + NOM)
    client.publish("pki/demande", json.dumps({"nom": NOM, "csr": csr}))
    print("[" + NOM + "] Demande de certificat envoyee a la PKI")


# ===== SCENARIO 1 : commande authentifiee =====

def commander_s1(id_produit, quantite):
    donnees = {"id_produit": id_produit, "quantite": quantite}
    donnees_bytes = json.dumps(donnees).encode()

    signature = crypto.signer(cle_privee, donnees_bytes)   # SHA1 + RSA
    print("[" + NOM + "] hash SHA1 :", crypto.hash_sha1(donnees_bytes))

    # on envoie : donnees + signature + certificat
    mqtt_client.publish("boutique/commande/s1/" + NOM, json.dumps({
        "donnees": donnees,
        "signature": signature,
        "cert": crypto.certificat_vers_texte(cert)
    }))
    print("[" + NOM + "] Commande envoyee (S1)")


# ===== Diffie-Hellman (avant le scenario 2) =====

def lancer_dh():
    mqtt_client.publish("boutique/dh/" + NOM, json.dumps({"etape": "debut"}))
    print("[" + NOM + "] Echange Diffie-Hellman lance")


# ===== SCENARIO 2 : commande chiffree =====

def commander_s2(id_produit, quantite):
    if cle_aes is None:
        print("[" + NOM + "] Faire diffie-hellman d'abord (option 3)")
        return

    donnees = {"id_produit": id_produit, "quantite": quantite}
    donnees_bytes = json.dumps(donnees).encode()

    signature = crypto.signer(cle_privee, donnees_bytes)   # on signe les donnees en clair
    chiffre = crypto.chiffrer_aes(cle_aes, donnees_bytes)  # puis on chiffre

    # on envoie : commande chiffree + signature + certificat
    mqtt_client.publish("boutique/commande/s2/" + NOM, json.dumps({
        "chiffre": chiffre,
        "signature": signature,
        "cert": crypto.certificat_vers_texte(cert)
    }))
    print("[" + NOM + "] Commande chiffree envoyee (S2)")


# ===== MQTT =====

def on_connect(client, userdata, flags, rc, props=None):
    print("[" + NOM + "] Connecte au broker MQTT")
    client.subscribe("pki/reponse/" + NOM)
    client.subscribe("boutique/catalogue/reponse/" + NOM)
    client.subscribe("boutique/reponse/" + NOM)
    client.subscribe("boutique/dh/reponse/" + NOM)


def on_message(client, userdata, msg):
    global cert, cert_ca, catalogue, cle_aes, cle_dh
    topic = msg.topic
    data = json.loads(msg.payload.decode())

    # certificat recu de la PKI
    if topic == "pki/reponse/" + NOM:
        cert = crypto.charger_certificat(data["cert"])
        cert_ca = crypto.charger_certificat(data["cert_ca"])
        print("[" + NOM + "] Certificat recu de la PKI")
        return

    # catalogue recu
    if topic == "boutique/catalogue/reponse/" + NOM:
        catalogue = data["produits"]
        afficher_catalogue()
        return

    # reponse a une commande
    if topic == "boutique/reponse/" + NOM:
        if data["ok"]:
            print("\n>>> COMMANDE OK :", data["quantite"], "x", data["produit"],
                  "=", data["total"], "euros (stock restant:", data["stock_restant"], ")\n")
        else:
            print("\n>>> COMMANDE REFUSEE :", data["message"], "\n")
        return

    # reponse diffie-hellman
    if topic == "boutique/dh/reponse/" + NOM:
        if data["etape"] == "params":
            # le vendeur envoie p,g + sa cle publique DH
            params = crypto.charger_parametres(data["params"])
            cle_dh = params.generate_private_key()
            cle_pub_vendeur = crypto.charger_cle_publique_dh(data["cle_pub"])
            cle_aes = crypto.secret_vers_cle_aes(cle_dh, cle_pub_vendeur)   # cle commune
            print("[" + NOM + "] cle AES :", cle_aes.hex())
            # on renvoie notre cle publique DH
            client.publish("boutique/dh/" + NOM, json.dumps({
                "etape": "cle_client",
                "cle_pub": crypto.cle_publique_dh_vers_texte(cle_dh)
            }))
        elif data["etape"] == "ok":
            print("[" + NOM + "] Diffie-Hellman termine, on peut commander en S2")
        return


def afficher_catalogue():
    print("\n----- CATALOGUE -----")
    for p in catalogue:
        print("  ", p["id"], "-", p["nom"], ":", p["prix"], "euros (stock", p["stock"], ")")
    print("---------------------\n")


# ===== Menu =====

def menu():
    time.sleep(2)   # on attend de recevoir le certificat
    while True:
        print("\n=== Menu (" + NOM + ") ===")
        print("1 - Voir le catalogue")
        print("2 - Commander (scenario 1)")
        print("3 - Diffie-Hellman (avant S2)")
        print("4 - Commander (scenario 2)")
        print("0 - Quitter")
        choix = input("Choix : ").strip()

        if choix == "1":
            mqtt_client.publish("boutique/catalogue/demande/" + NOM, "{}")
            time.sleep(1)
        elif choix == "2":
            id_p = int(input("  id produit : "))
            qte = int(input("  quantite : "))
            commander_s1(id_p, qte)
            time.sleep(1)
        elif choix == "3":
            lancer_dh()
            time.sleep(2)
        elif choix == "4":
            id_p = int(input("  id produit : "))
            qte = int(input("  quantite : "))
            commander_s2(id_p, qte)
            time.sleep(1)
        elif choix == "0":
            break


def main():
    global mqtt_client
    print("=== CLIENT :", NOM, "===")

    mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="client_" + NOM)
    mqtt_client.on_connect = on_connect
    mqtt_client.on_message = on_message
    mqtt_client.connect("localhost", 1883)
    mqtt_client.loop_start()

    time.sleep(1)
    demander_certificat(mqtt_client)

    menu()


if __name__ == "__main__":
    main()
