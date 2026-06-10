# vendeur.py
# Le serveur de la boutique (catalogue 10 produits).
# Demande son certificat a la PKI, puis traite les commandes.
# Scenario 1 = authentifie / Scenario 2 = authentifie + chiffre AES.
# Lancer : python3 vendeur.py

import json
import time
import paho.mqtt.client as mqtt

import crypto

NOM = "vendeur"

cle_privee = None      # ma cle privee RSA
cert = None            # mon certificat (signe par la PKI)
cert_ca = None         # certificat de la PKI (pour verifier les clients)
catalogue = []

cles_aes = {}          # une cle AES par client : { "alice": b"..." }
params_dh = None       # parametres DH (p,g)
cle_dh = None          # ma cle privee DH

mqtt_client = None


def charger_catalogue():
    global catalogue
    catalogue = json.load(open("catalogue.json"))["produits"]
    print("[VENDEUR] Catalogue :", len(catalogue), "produits")


def demander_certificat(client):
    # on genere nos cles et on demande un certificat a la PKI
    global cle_privee
    cle_privee = crypto.generer_cles_rsa()
    csr = crypto.creer_csr(cle_privee, NOM)
    client.subscribe("pki/reponse/" + NOM)
    client.publish("pki/demande", json.dumps({"nom": NOM, "csr": csr}))
    print("[VENDEUR] Demande de certificat envoyee a la PKI")


# ===== SCENARIO 1 : authentification =====

def traiter_scenario1(client, nom_client, msg):
    try:
        donnees = msg["donnees"]
        cert_client = crypto.charger_certificat(msg["cert"])

        # 1) le certificat du client vient bien de la PKI ?
        crypto.verifier_certificat(cert_client, cert_ca)
        # 2) la signature des donnees est bonne ?
        donnees_bytes = json.dumps(donnees).encode()
        if not crypto.verifier_signature(cert_client.public_key(), donnees_bytes, msg["signature"]):
            raise Exception("signature invalide")

        print("[VENDEUR] Client", nom_client, "authentifie (S1)")
        traiter_commande(client, nom_client, donnees)
    except Exception as e:
        refuser(client, nom_client, str(e))


# ===== SCENARIO 2 : authentification + chiffrement =====

def traiter_scenario2(client, nom_client, msg):
    try:
        if nom_client not in cles_aes:
            raise Exception("faire diffie-hellman d'abord")
        cle = cles_aes[nom_client]

        # 1) on dechiffre la commande
        donnees_bytes = crypto.dechiffrer_aes(cle, msg["chiffre"]["iv"], msg["chiffre"]["data"])
        donnees = json.loads(donnees_bytes.decode())

        # 2) on verifie le certificat + la signature (comme en S1)
        cert_client = crypto.charger_certificat(msg["cert"])
        crypto.verifier_certificat(cert_client, cert_ca)
        if not crypto.verifier_signature(cert_client.public_key(), donnees_bytes, msg["signature"]):
            raise Exception("signature invalide")

        print("[VENDEUR] Client", nom_client, "authentifie (S2, commande dechiffree)")
        traiter_commande(client, nom_client, donnees)
    except Exception as e:
        refuser(client, nom_client, str(e))


def traiter_commande(client, nom_client, donnees):
    # commun aux 2 scenarios : on verifie le stock et on repond
    id_p = donnees["id_produit"]
    qte = donnees["quantite"]

    produit = None
    for p in catalogue:
        if p["id"] == id_p:
            produit = p
            break

    if produit is None:
        return refuser(client, nom_client, "produit introuvable")
    if produit["stock"] < qte:
        return refuser(client, nom_client, "stock insuffisant")

    produit["stock"] -= qte
    reponse = {"ok": True, "produit": produit["nom"], "quantite": qte,
               "total": produit["prix"] * qte, "stock_restant": produit["stock"]}
    client.publish("boutique/reponse/" + nom_client, json.dumps(reponse))
    print("[VENDEUR] Commande OK :", qte, "x", produit["nom"], "pour", nom_client)


def refuser(client, nom_client, raison):
    client.publish("boutique/reponse/" + nom_client, json.dumps({"ok": False, "message": raison}))
    print("[VENDEUR] Commande refusee :", raison)


# ===== Diffie-Hellman (pour le scenario 2) =====

def traiter_dh(client, nom_client, msg):
    global cle_dh

    if msg["etape"] == "debut":
        # on envoie les parametres (p,g) + notre cle publique DH
        cle_dh = params_dh.generate_private_key()
        client.publish("boutique/dh/reponse/" + nom_client, json.dumps({
            "etape": "params",
            "params": crypto.parametres_vers_texte(params_dh),
            "cle_pub": crypto.cle_publique_dh_vers_texte(cle_dh)
        }))

    elif msg["etape"] == "cle_client":
        # on recoit la cle publique du client -> on calcule la cle AES commune
        cle_pub_client = crypto.charger_cle_publique_dh(msg["cle_pub"])
        cles_aes[nom_client] = crypto.secret_vers_cle_aes(cle_dh, cle_pub_client)
        print("[VENDEUR] Cle AES etablie avec", nom_client)
        client.publish("boutique/dh/reponse/" + nom_client, json.dumps({"etape": "ok"}))


# ===== MQTT =====

def on_connect(client, userdata, flags, rc, props=None):
    print("[VENDEUR] Connecte au broker MQTT")
    client.subscribe("boutique/catalogue/demande/+")
    client.subscribe("boutique/commande/s1/+")
    client.subscribe("boutique/commande/s2/+")
    client.subscribe("boutique/dh/+")


def on_message(client, userdata, msg):
    global cert, cert_ca
    topic = msg.topic
    data = json.loads(msg.payload.decode())

    # certificat recu de la PKI
    if topic == "pki/reponse/" + NOM:
        cert = crypto.charger_certificat(data["cert"])
        cert_ca = crypto.charger_certificat(data["cert_ca"])
        print("[VENDEUR] Certificat recu de la PKI")
        return

    # demande de catalogue
    if topic.startswith("boutique/catalogue/demande/"):
        nom_client = topic.split("/")[-1]
        client.publish("boutique/catalogue/reponse/" + nom_client, json.dumps({"produits": catalogue}))
        return

    # diffie-hellman
    if topic.startswith("boutique/dh/") and "reponse" not in topic:
        traiter_dh(client, topic.split("/")[-1], data)
        return

    # commande scenario 1
    if topic.startswith("boutique/commande/s1/"):
        traiter_scenario1(client, topic.split("/")[-1], data)
        return

    # commande scenario 2
    if topic.startswith("boutique/commande/s2/"):
        traiter_scenario2(client, topic.split("/")[-1], data)
        return


def main():
    global mqtt_client, params_dh

    print("=== VENDEUR (serveur boutique) ===")
    charger_catalogue()

    # parametres DH generes une fois au demarrage
    params_dh = crypto.generer_parametres_dh()

    mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=NOM)
    mqtt_client.on_connect = on_connect
    mqtt_client.on_message = on_message
    mqtt_client.connect("localhost", 1883)
    mqtt_client.loop_start()

    time.sleep(1)
    demander_certificat(mqtt_client)

    print("[VENDEUR] Boutique ouverte")
    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
