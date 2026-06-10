# pki.py
# La PKI = autorite de certification. Entite SEPAREE (ni vendeur ni client).
# Role : signer les certificats des autres. Tourne en permanence.
# Lancer : python3 pki.py

import json
import os
import datetime
import paho.mqtt.client as mqtt

import crypto

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

DOSSIER = "pki_fichiers"

cle_ca = None      # cle privee de la PKI
cert_ca = None     # certificat de la PKI (auto-signe)


def init_ca():
    # au demarrage : on recharge la CA si elle existe, sinon on la cree
    global cle_ca, cert_ca

    if not os.path.exists(DOSSIER):
        os.makedirs(DOSSIER)

    f_cle = DOSSIER + "/ca_cle.pem"
    f_cert = DOSSIER + "/ca_cert.pem"

    if os.path.exists(f_cle):
        cle_ca = crypto.charger_cle_privee(f_cle)
        cert_ca = crypto.charger_certificat(open(f_cert).read())
        print("[PKI] CA rechargee")
        return

    print("[PKI] Creation de la CA...")
    cle_ca = crypto.generer_cles_rsa()

    # certificat AUTO-SIGNE : subject == issuer (c'est la racine de confiance)
    nom = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PKI-RT0802")])
    cert_ca = (x509.CertificateBuilder()
        .subject_name(nom)
        .issuer_name(nom)                       # <- auto-signe
        .public_key(cle_ca.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
        .sign(cle_ca, hashes.SHA256()))

    crypto.sauver_cle_privee(cle_ca, f_cle)
    open(f_cert, "w").write(crypto.certificat_vers_texte(cert_ca))
    print("[PKI] CA creee (certificat auto-signe)")


def signer_csr(texte_csr):
    # on recoit un CSR, on cree le certificat et on le signe avec la cle de la PKI
    csr = x509.load_pem_x509_csr(texte_csr.encode())
    cert = (x509.CertificateBuilder()
        .subject_name(csr.subject)              # le nom demande
        .issuer_name(cert_ca.subject)           # signe par la PKI
        .public_key(csr.public_key())           # la cle publique du demandeur
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .sign(cle_ca, hashes.SHA256()))         # <- signature avec la cle privee PKI
    return crypto.certificat_vers_texte(cert)


# ===== MQTT =====

def on_connect(client, userdata, flags, rc, props=None):
    print("[PKI] Connecte au broker MQTT")
    client.subscribe("pki/demande")             # on ecoute les demandes de cert
    print("[PKI] En attente de demandes...")


def on_message(client, userdata, msg):
    # message recu : { "nom": "...", "csr": "..." }
    d = json.loads(msg.payload.decode())
    nom = d["nom"]
    print("[PKI] Demande recue de :", nom)

    cert_signe = signer_csr(d["csr"])           # on signe

    # on renvoie le cert signe + le cert de la PKI (pour verifier les autres)
    reponse = {"cert": cert_signe,
               "cert_ca": crypto.certificat_vers_texte(cert_ca)}
    client.publish("pki/reponse/" + nom, json.dumps(reponse))
    print("[PKI] Certificat envoye a", nom)


def main():
    print("=== PKI (autorite de certification) ===")
    init_ca()

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="pki")
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect("localhost", 1883)
    client.loop_forever()                       # boucle infinie : la PKI tourne tout le temps


if __name__ == "__main__":
    main()
