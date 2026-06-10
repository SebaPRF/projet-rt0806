# crypto.py
# Toutes les fonctions de crypto regroupees ici (utilisees par pki, vendeur, client)

import os
import base64
import hashlib
import datetime

from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import x509
from cryptography.x509.oid import NameOID


# ===== RSA =====

def generer_cles_rsa():
    # genere la paire de cles RSA (2048 bits)
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def sauver_cle_privee(cle, chemin):
    pem = cle.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    )
    open(chemin, "wb").write(pem)


def charger_cle_privee(chemin):
    return serialization.load_pem_private_key(open(chemin, "rb").read(), password=None)


# ===== CSR (demande de certificat envoyee a la PKI) =====

def creer_csr(cle, nom):
    # le CSR contient mon nom + ma cle publique, signe avec ma cle privee
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, nom)])
    ).sign(cle, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.PEM).decode()


# ===== Certificats X509 =====

def charger_certificat(pem):
    return x509.load_pem_x509_certificate(pem.encode())


def certificat_vers_texte(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def verifier_certificat(cert, cert_ca):
    # verifie que le cert a bien ete signe par la PKI (avec la cle publique de la PKI)
    cert_ca.public_key().verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm,
    )
    return True


# ===== Signature des donnees : SHA1 + RSA =====

def signer(cle, donnees):
    # hash SHA1 puis signature avec la cle privee
    sig = cle.sign(donnees, padding.PKCS1v15(), hashes.SHA1())
    return base64.b64encode(sig).decode()   # base64 pour le mettre dans du json


def verifier_signature(cle_pub, donnees, sig_b64):
    sig = base64.b64decode(sig_b64)
    try:
        cle_pub.verify(sig, donnees, padding.PKCS1v15(), hashes.SHA1())
        return True
    except Exception:
        return False


def hash_sha1(donnees):
    # juste pour afficher l'empreinte
    return hashlib.sha1(donnees).hexdigest()


# ===== AES-128 (mode CBC) =====

def chiffrer_aes(cle, donnees):
    iv = os.urandom(16)                       # IV aleatoire (16 octets)
    reste = 16 - (len(donnees) % 16)          # padding : completer a un multiple de 16
    donnees = donnees + bytes([reste] * reste)
    c = Cipher(algorithms.AES(cle), modes.CBC(iv)).encryptor()
    chiffre = c.update(donnees) + c.finalize()
    return {"iv": base64.b64encode(iv).decode(),
            "data": base64.b64encode(chiffre).decode()}


def dechiffrer_aes(cle, iv_b64, data_b64):
    iv = base64.b64decode(iv_b64)
    chiffre = base64.b64decode(data_b64)
    d = Cipher(algorithms.AES(cle), modes.CBC(iv)).decryptor()
    donnees = d.update(chiffre) + d.finalize()
    reste = donnees[-1]                       # on enleve le padding
    return donnees[:-reste]


# ===== Diffie-Hellman (pour echanger la cle AES sans l'envoyer) =====

def generer_parametres_dh():
    # p et g (publics)
    return dh.generate_parameters(generator=2, key_size=1024)


def parametres_vers_texte(params):
    return params.parameter_bytes(serialization.Encoding.PEM,
                                  serialization.ParameterFormat.PKCS3).decode()


def charger_parametres(texte):
    return serialization.load_pem_parameters(texte.encode())


def cle_publique_dh_vers_texte(cle_dh):
    return cle_dh.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def charger_cle_publique_dh(texte):
    return serialization.load_pem_public_key(texte.encode())


def secret_vers_cle_aes(ma_cle_dh, cle_pub_autre):
    # on calcule le secret commun, puis SHA256 -> on garde 16 octets pour AES-128
    secret = ma_cle_dh.exchange(cle_pub_autre)
    return hashlib.sha256(secret).digest()[:16]
