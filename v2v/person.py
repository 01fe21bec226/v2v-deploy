from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class Person:
    def __init__(self, name):
        self.name = name
        self.seq = 0

        # Load certificate
        with open(f'certificates/{self.name}_CERT.pem', 'rb') as cert_file:
            pem_data = cert_file.read()
            self.cert = x509.load_pem_x509_certificate(pem_data, default_backend())
            self.ku = self.cert.public_key()

        # Load private key
        with open(f'certificates/{self.name}_KR.pem', 'rb') as private_key_file:
            pem_data = private_key_file.read()
            self.kr = serialization.load_pem_private_key(
                pem_data,
                password=None,
                backend=default_backend()
            )

        # Load CA's public key
        with open('certificates/CA_KU.pem', 'rb') as ca_public_key_file:
            pem_data = ca_public_key_file.read()
            self.ca_ku = serialization.load_pem_public_key(
                pem_data,
                backend=default_backend()
            )

        print(f'{name} initialized')

    def generate_dh_public_key(self):
        print('Generating DH public/private key pair')
        self.dh_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.dh_public_key = self.dh_private_key.public_key()
        print(self.dh_public_key)

        print('Signing DH public key with private key')
        signature = self.kr.sign(
            self.dh_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ),
            ec.ECDSA(hashes.SHA256())  # Specify the hash algorithm here
        )

        return self.dh_public_key, signature

    def set_dh_peer_public_key(self, dh_peer_public_key, signature, peer_cert):
        print('Received DH public key from peer')
        self.dh_peer_public_key = dh_peer_public_key

        print('Verifying peer certificate')
        self.ca_ku.verify(
            peer_cert.signature,
            peer_cert.tbs_certificate_bytes,
            ec.ECDSA(hashes.SHA256())  # Specify the hash algorithm here
        )

        print('Verifying peer public key signature')
        peer_cert.public_key().verify(
            signature,
            dh_peer_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ),
            ec.ECDSA(hashes.SHA256())  # Specify the hash algorithm here
        )

    def calculate_symmetric_key(self):
        print('Calculating symmetric key')
        secret_symmetric_key = self.dh_private_key.exchange(ec.ECDH(), self.dh_peer_public_key)
        self.aes_key = secret_symmetric_key[:16]  # Use first 16 bytes as AES key
        print(f'{self.name}: Symmetric key generated')
        print(self.aes_key)

    def get_certificate(self):
        return self.cert

    def encrypt(self, message):
        print('Encrypting message...')
        iv = ec.generate_private_key(ec.SECP256R1(), default_backend()).exchange(ec.ECDH(), self.dh_peer_public_key)
        cipher = Cipher(
            algorithms.AES(self.aes_key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ct = encryptor.update(message) + encryptor.finalize()
        print('Encryption complete')
        print(ct)
        return ct, iv, encryptor.tag

    def decrypt(self, ct, iv, tag, peer_cert):
        print('Decrypting message...')
        cipher = Cipher(
            algorithms.AES(self.aes_key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ct) + decryptor.finalize()

        print('Verifying peer certificate for decryption')
        self.ca_ku.verify(
            peer_cert.signature,
            peer_cert.tbs_certificate_bytes,
            ec.ECDSA(hashes.SHA256())
        )

        return decrypted

    def sign_ack(self, message):
        print('Signing acknowledgment...')
        return self.kr.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        ), self.ku

    def verify_ack_signature(self, message, signature, peer_ku):
        print('Verifying acknowledgment signature...')
        peer_ku.verify(
            signature,
            message,
            ec.ECDSA(hashes.SHA256())
        )
        print(f'{self.name} received an acknowledgment from the peer.')
