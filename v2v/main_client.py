import socket
import json
import time
from person import Person
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

def serialize_certificate(cert):
    pem_data = cert.public_bytes(encoding=serialization.Encoding.PEM)
    hex_data = pem_data.hex()
    return hex_data

def deserialize_certificate(hex_data):
    pem_data = bytes.fromhex(hex_data)
    cert = x509.load_pem_x509_certificate(pem_data, default_backend())
    return cert

def serialize_ec_public_key(public_key):
    pem_data = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    hex_data = pem_data.hex()
    return hex_data

def deserialize_ec_public_key(hex_data):
    pem_data = bytes.fromhex(hex_data)
    public_key = serialization.load_pem_public_key(pem_data, default_backend())
    return public_key

def send_message(conn, message):
    conn.sendall(json.dumps(message).encode('utf-8'))

def receive_message(conn):
    data = conn.recv(4096).decode('utf-8')
    print("Received data:", data)
    return json.loads(data)

def main():
    report = []
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        start_time = time.time()
        conn.connect(('localhost', 8085))
        report.append(f"Connection established: {time.time() - start_time} seconds")
        
        node2 = Person("Node 2")

        # Receive Node 1's certificate
        start_time = time.time()
        response = receive_message(conn)
        report.append(f"Received Node 1's certificate: {time.time() - start_time} seconds")

        start_time = time.time()
        node1_cert_hex = response['certificate']
        node1_cert = deserialize_certificate(node1_cert_hex)
        report.append(f"Deserialized Node 1's certificate: {time.time() - start_time} seconds")

        # Verify Node 1's certificate
        start_time = time.time()
        node2.ca_ku.verify(
            node1_cert.signature,
            node1_cert.tbs_certificate_bytes,
            ec.ECDSA(hashes.SHA256())
        )
        report.append(f"Verified Node 1's certificate: {time.time() - start_time} seconds")

        # Send Node 2's certificate
        start_time = time.time()
        node2_cert_hex = serialize_certificate(node2.get_certificate())
        send_message(conn, {'certificate': node2_cert_hex})
        report.append(f"Sent Node 2's certificate: {time.time() - start_time} seconds")

        # Proceed with DH key exchange
        start_time = time.time()
        node2_dh_public_key, node2_dh_signature = node2.generate_dh_public_key()
        report.append(f"Generated DH public key: {time.time() - start_time} seconds")

        # Receive Node 1's DH public key and signature
        start_time = time.time()
        response = receive_message(conn)
        node1_dh_public_key = serialization.load_pem_public_key(
            response['dh_public_key'].encode(),
            default_backend()
        )
        node1_dh_signature = bytes.fromhex(response['dh_signature'])
        report.append(f"Received and deserialized Node 1's DH public key and signature: {time.time() - start_time} seconds")

        # Set Node 1's DH public key as peer public key
        start_time = time.time()
        node2.set_dh_peer_public_key(
            dh_peer_public_key=node1_dh_public_key,
            signature=node1_dh_signature,
            peer_cert=node1_cert
        )
        report.append(f"Set DH peer public key: {time.time() - start_time} seconds")

        # Calculate symmetric key
        start_time = time.time()
        node2.calculate_symmetric_key()
        report.append(f"Calculated symmetric key: {time.time() - start_time} seconds")

        # Send Node 2's DH public key and signature to Node 1
        start_time = time.time()
        message = {
            'dh_public_key': node2_dh_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode(),
            'dh_signature': node2_dh_signature.hex()
        }
        send_message(conn, message)
        report.append(f"Sent DH public key and signature: {time.time() - start_time} seconds")

        # Receive encrypted message
        start_time = time.time()
        encrypted_packet = receive_message(conn)
        encrypted_msg = bytes.fromhex(encrypted_packet['encrypted_msg'])
        iv = bytes.fromhex(encrypted_packet['iv'])
        tag = bytes.fromhex(encrypted_packet['tag'])
        report.append(f"Received encrypted message: {time.time() - start_time} seconds")

        # Decrypt the message
        start_time = time.time()
        decrypted_msg = node2.decrypt(encrypted_msg, iv, tag, node1_cert)
        report.append(f"Decrypted message: {time.time() - start_time} seconds")
        print("Decrypted message:", decrypted_msg.decode("utf-8"))

        # Send acknowledgment to Node 1
        start_time = time.time()
        message = b"Acknowledgment from Node 2!"
        signature, node2_ku = node2.sign_ack(message)
        ack_data = {
            'message': message.decode(),
            'signature': signature.hex(),
            'ku': serialize_ec_public_key(node2_ku)
        }
        send_message(conn, ack_data)
        report.append(f"Sent acknowledgment: {time.time() - start_time} seconds")

    # Write report to file
    with open('client_timing_report.txt', 'w') as f:
        for line in report:
            f.write(line + '\n')

if __name__ == "__main__":
    main()
