import socket
import json
import time
from datetime import datetime
import struct
import psutil

from cryptography import x509
from person import Person
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature
from certificates import create_certificates, create_pub_priv_key_pair

import board
import busio
import adafruit_mpu6050

# Global variables for memory tracking
prev_memory = None
max_memory = 0

def log_memory_usage(step, log_file):
    global prev_memory, max_memory

    process = psutil.Process()
    memory_info = process.memory_info()

    current_rss = memory_info.rss
    current_vms = memory_info.vms

    if prev_memory is not None:
        rss_diff = current_rss - prev_memory['rss']
        vms_diff = current_vms - prev_memory['vms']
    else:
        rss_diff = 0
        vms_diff = 0

    prev_memory = {'rss': current_rss, 'vms': current_vms}

    if current_rss > max_memory:
        max_memory = current_rss

    with open(log_file, 'a') as f:
        f.write(f"{step}: RSS={current_rss}, VMS={current_vms}, RSS Diff={rss_diff}, VMS Diff={vms_diff}\n")

def serialize_certificate(cert):
    pem_data = cert.public_bytes(encoding=serialization.Encoding.PEM)
    hex_data = pem_data.hex()
    return hex_data

def deserialize_certificate(hex_data):
    pem_data = bytes.fromhex(hex_data)
    cert = x509.load_pem_x509_certificate(pem_data, default_backend())
    return cert

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

def get_mpu6050_data():
    i2c = busio.I2C(board.SCL, board.SDA)
    mpu = adafruit_mpu6050.MPU6050(i2c)
    accel = mpu.acceleration
    gyro = mpu.gyro
    mpu_data = struct.pack('ffffff', accel[0], accel[1], accel[2], gyro[0], gyro[1], gyro[2])
    return mpu_data

def append_time_info(data):
    now = datetime.now()
    minutes = now.minute
    hours = now.hour
    time_info = struct.pack('>HH', hours, minutes)
    return data + time_info

def main():
    global max_memory
    report = []
    memory_log_file = 'memory_log.txt'
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 8085))
    server_socket.listen()

    log_memory_usage('Initialization', memory_log_file)

    print("Node 1 is listening for incoming connections...")

    conn, addr = server_socket.accept()

    with conn:
        print(f"Connected to Node 2 at {addr}")

        try:
            node1 = Person('Node 1')
            log_memory_usage('After initializing Person', memory_log_file)

            #======================================================================================
            # Send Node 1's certificate
            start_time = time.time()
            node1_cert_hex = serialize_certificate(node1.get_certificate())
            send_message(conn, {'certificate': node1_cert_hex})
            report.append(f"Sent Node 1's certificate: {time.time() - start_time} seconds")
            log_memory_usage('After sending Node 1 certificate', memory_log_file)

            # Receive Node 2's certificate
            start_time = time.time()
            response = receive_message(conn)
            report.append(f"Received Node 2's certificate: {time.time() - start_time} seconds")
            log_memory_usage('After receiving Node 2 certificate', memory_log_file)

            start_time = time.time()
            node2_cert_hex = response['certificate']
            node2_cert = deserialize_certificate(node2_cert_hex)
            report.append(f"Deserialized Node 2's certificate: {time.time() - start_time} seconds")
            log_memory_usage('After deserializing Node 2 certificate', memory_log_file)

            # Verify Node 2's certificate
            start_time = time.time()
            node1.ca_ku.verify(
                node2_cert.signature,
                node2_cert.tbs_certificate_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            report.append(f"Verified Node 2's certificate: {time.time() - start_time} seconds")
            log_memory_usage('After verifying Node 2 certificate', memory_log_file)

            # Continue with DH key exchange
            start_time = time.time()
            node1_dh_public_key, node1_dh_signature = node1.generate_dh_public_key()
            message = {
                'dh_public_key': node1_dh_public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode(),
                'dh_signature': node1_dh_signature.hex()
            }
            send_message(conn, message)
            report.append(f"Generated and sent DH public key: {time.time() - start_time} seconds")
            log_memory_usage('After sending DH public key', memory_log_file)

            # Receive Node 2's DH public key and signature
            start_time = time.time()
            response = receive_message(conn)
            node2_dh_public_key = serialization.load_pem_public_key(
                response['dh_public_key'].encode(),
                default_backend()
            )
            node2_dh_signature = bytes.fromhex(response['dh_signature'])
            report.append(f"Received and deserialized Node 2's DH public key and signature: {time.time() - start_time} seconds")
            log_memory_usage('After receiving Node 2 DH public key and signature', memory_log_file)

            start_time = time.time()
            node1.set_dh_peer_public_key(
                dh_peer_public_key=node2_dh_public_key,
                signature=node2_dh_signature,
                peer_cert=node2_cert
            )
            report.append(f"Set DH peer public key: {time.time() - start_time} seconds")
            log_memory_usage('After setting DH peer public key', memory_log_file)

            start_time = time.time()
            node1.calculate_symmetric_key()
            report.append(f"Calculated symmetric key: {time.time() - start_time} seconds")
            log_memory_usage('After calculating symmetric key', memory_log_file)

            start_time = time.time()
            mpu_data = get_mpu6050_data()
            message = append_time_info(mpu_data)
            encrypted_msg, iv, tag = node1.encrypt(message)
            encrypted_packet = {
                'encrypted_msg': encrypted_msg.hex(),
                'iv': iv.hex(),
                'tag': tag.hex()
            }
            send_message(conn, encrypted_packet)
            report.append(f"Encrypted and sent message: {time.time() - start_time} seconds")
            log_memory_usage('After encrypting and sending message', memory_log_file)

            start_time = time.time()
            ack = receive_message(conn)
            if ack:
                msg = ack['message']
                signature = ack['signature']
                node2_ku_hex = ack['ku']
                node2_ku = deserialize_ec_public_key(node2_ku_hex)
                try:
                    print("Verifying acknowledgment signature...")
                    node1.verify_ack_signature(msg.encode('utf-8'), bytes.fromhex(signature), node2_ku)
                    print("Acknowledgment signature verified successfully.")
                    report.append(f"Verified acknowledgment signature: {time.time() - start_time} seconds")
                    log_memory_usage('After verifying acknowledgment signature', memory_log_file)
                except Exception as e:
                    print("Error verifying acknowledgment signature:", e)
                    report.append(f"Error verifying acknowledgment signature: {time.time() - start_time} seconds")
                    log_memory_usage('Error verifying acknowledgment signature', memory_log_file)

        except Exception as e:
            print(f"An error occurred: {e}")
            log_memory_usage('Error occurred', memory_log_file)
        finally:
            server_socket.close()
            log_memory_usage('Server socket closed', memory_log_file)

    # Write report to file
    with open('server_timing_report.txt', 'w') as f:
        for line in report:
            f.write(line + '\n')

    # Append max memory usage to report
    with open('server_timing_report.txt', 'a') as f:
        f.write(f"Max Memory Usage: {max_memory} bytes\n")

if __name__ == "__main__":
    main()
