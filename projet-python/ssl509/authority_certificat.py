from OpenSSL.crypto import verify
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import pika
from os import path
import datetime


cert = None
key = None

def certif_request(CSR_PATH):
    if(path.exists(CSR_PATH) and path.isfile(CSR_PATH)):
        # loading certification request
        print('Handling request')
        csr = x509.load_pem_x509_csr(
            open(CSR_PATH, 'rb').read(), default_backend())
        cert_client = x509.CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            cert.subject
        ).public_key(
            csr.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=14)
        )
        for ext in csr.extensions:
            cert_client.add_extension(ext.value, ext.critical)

        cert_client = cert_client.sign(key, hashes.SHA256(), default_backend())
        with open('client_cert.pem', 'wb') as f:
            f.write(cert_client.public_bytes(serialization.Encoding.PEM))
    else:
        print('No Request to handle')


def certif_request2(reqData, cert):
    csr = x509.load_pem_x509_csr(reqData, default_backend())
    cert_client = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        cert.subject
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=14)
    )
    for ext in csr.extensions:
        cert_client.add_extension(ext.value, ext.critical)

    cert_client = cert_client.sign(key, hashes.SHA256(), default_backend())
    return cert_client.public_bytes(serialization.Encoding.PEM).decode()


def handle_cert(data):
    if data:
        cert = x509.load_pem_x509_certificate(data, default_backend())
        return cert
    else:
        print('There is no certification')
        return None

def generate_import_certif():
    global cert
    global key
    if(path.isfile('certificate_ca.pem') and path.exists('certificate_ca.pem') and path.isfile('key_ca.pem') and path.exists('key_ca.pem')):
        # load files
        print('Loading !')
        cert = x509.load_pem_x509_certificate(open('certificate_ca.pem', 'rb').read(), default_backend())
        key = serialization.load_pem_private_key(
            open('key_ca.pem', 'rb').read(), password=None, backend=default_backend())
    else:
        print('Generating !')
        # generate key and self signed cert
        key = rsa.generate_private_key(public_exponent=65537,key_size=3072,backend=default_backend())   
        # Save it to disk
        with open('key_ca.pem', "wb") as f:
            f.write(key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=serialization.NoEncryption()))
            # Making a self signed certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"TN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Tunis"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Tek-up"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"tekup"),
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=3650)
        ).sign(key, hashes.SHA256(), default_backend())
        with open('certificate_ca.pem', "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
    return (key, cert)


class Certif_Autho_Server:

    def connect_to_rabbitmq(self):
        self.generate_autho_key()
        self.connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost'))
        self.channel = self.connection.channel()
        self.receive_from_client()
    
    def generate_autho_key(self):
        self.ca_key, self.ca_cert = generate_import_certif()
        self.ca_pubkey = self.ca_key.public_key()
    
    def receive_from_client(self):
        self.channel.queue_declare(queue='request_certif_queue', durable=True)

        def callback(ch, method, properties, body):
            client_queue, demand, data = body.decode().split('*')
            if (demand == 'request'):

                print('Server get cert request from client')
                data = data.encode()
                certdata = certif_request2(data, self.ca_cert)
                self.send_to_client(client_queue, 'certif', certdata)
            if(demand == 'verify'):
                print('Server get verifying from client')
                certif = handle_cert(data.encode())
                result = ""
                try:
                    result = self.ca_pubkey.verify(certif.signature,certif.tbs_certificate_bytes,padding.PKCS1v15(),certif.signature_hash_algorithm,)
                    result = "existe"
                except Exception:
                    result = "does not exist"
                finally:
                    self.send_to_client(client_queue, 'verify', result)

            ch.basic_ack(delivery_tag=method.delivery_tag)

        self.channel.basic_consume(queue='request_certif_queue', on_message_callback=callback)
        print('Server Listening')
        self.channel.start_consuming()

    def send_to_client(self, client_queue, demand, data):

        self.channel.exchange_declare(exchange='certificate_exchange', exchange_type='direct')
        self.channel.queue_declare(queue=client_queue, durable=True)

        message = demand+'*'+data
        self.channel.basic_publish(exchange='certificate_exchange',routing_key=client_queue,body=message)
        print('Server sended cert to client')

    


server_certif = Certif_Autho_Server()
server_certif.connect_to_rabbitmq()
