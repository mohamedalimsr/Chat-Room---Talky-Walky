from os import path
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import pika


def handle_cert_local(CERT_PATH):
    if(path.exists(CERT_PATH) and path.isfile(CERT_PATH)):
        cert_client = x509.load_pem_x509_certificate(open(CERT_PATH, 'rb').read(), default_backend())
        return cert_client
    else:
        print("no certificate for user")
        return None


def extract_pub(cert):
    if cert:
        certificat = x509.load_pem_x509_certificate(cert.encode(), default_backend())
        print(certificat.issuer, certificat.version, certificat.subject)
        return certificat
    else:
        print('There is no certification')
        return None


class certification_client:
    def __init__(self, username):
        self.username = username

    def generate_RSA_key(self):
        # Generate RSA key
        key = rsa.generate_private_key(public_exponent=65537,key_size=2048,backend=default_backend())
        # Write private_key to disk for safe keeping
        with open("./client_key.pem", "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(b"Azertyuiop!123")
            ))
        return key

    def generate_certif_request(self):
        key = self.generate_RSA_key()
        # Generate a CSR
        certif_request = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            # Provide various details about who we are.
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"TN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Python"),
            x509.NameAttribute(NameOID.COMMON_NAME,u"client:"+str(self.username)),
        ])).add_extension(x509.SubjectAlternativeName([
            # Describe what sites we want this certificate for.
            x509.DNSName(u"www.projet.python.com"),]), critical=False).sign(key, hashes.SHA256(), default_backend())
        # Write our certificate out to disk.
        #with open("./client_csr.pem", "wb") as f:
        with open("./CA/" + self.username.get() + ".pem", "wb") as f:
            f.write(certif_request.public_bytes(serialization.Encoding.PEM))
        return certif_request.public_bytes(serialization.Encoding.PEM).decode()

    def certif_request(self):
        request = self.generate_certif_request()
        self.send_to_certifserver('request', request)
        self.channel.start_consuming()

    def verify_cert(self):
        #certificat_client = handle_cert_local('./CA/' + self.username.get() + '.pem')
        certificat_client = handle_cert_local('./client_cert.pem')
        cert = certificat_client.public_bytes(serialization.Encoding.PEM).decode()
        print(cert)
        print(certificat_client)
        self.send_to_certifserver('verify', cert)
        self.channel.start_consuming()

    def connect_to_rabbitmq(self):
        self.connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost'))
        self.channel = self.connection.channel()
        self.receive_from_certifserver()
      

    def send_to_certifserver(self, demand, data):
        self.channel.queue_declare(queue='request_certif_queue', durable=True)
        message = self.queue_name + '*' + demand + '*' + str(data)

        self.channel.basic_publish(exchange='',routing_key='request_certif_queue',body=message)
        print('Client send request')

    def receive_from_certifserver(self):

        self.channel.exchange_declare(exchange='certificate_exchange', exchange_type='direct')
        result = self.channel.queue_declare(queue='', exclusive=True)
        self.queue_name = result.method.queue[4:]
        self.channel.queue_bind(exchange='certificate_exchange', queue=result.method.queue, routing_key=self.queue_name)

        def callback(ch, method, properties, body):
            print(body.decode("utf-8"))
            demand, data = body.decode().split('*')

            if(demand == 'certif'):
                print('Client receive certificate')
                client_cert = extract_pub(data)
                with open("CA/client_cert.pem", "wb") as f:
                    f.write(client_cert.public_bytes(serialization.Encoding.PEM))
                print(client_cert)
                self.cert = data
                self.channel.close()
                self.connection.close()
            if(demand == 'verify'):
                print(data)
                print('Verificationsas', str(data))
                self.certificat_existe = data
                self.channel.close()
                self.connection.close()
        self.channel.basic_consume(
            queue=result.method.queue, on_message_callback=callback, auto_ack=True)

