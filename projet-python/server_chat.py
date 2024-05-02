import pika
from RSAencrydecryp import RSA_asymetric_encrypt, RSA_asymetric_decrypt, Import_RSA_key

class Server_chat:
    def __init__(self):
        self.users_online = {}
        self.rooms={'room1':[]}
    def connect_to_rabbitmq(self):
        self.connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost'))
        self.channel = self.connection.channel()
        self.receive_from_chatroom()

    def receive_from_chatroom(self):
        self.channel.queue_declare(queue='main_queue')
        def callback(ch, method, properties, body):
            # Received a Message
            
            tokens = body.decode().split('*')
            demand = tokens[0]
            tokens[1] =  'amq.'+tokens[1]
            print("✔ Received this ",body)
            self.traiter_demand(demand,tokens[1:])
            ch.basic_ack(delivery_tag=method.delivery_tag)

        self.channel.basic_consume(queue='main_queue', on_message_callback=callback)
        print('server chat start')
        self.channel.start_consuming()
        
    def traiter_demand(self,demand,tokens):
        if demand == 'login':
            # User send this demand + his queue name + his name
            queue_name = tokens[0]
            user_name= tokens[1]
            pubkey = tokens[2].encode()
            self.users_online.setdefault(queue_name,{'username': user_name, 'pubkey': pubkey})
            self.send_to_chatroom(queue_name,"connected*")
            for queue in self.users_online.keys():
                if queue != queue_name:
                    self.send_to_chatroom(queue,"connectedUsers*"+','.join([obj['username'] for obj in self.users_online.values()]))
        elif demand == 'getuser_online':
            # return all connected Users names
            queue_name = tokens[0]
            if( queue_name in self.users_online.keys()):

                usersNames = ','.join([obj['username'] for obj in self.users_online.values()])
                self.send_to_chatroom(queue_name,"connectedUsers*"+usersNames)
                return True
            else:
                self.send_to_chatroom(queue_name,"notfound*")
                return False
        elif demand == 'getuser-information':
            queue_name = tokens[0]
            demanded_user_name = tokens[1]
            for key,val in self.users_online.items():
                if val['username'] == demanded_user_name:
                    self.send_to_chatroom(key,"chosen*"+self.users_online[queue_name]['username']+'*'+self.users_online[queue_name]['pubkey'].decode()+'*'+queue_name)
                    self.send_to_chatroom(queue_name,"username*"+str(val['username'])+"*"+str(key)+"*"+val['pubkey'].decode())
                    return True
            self.send_to_chatroom(queue_name,"notfound*")
            return False
        elif demand == 'getRooms':
            queue_name = tokens[0]
            if(queue_name in self.users_online.keys()):
                self.send_to_chatroom(queue_name,"rooms*"+','.join(self.rooms.keys()))
                return True
            self.send_to_chatroom(queue_name,'notfound*')
            return False
        elif demand == 'joinRoom':
            queue_name = tokens[0]
            room = tokens[1]
            if(queue_name in self.users_online.keys()):
                self.rooms[room].append(queue_name)
                self.send_to_chatroom(queue_name,"joinedRoom*"+room+'*')
                return True
            self.send_to_chatroom(queue_name,"notfound*")
            return False
        elif demand == 'sendToRoom':
            queue_name = tokens[0]
            user_name = self.users_online[queue_name]['username']
            room = tokens[1]
            # We decrypted the message using the room's private key first
            roomPrivateKey = Import_RSA_key("./"+room).export_key()
            message = RSA_asymetric_decrypt(tokens[2].encode(), roomPrivateKey).decode()
            if(queue_name in self.users_online.keys() and queue_name in self.rooms[room]):
                for queue in self.rooms[room]:
                    # Get pubkey for each user
                    destPubKey = self.users_online[queue]['pubkey']
                    # Encrypt the message with user's public key
                    print("This is the pubKey of " + self.users_online[queue]['username'] + ": "+destPubKey.decode()[:40])
                    encrypted_msg = RSA_asymetric_encrypt(message, destPubKey)
                    self.send_to_chatroom(queue,'roomReceive*'+room+'*'+user_name+'*'+encrypted_msg.decode())
                return True
            else :
                self.send_to_chatroom(queue_name,'notfound*')
                return False
        
    def send_to_chatroom(self,client_queue,msg):
        self.channel.exchange_declare(exchange='users_exchange', exchange_type='direct')
        self.channel.basic_publish(exchange='users_exchange',routing_key=client_queue[4:],body=msg,
        properties=pika.BasicProperties(delivery_mode=2,))

s = Server_chat()
s.connect_to_rabbitmq()