import pika
from threading import Thread as th

class SenderBroker(th):
    def __init__(self, queue_name):
        super().__init__()
        self.queue_name = queue_name

    def connect_to_rabbitmq(self):
        self.connection = pika.BlockingConnection( pika.ConnectionParameters(host='localhost'))
        self.channel = self.connection.channel()
        
    def routing(self,message):
        self.connect_to_rabbitmq()
        self.channel.basic_publish(exchange='', routing_key=self.queue_name, body=message)

    def send_msg(self, message):
        self.routing(message)


    def stop_coonection(self):
        self.join(5)
        self.connection.close()