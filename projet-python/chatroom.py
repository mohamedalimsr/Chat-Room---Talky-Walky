from tkinter import *
from tkinter import ttk
import time
import tkinter as tk
from threading import Thread
from senderBroker import SenderBroker
from receiverBroker import ReceiverBroker
from Crypto.PublicKey import RSA
from RSAencrydecryp import RSA_asymetric_encrypt, RSA_asymetric_decrypt, Import_RSA_key
import pika
from ttkthemes import ThemedTk
saved_username = ["You"]

class Chatroom():

    def on_closing(self):
        self.root.destroy()
        self.app.disconnect_from_server()

    def run(self, user):
        self.root = ThemedTk(theme="equilux")
        self.root.title("Python Project")
        self.root.geometry("600x500")
        self.root.minsize(360, 200)

        self.pass1 = ChatInterface(self.root, fullname=user)

        # root is your root window
        self.root.protocol('WM_DELETE_WINDOW', self.on_closing)
        self.root.mainloop()

class ChatInterface(Frame, SenderBroker, ReceiverBroker):

    def __init__(self, master=None, fullname=""):
        Frame.__init__(self, master)
        self.master = master
        self.selectedRoom=''
        self.talking_users = {}
        self.tabs=[]
        self.username = fullname

        self.connect_to_server(self.username)
        #alwen
        self.master.config(bg="#2b2b2b")
      
        menu = Menu(self.master)
        self.master.config(menu=menu, bd=5)

        self.on_room_select("room1")
     
    # Chat interface
        # frame containing text box with messages and scrollbar

        self.notebook = ttk.Notebook(self.master)
        self.container = Frame(self.notebook, bd=0)
        self.container.pack(expand=True, fill=BOTH)
        
        self.notebook.pack(expand=True, fill=BOTH)
        self.upperFrame = Frame(self.container)
        self.upperFrame.pack(expand=True, fill=BOTH, side=TOP)

        self.text_frame = Frame(self.upperFrame, bd=0,bg="#2b2b2b")
        self.text_frame.pack(expand=True, fill=BOTH, side=LEFT)

        
        # scrollbar for text box
        self.text_box_scrollbar = Scrollbar(self.text_frame, bd=0)
        self.text_box_scrollbar.pack(fill=Y, side=RIGHT)
    
        # contains messages
        self.text_box = Text(self.text_frame, yscrollcommand=self.text_box_scrollbar.set, state=DISABLED,
                             bd=1, padx=6, pady=6, spacing3=8, wrap=WORD, bg=None, font="Verdana 10", relief=GROOVE,
                             width=10, height=1)
        self.text_box.config(bg="#2b2b2b", fg="#FFFFFF")
        self.text_box.pack(expand=True, fill=BOTH)
        self.text_box_scrollbar.config(command=self.text_box.yview)
        self.text_box.insert(END, 'happpy chatting''\n')

        # frame containing user entry field
        self.entry_frame = Frame(self.container, bd=0)
        self.entry_frame.config(bg="#FFFFFF")
        self.entry_frame.pack(side=BOTTOM, fill=X, expand=False)

        # entry field
        self.entry_field = Entry(self.entry_frame, bd=0,font="lucida 10 bold", justify=LEFT)
        self.entry_field.config(bg="#2b2b2b", fg="#FFFFFF", insertbackground="#FFFFFF")
        self.entry_field.pack(fill=X, padx=6, pady=6, ipady=3)
        self.entry_field.focus()
        # self.users_message = self.entry_field.get()

        # frame containing send button and emoji button
        self.send_button_frame = Frame(self.entry_frame, bd=0)
        self.send_button_frame.config(bg="#2b2b2b")
        self.send_button_frame.pack(fill=BOTH)

        # send button
        self.send_button = Button(self.send_button_frame, text="Send message",fg="#83eaf7", font="lucida 11 bold", bg="lightblue", padx=10,
                                relief="solid", bd=2, command=lambda: self.send_message(None), activebackground="red", activeforeground="#000000")
        self.send_button.place(x=200,y=5)


        # emoticons
        self.emoji = Button(self.send_button_frame, text="💯", width=0,font="lucida 11 bold", relief=RAISED, bg="black",
                                   bd=1, command=lambda: self.insertemoji("💯"))
        self.emoji.pack(side=LEFT, padx=0, pady=0, ipady=2)
        # emoticons
    


        self.container.bind("<Return>", self.send_message_event)

     
        self.notebook.add(self.container,text="Room to talk")
         #hhhhisiididid ahaya
        
        self.userf= Toplevel(bg="#EEEEEE" )
        self.userf.title("list of connected user")
        self.userf.geometry("300x200")
        self.userf.minsize(360, 200)
        #jj
        self.users_frame = Frame(self.userf, bd=0)
        self.users_frame.config(bg="#1c2e44")
        self.users_frame.pack(fill=BOTH, expand=True)
        #jjj
        self.usersPanel= Listbox(self.users_frame, selectmode=SINGLE)
        self.usersPanel.config(bg="#2b2b2b", fg="#FFFFFF")
        self.usersPanel.pack(expand=True, fill=BOTH)
        self.usersPanel.select_set(0) #This only sets focus on the first item.
        self.usersPanel.bind('<<ListboxSelect>>', self.on_user_select)
        

        self.get_rooms()
        self.get_connected_users()
  

# Interface Function 
    def generate_tab(self,username="Pardefaut",userqueue=None):
        newTab = Frame(self.notebook,bd=0)
        text_frame = Frame(newTab, bd=0)
        self.text_frame.config(bg="#2b2b2b")
        text_frame.pack(expand=True, fill=BOTH, side=TOP)
        text_box_scrollbar = Scrollbar(text_frame, bd=0)
        self.text_box.config(bg="#2b2b2b", fg="#FFFFFF")
        text_box_scrollbar.pack(fill=Y, side=RIGHT)
        text_box = Text(text_frame, yscrollcommand=text_box_scrollbar.set, state=DISABLED,
                             bd=1, padx=6, pady=6, spacing3=8, wrap=WORD, bg=None, font="Verdana 10", relief=GROOVE,
                             width=10, height=1)
        text_box.config(bg="#2b2b2b", fg="#FFFFFF")
        text_box.pack(expand=True, fill=BOTH)
        text_box_scrollbar.config(command=text_box.yview)

        # frame containing user entry field
        entry_frame = Frame(newTab, bd=1)
        self.entry_frame.config(bg="#263b54")
        entry_frame.pack(side=BOTTOM, fill=BOTH, expand=False)

        # entry field
        entry_field = Entry(entry_frame, bd=1, justify=LEFT)
        self.entry_field.config(bg="#2b2b2b", fg="#2b2b2b", insertbackground="#2b2b2b")
        entry_field.pack(fill=X, padx=6, pady=6, ipady=3)
        entry_field.focus()
        # users_message = entry_field.get()

        # frame containing send button and emoji button
        def sending_message():
            sender = SenderBroker(userqueue)
            # Get destination user pubkey
            dest_user_pubkey = self.talking_users[userqueue]['pubkey']
            message = entry_field.get()
            # Encrypt msg with dest user pubkey
            encrypted_msg = RSA_asymetric_encrypt(message, dest_user_pubkey)
            print("! Sending encrypted msg: \n" + encrypted_msg.decode()[:40])
            sender.send_msg("messageSent*"+self.queue_name+"*"+encrypted_msg.decode())
            text_box.configure(state=NORMAL)
            text_box.insert(END, str(time.strftime('%I:%M:%S ')) +'🔑'+  self.username +': '+ message+'\n')
            text_box.see(END)
            text_box.configure(state=DISABLED)
            entry_field.delete(0, END)
        # send button
        send_button = Button(entry_frame, text="Send", width=5, relief=GROOVE, bg='lightblue',
                                  bd=1, command=lambda: sending_message(), activebackground="red",
                                  activeforeground="#2b2b2b")
        self.send_button.place(x=200,y=5)
        
        self.send_button.config(bg="#2b2b2b", fg="#FFFFFF", activebackground="#2b2b2b", activeforeground="#2b2b2b")
        send_button.pack(side=LEFT, ipady=2)
        newTab.bind("<Return>", sending_message)
        
        self.notebook.add(newTab,text=username)
        self.notebook.select(newTab)
        self.tabs.append(newTab)
        return newTab,text_box

  
# Interdemand with Server
    def create_queue(self):
        self.channel.exchange_declare(exchange='users_exchange', exchange_type='direct')
        result = self.channel.queue_declare(queue='', exclusive=True)
        self.queue_name = result.method.queue

    def generate_rsa_key_pair(self):
        #Generating RSA key pair
        key = RSA.generate(2048)
        #Extracting private_key
        self.private_key = key.export_key('PEM')
        #Extracting public_key
        self.public_key = key.publickey().exportKey('PEM')
    
    def connect_to_server(self, username):
        self.username = username
        self.connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost'))
        self.channel = self.connection.channel()
        self.create_queue()
        self.generate_rsa_key_pair()
        self.channel.queue_bind(exchange='users_exchange', queue=self.queue_name,routing_key=self.queue_name[4:])
        self.send_request_to_server("login*"+self.queue_name[4:]+"*"+self.username+"*"+self.public_key.decode())
        self.async_consumer()

    def send_request_to_server(self, message):
        sender = SenderBroker('main_queue')
        print('✔ Requesting with '+str(self.queue_name),message[:150])
        sender.send_msg(message)
        
        
    def get_connected_users(self):
        self.send_request_to_server("getuser_online*"+self.queue_name[4:]+"*")
        
    def get_user_data(self, dest_username):
        self.send_request_to_server("getuser-information*"+self.queue_name[4:]+"*"+dest_username)

    def get_rooms(self):
        self.send_request_to_server("getRooms*"+self.queue_name[4:]+"*")
    
    def select_room(self, room):
        self.send_request_to_server("joinRoom*"+self.queue_name[4:]+"*"+room)
        
    def send_msg_to_room(self, room, message):
        # get room public key
        joinedRoomPublicKey = Import_RSA_key("./"+room).publickey().export_key()        
        # now, we'll encrypt the message before sending it to server with room pub key
        encrypted_msg = RSA_asymetric_encrypt(message, joinedRoomPublicKey)
        print('! Sending to room %s key %s'%(self.selectedRoom,encrypted_msg[:50]))
        self.send_request_to_server("sendToRoom*"+self.queue_name[4:]+"*"+room+"*"+encrypted_msg.decode())
        
        
    def disconnect_from_server(self):
        self.send_request_to_server("quit*"+self.queue_name[4:]+"*"+self.username)
        self.channel.stop_consuming()
        self.connection.close()
    def listen_channel(self):
        self.channel.basic_consume(
            queue=self.queue_name, on_message_callback=self.on_message_recieved)
        self.channel.start_consuming()
        

    def async_consumer(self):
        self.worker = Thread(target=self.listen_channel)
        self.worker.start()

# Send Message

    # allows user to hit enter instead of button to change username
    def change_username_main_event(self, event):
        saved_username.append(self.username_entry.get())
        self.change_username_main(username=saved_username[-1])


    # allows "enter" key for sending msg
    def send_message_event(self, event):
        user_name = saved_username[-1]
        self.send_message(user_name)
    
    # joins username with message into publishable format
    def send_message(self, username):

        user_input = self.entry_field.get()
        currentRoom = self.usersPanel.get(ANCHOR)
        currentRoom = currentRoom.replace(" ", "")

        # now, we'll encrypt the message before sending it to rabbitmq
        #user_input = rsa_encrypt(user_input, currentRoomPublicKey)

        username = saved_username[-1] + ": "
        message = user_input
        readable_msg = ''.join(message)
        readable_msg.strip('{')
        readable_msg.strip('}')

        # clears entry field, passes formatted msg to send_message_insert
        if user_input != '':
            self.entry_field.delete(0, END)
            
            # broadcast messages in this room
            self.send_msg_to_room(self.selectedRoom,message)


    def received_user_message(self,message,textbox):
        textbox.configure(state=NORMAL)
        textbox.insert(END, str(time.strftime('%I:%M:%S ')) + message+'\n')
        textbox.see(END)
        textbox.configure(state=DISABLED)
    # inserts user input into text box
    def send_message_insert(self, message):
        # tries to close emoji window if its open. If not, passes
        try:
            self.close_emoji()

        except AttributeError:
            pass
  
        self.text_box.configure(state=NORMAL)
        self.text_box.insert(END, str(time.strftime('%I:%M:%S ')) + message+'\n',)
        self.text_box.see(END)
        self.text_box.configure(state=DISABLED)


    # callback on broker triggered
    def on_message_recieved(self, ch, method, properties, body):
        
        tokens = body.decode().split('*')
        demand = tokens[0]
        if demand =='connected':
            print('[+] Connected')
            # connected treatement
        elif demand =='disconnected':
            print('[+] Disconnected')
        elif demand =='connectedUsers':
            users_names = tokens[1].split(',')
            if self.username in users_names:
                users_names.remove(self.username)
            print('[+] Connected users: ',users_names)
            self.usersPanel.delete(0, END)
            for i,name in enumerate(users_names):
                self.usersPanel.insert(i,name)
            # TODO show the users
        # The demand for user who sent the demand to chat with another user: we get him username, queue and pubkey of dest
        elif demand =='username':
            demanded_username = tokens[1]
            demanded_user_queue = tokens[2]
            demanded_user_pubkey = tokens[3].encode()
            # adding the wanted user to talking users
            tab,textbox = self.generate_tab(demanded_username,demanded_user_queue)
            self.talking_users.setdefault(demanded_user_queue,{'username':demanded_username,'pubkey':demanded_user_pubkey,'textbox':textbox})
            
            print('[+] Demanded user: ',demanded_username,demanded_user_queue)
        # The demand for a chosen user : we get him the sender's name, pubkey and queue  
        elif demand =='chosen':
            calling_username = tokens[1]
            calling_user_pubkey = tokens[2].encode()
            calling_user_queue = tokens[3]
            # adding who want to talk to me in talking users
            tab,textbox = self.generate_tab(calling_username,calling_user_queue)
            self.talking_users.setdefault(calling_user_queue,{'username':calling_username,'pubkey':calling_user_pubkey,'textbox':textbox})

            print('[+] Have been demanded from ', calling_username,calling_user_queue)
        elif demand =='messageSent':
            user_queue = tokens[1]
            message = tokens[2].encode()
            print("[+] Got encrypred message : %s  1v1 from : %s"% (self.talking_users[user_queue]['username'] ,message.decode()[:50]))
            decrypted_msg = RSA_asymetric_decrypt(message, self.private_key)
            if(user_queue in self.talking_users):
                self.received_user_message(user_queue+": 👋 "+decrypted_msg.decode(),self.talking_users[user_queue]['textbox'])
            
        elif demand == 'rooms':
            rooms = tokens[1].split(',')
            print('[+] Received rooms ',rooms)
        elif demand =='joinedRoom':
            joinedRoom = tokens[1]
            self.selectedRoom = joinedRoom
            print('[+] Joined room: ',joinedRoom)
        elif demand =='roomReceive':
            room = tokens[1]
            username = tokens[2]
            # encode message then decrypt it with user private key
            message = tokens[3].encode()
            decrypted_msg = RSA_asymetric_decrypt(message, self.private_key)
            print('[+] Received msg at room (%s) from %s: %s '%(room,username,message.decode()))
            if( username==self.username):
                username="Me"
            self.send_message_insert("🚀 %s : %s"%(username,decrypted_msg.decode()))
        elif demand =='left':
            #room = tokens[1]
            print('[+] Leaving room ',room)

    def on_room_select(self, selection):
        # Note here that Tkinter passes an event object to onselect()
        print('[!] You selected room : "%s"' % selection)
        self.select_room(selection)
        
    def on_user_select(self, evt):
        # Note here that Tkinter passes an event object to onselect()
        w = evt.widget
        index = int(w.curselection()[0])
        value = w.get(index).lower().replace(' ','')
        print('[!] You selected user : "%s"' % value)
        if(value not in [ obj['username']for obj in self.talking_users.values()]):
            self.get_user_data(value)
      

    def on_user_connected(self, user):
        end = self.usersPanel.size()
        self.usersPanel.insert(end, user)

    def on_user_disconnected(self, user):
        idx = self.usersPanel.get(0, tk.END).index(user)
        self.usersPanel.delete(idx)
        

    def insertemoji(self, emoticon):
        self.entry_field.insert(END, emoticon)
