from tkinter import Label, Entry, Button, Radiobutton,StringVar, Toplevel,Frame
from tkinter import Frame,Label
from ldapphpadmin import Ldap
from random import randint
import ssl
import smtplib
from ssl509.certificat_client import certification_client
from chatroom import *


        

class Log_to_chat:

    def main(self):
        ##### form login
        self.root = Toplevel()
        self.root.title("Login Form")
        self.root.geometry('1125x600+300+200')
        self.root.configure(bg="black")
        self.root.resizable(True,True)
        
        img = PhotoImage(file='./logo.png')
        Label(self.root,image=img,bg='white',width=650,height=600).place(x=70,y=30)

        frame=Frame(self.root,width=450,height=480,bg="white")
        frame.place(x=720,y=100)

        self.USERNAME = StringVar(self.root)
        self.PASSWORD = StringVar(self.root)
        

        label_0 = Label(frame, text="Login", fg='#3b6180',bg='blue', font=("Microsoft YaHei UI Light", 29, 'bold'))
        label_0.place(x=120, y=5)

        # self.USERNAME label & entry
        user= Entry(frame, width=25,border=0,textvariable=self.USERNAME,fg='#3b6180',bg='white', font=("Microsoft YaHei UI Light", 11))
        user.place(x=130, y=100)
        
        

        label=Label(frame,text="Utilisateur",fg='black', bg='white',font=("Microsoft YaHei UI Light", 11))
        label.place(x=30,y=100)

        # self.PASSWORD label & entry
       
        code= Entry(frame, width=25,border=0,textvariable=self.PASSWORD, show="*",fg='#3b6180',bg='white', font=("Microsoft YaHei UI Light", 11))
        code.place(x=130, y=150)
        
        

        label=Label(frame,text="Mot de passe",fg='black', bg='white',font=("Microsoft YaHei UI Light", 11))
        label.place(x=30,y=150)

        # Submit button
        Button(frame, text='Submit',pady=7, width=39, bg='blue', fg='white',border=0, command=self.Login).place(x=35, y=244)
        
        
        label=Label(frame,text="Don't have an account?",fg='black', bg='white',font=("Microsoft YaHei UI Light", 9))
        label.place(x=75,y=325)
        
        # Register button
        btn_2 = Button(frame, text='Signup', width=10, command=self.go_signup, bg='blue',
                       fg='white', borderwidth=0, font="Verdana 10 underline")
        btn_2.place(x=235, y=325)

        # Error label
        self.error= Label(frame, width=60, font=("bold", 8))
        self.error.place(x=30, y=290)

        # theme color
        self.root.config(bg="white")
        label_0.config(bg="white", fg="#3b6180")
        
        self.error.config(bg="white")

        # it is use for display the registration form on the self.root
        self.root.resizable(200, 120)
        self.root.mainloop()
        print("login succes")
    
    def Login(self, event=None):

        if self.USERNAME.get() == "" or self.PASSWORD.get() == "":
            self.error.config( text="Please complete the required field!", fg="white", bg="#3b6180")
        else:
            ld = Ldap(password_admin="sassas")
            ldap_resultat = ld.login_to_ldap(username=self.USERNAME.get(), password=self.PASSWORD.get())
            
            if not ldap_resultat:
        

                caclient = certification_client(self.USERNAME)
                caclient.connect_to_rabbitmq()
                caclient.verify_cert()
                if caclient.certificat_existe != "existe":
                    self.to_chat()
                else:
                    self.error.config(text="Access denied", fg="white", bg="#3b6180")

            else:
                print("non")
                self.error.config(text=ldap_resultat, fg="white", bg="#3b6180")
          

    def to_chat(self):
        username = self.USERNAME.get()
        self.root.withdraw()
        cr = Chatroom()
        cr.run(user=username)

    def go_signup(self):
        self.root.destroy()
        from signup import Sign_to_chat
        self.root.withdraw()
        sp = Sign_to_chat()
        sp.main()


l = Log_to_chat()
l.main()
