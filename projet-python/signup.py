from tkinter import Label, Entry, Button, Radiobutton,StringVar, Toplevel,Frame
from ldapphpadmin import Ldap
from chatroom import *
import re
from ssl509.certificat_client import certification_client, handle_cert_local
import random



def checkMail(email):
    if bool(re.match(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', email)):
        return True
    else:
        return False
class Sign_to_chat:

    def main(self):
        # main frame
        self.root = Toplevel()
        self.root.title("Login Form")
        self.root.geometry('1125x600+300+200')
        self.root.configure(bg="black")
        self.root.resizable(True,True)
        
        img = PhotoImage(file='./logo.png')
        Label(self.root,image=img,bg='white',width=650,height=600).place(x=70,y=30)


        frame=Frame(self.root,width=450,height=480,bg="white")
        frame.place(x=720,y=100)

        # data binding
        self.USERNAME = StringVar(self.root)
        self.EMAIL = StringVar(self.root)
        self.PASSWORD = StringVar(self.root)
        self.CPASSWORD = StringVar(self.root)
        self.GENDER = StringVar(self.root)
        self.UID = StringVar(self.root)
        

        # Registration form
        label_0 = Label(frame, text="Inscription", fg='#3b6180',bg='white', font=("Microsoft YaHei UI Light", 20 , 'bold'))
        label_0.place(x=50, y=5)

        # FullName label & entry
        
        label1= Entry(frame, width=20,border=0,textvariable=self.USERNAME,fg='#3b6180',bg='white', font=("Microsoft YaHei UI Light", 11))
        label1.place(x=150, y=60)
        

        label=Label(frame,text="Login",fg='black', bg='white',font=("Microsoft YaHei UI Light", 11))
        label.place(x=30,y=60)

        # self.EMAIL label & entry
        
        label2= Entry(frame, width=20,border=0,textvariable=self.EMAIL,fg='#3b6180',bg='white', font=("Microsoft YaHei UI Light", 11))
        label2.place(x=150, y=100)
       
        
        
        label=Label(frame,text="E-mail",fg='black', bg='white',font=("Microsoft YaHei UI Light", 11))
        label.place(x=30,y=100)

        # self.PASSWORD label &
        

        label3= Entry(frame, width=20,border=0,show="*",textvariable=self.PASSWORD,fg='#3b6180',bg='white', font=("Microsoft YaHei UI Light", 11))
        label3.place(x=150, y=140)
       

        label=Label(frame,text="Mot de Passe",fg='black', bg='white',font=("Microsoft YaHei UI Light", 11))
        label.place(x=30,y=140)

        

        label3= Entry(frame, width=20,border=0,show="*",textvariable=self.CPASSWORD,fg='#3b6180',bg='white', font=("Microsoft YaHei UI Light", 11))
        label3.place(x=150, y=180)
       

        label=Label(frame,text="confirmer MP",fg='black', bg='white',font=("Microsoft YaHei UI Light", 11))
        label.place(x=30,y=180)
        
         # self.GENDER label & radio-box
        
        label=Label(frame,text="Genre",fg='black', bg='white',font=("Microsoft YaHei UI Light", 11))
        label.place(x=30,y=220)


        optionMale = Radiobutton(frame, text="Male              ", variable=self.GENDER, value=1)
        optionMale.place(x=150, y=220)
        optionFemale = Radiobutton(frame, text="Female      ", variable=self.GENDER, value=2)
        optionFemale.place(x=230, y=220)

        # Error label
        self.error = Label(frame, width=60, font=("bold", 9))
        self.error.place(x=30, y=300)

        # Submit button
        btn = Button(frame, text='Enregister', width=20,pady=7, command=self.Register, bg='blue',border=0, fg='white')
        btn.place(x=150, y=280)

        

        # theme color hacker
        self.root.config(bg="white")
        label_0.config(bg="white", fg="#3b6180")
        optionFemale.config(bg="white")
        optionMale.config(bg="white")
        self.error.config(bg="white")

        # it is use for display the registration form on the self.root
        self.root.mainloop()
        print("registration seccuss")

    def Register(self, event=None):
        UID=str(random.randint(1001,3000))
        if self.USERNAME.get() != "" and self.PASSWORD.get() != "" and self.CPASSWORD.get() != "" and self.EMAIL.get() != "":
            if self.PASSWORD.get() == self.CPASSWORD.get():
                if (checkMail(self.EMAIL.get())==True):
            
                    user_info = {'username': self.USERNAME.get(),'password': self.PASSWORD.get(),'email': self.EMAIL.get(),
                        'gender': self.GENDER.get(),'group_id': 500,'uid': UID }
                    print(user_info)
                  
                    ld = Ldap(password_admin="sassas")
                    ldap_resultat = ld.register_to_ldap(user_info)
                    print(ldap_resultat)
                    if not ldap_resultat:
                                           
                        self.error.config(text="Sucess", fg="#3b6180", bg="#336633")

                        time.sleep(1)

                        # handle certificatei
                        caclient = certification_client(self.USERNAME)
                        caclient.connect_to_rabbitmq()
                        caclient.certif_request()
                        result = handle_cert_local('CA/client_cert.pem')
                        
                        if result:
                            self.root.destroy()
                            exec(open("login.py").read())
                            #self.to_chat()
                        else:
                            self.error.config(text="Error occured while obtaining SSL certificate", fg="white", bg="#3b6180")
            
                else:
                    self.error.config(text="invalide mail", fg="white", bg="#3b6180")
            else:
                self.error.config(text="mot de passe erreur", fg="white", bg="#3b6180")

        else:
            self.error.config(text="Please complete the required field!", fg="white", bg="#3b6180")

        
            

    def to_chat(self):
        username = self.USERNAME.get()
        cr = Chatroom()
        cr.run(user=username)


s = Sign_to_chat()

s.main()


