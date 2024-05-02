import ldap
import hashlib
import sys
import ldap.modlist as modlist
from base64 import b64encode


class Ldap():

    def __init__(self, password_admin):
        self.ldap_admin = password_admin


    def register_to_ldap(self, user):

        # new user domain
        user_domaine = 'cn=' + user['username'] + ',cn=security,ou=security,dc=salem,dc=local'
        home_directory = '/home/users/' + user['username']

        # encode password using md5 hash
        pass_hached = hashlib.md5(user['password'].encode("UTF-8"))
        
        
        entry = {}
        entry['objectClass'] = [b'inetOrgPerson', b'posixAccount', b'top']
        entry['uid'] = user['username'].encode("UTF-8")
        entry['givenname'] = user['username'].encode("UTF-8")
        entry['sn'] = user['username'].encode("UTF-8")
        entry['mail'] = user['email'].encode("UTF-8")
        entry['uidNumber'] = user['uid'].encode("UTF-8")
        entry['gidNumber'] = str(user['group_id']).encode("UTF-8")
        entry['loginShell'] = [b'/bin/sh']
        entry['homeDirectory'] = home_directory.encode("UTF-8")
        entry['userPassword'] = [b'{md5}' + b64encode(pass_hached.digest())]
      

        ldif = modlist.addModlist(entry)
        # connect to host with admin
        l = ldap.initialize("ldap://192.168.204.129:389")
        l.simple_bind_s("cn=admin,dc=salem,dc=local", self.ldap_admin)

        try:
            # add entry in the directory
            l.add_s(user_domaine, ldif)
            print("user added")
            return None
        except Exception:
            return sys.exc_info()[0]

        finally:
            l.unbind_s()

    def login_to_ldap(self, username, password):
        self.username = username
        self.password = password


        # organization user's domain
        user_domain = "cn=" + self.username + ",cn=security,ou=security,dc=salem,dc=local"

        # base domain
        base_domaine = "cn=security,ou=security,dc=salem,dc=local"

        # start connection
        l = ldap.initialize("ldap://192.168.204.129:389")
        search = "cn=" + self.username


        try:
            # if authentication successful, get the full user data
            l.bind_s(user_domain, self.password)
            resultat = l.search_s(base_domaine, ldap.SCOPE_SUBTREE, search)

            l.unbind_s()
            print("sassas")
            print(resultat)
            return None
        except ldap.INVALID_CREDENTIALS:
            l.unbind()
            print("credential problem")
            return "credentiel problem.."
        except ldap.SERVER_DOWN:
            print("ldap server problem")
            return "ldap server problem"


  
ld = Ldap(password_admin="sassas")

