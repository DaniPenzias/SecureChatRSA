import socket
from tkinter import *
from tkinter.scrolledtext import ScrolledText
from RSACode import RSAEncryption
import threading
from tkinter import filedialog

# This class is responsible for the looks of the GUI as well to change the screen after login is approved
class GUI:
    # This constructing function creates the basic login screen as well as 
    # creating the Client object which does all the authentication
    def __init__(self):
        self.client = Client('localhost', 12345)
        self.rsa = self.client.rsa

        self.Window = Tk()
        self.Window.withdraw()

        self.login = Toplevel()
        self.login.title("Login")
        self.login.resizable(width=False, height=False)
        self.login.configure(width=400, height=300)

        self.pls = Label(self.login, text="Please login to continue", justify=CENTER, font="Helvetica 14 bold")
        self.pls.place(relheight=0.15, relx=0.2, rely=0.07)

        self.labelName = Label(self.login, text="Name: ", font="Helvetica 12")
        self.labelName.place(relheight=0.2, relx=0.1, rely=0.2)

        self.entryName = Entry(self.login, font="Helvetica 14")
        self.entryName.place(relwidth=0.4, relheight=0.12, relx=0.35, rely=0.2)
        self.entryName.focus()

        self.labelPass = Label(self.login, text="Password: ", font="Helvetica 12")
        self.labelPass.place(relheight=0.2, relx=0.1, rely=0.4)

        self.entryPass = Entry(self.login, show='*', font="Helvetica 14")
        self.entryPass.place(relwidth=0.4, relheight=0.12, relx=0.35, rely=0.4)

        self.go = Button(self.login, text="LOGIN", font="Helvetica 14 bold", command=self.authenticate)
        self.go.place(relx=0.4, rely=0.55)

        self.errorLabel = Label(self.login, text="", fg="red", font="Helvetica 12")
        self.errorLabel.place(relheight=0.1, relx=0.1, rely=0.75)

        self.Window.mainloop()

    # This function goes on to check each part of the authentication happening
    # in the Client functions and if there is a problem doesn't let continuing
    def authenticate(self):
        username = self.entryName.get()
        password = self.entryPass.get()
        
        if username and password:
            if self.client.connect():
                if self.client.authenticate(username, password):
                    self.login.destroy()
                    self.layout(username)
                    self.receive_thread = threading.Thread(target=self.receive)
                    self.receive_thread.start()
                else:
                    self.errorLabel.configure(text="Authentication failed.")
            else:
                self.errorLabel.configure(text="Failed to connect to the server.")
                self.client.close()  # Close the client if connection failed
        else:
            self.errorLabel.configure(text="Please enter both username and password.")
    
    # This function is the looks of the chat screen
    def layout(self, username):
        self.name = username
        self.Window.deiconify()
        self.Window.title("CHATROOM")
        self.Window.resizable(width=False, height=False)
        self.Window.configure(width=470, height=550, bg="#17202A")

        self.labelHead = Label(self.Window, bg="#17202A", fg="#EAECEE", text=self.name,
                               font="Helvetica 13 bold", pady=5)
        self.labelHead.place(relwidth=1)

        self.line = Label(self.Window, width=450, bg="#ABB2B9")
        self.line.place(relwidth=1, rely=0.07, relheight=0.012)

        self.textCons = ScrolledText(self.Window, width=20, height=2, bg="#17202A", fg="#EAECEE",
                                     font="Helvetica 14", padx=5, pady=5)
        self.textCons.place(relheight=0.745, relwidth=1, rely=0.08)

        self.labelBottom = Label(self.Window, bg="#ABB2B9", height=80)
        self.labelBottom.place(relwidth=1, rely=0.825)

        self.entryMsg = Entry(self.labelBottom, bg="#2C3E50", fg="#EAECEE", font="Helvetica 13")
        self.entryMsg.place(relwidth=0.55, relheight=0.06, rely=0.008, relx=0.21)
        self.entryMsg.focus()

        self.buttonMsg = Button(self.labelBottom, text="Send", font="Helvetica 10 bold", width=20, bg="#ABB2B9",
                                command=self.send_message)
        self.buttonMsg.place(relx=0.77, rely=0.008, relheight=0.06, relwidth=0.22)

        self.textCons.config(cursor="arrow")

        self.browseButton = Button(self.labelBottom, text="Browse", font="Helvetica 10 bold", width=10, bg="#ABB2B9",
                               command=self.browse_file)
        self.browseButton.place(relx=0.01, rely=0.008, relheight=0.06)

        scrollbar = Scrollbar(self.textCons)
        scrollbar.place(relheight=1, relx=0.974)
        scrollbar.config(command=self.textCons.yview)
    
    # This function is responsible for the browsement in the file explorer in order to send a file content
    def browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            if file_path[-4:] == ".txt":
                self.client.send_text_file(file_path)
            else:
                print("Not a text file.")
    
    # This function takes the message written in the entry and sends it to the server using the send_message function
    def send_message(self):
        message = self.entryMsg.get()
        if message:
            self.client.send_message(message)
            self.entryMsg.delete(0, END)

    # This function is reponsible for receiving all messages from the server and writing them down
    def receive(self):
        while True:
            try:
                response = self.client.receive_message()
                self.textCons.config(state=NORMAL)
                self.textCons.insert(END, response + '\n')
                self.textCons.config(state=DISABLED)
                self.textCons.see(END)
            except Exception as e:
                print(str(e))
                self.client.close_connection()
                break


# This class is responsible for most of the functionality of the connection to the server,
# authentication of the client, the exchange of public keys with the server and send and receive functions
class Client:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.client_socket = None
        self.rsa = RSAEncryption()
        self.rsa.generate_keypair()
        self.authenticated = False
        self.server_public_key = None

    # This function connects the client to the server using UDP
    def connect(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.host, self.port))
            return True
        except Exception as e:
            print('Error occurred during connection:', str(e))
            return False

    # This function receives the public key from the server in order to communicate with it
    def receive_public_key(self):
        try:
            serialized_public_key = self.client_socket.recv(1024).decode()
            self.server_public_key = serialized_public_key
            return True
        except Exception as e:
            print('Error occurred during receive_public_key:', str(e))
            return False

    # This function sends the clients' public key to the server in order to communicate with it
    def send_public_key(self):
        public_key = self.rsa.get_public_key()
        public_key_data = repr(public_key)
        self.client_socket.sendall(public_key_data.encode())

    # This function is responsible for the authentication of the client against the server
    def authenticate(self, username, password):
        try:
            # Sending the public key to the server
            self.send_public_key()

            # Receiving public key from server
            self.receive_public_key()

            # Sending username and password
            public_key = tuple(map(int, self.server_public_key[1:-1].split(', ')))
            self.server_public_key = public_key
            self.send_message(str('{}:{}'.format(str(username), str(password))))

            # Receiving successed or failed authentication
            response = self.client_socket.recv(1024).decode()
            decrypted_response = self.rsa.decrypt_message(list(map(int, response.split(','))))
            
            if decrypted_response == 'Authentication successful.':
                self.authenticated = True
                print('Authentication successful.')
                return True
            else:
                print('Authentication failed.')
                return False
        except Exception as e:
            print('Error occurred during authentication:', str(e))
            return False

    # This function sends a text message to the server which sends it to all connected clients
    def send_message(self, message):
        try:
            encrypted_message = self.rsa.encrypt_RSA(self.server_public_key, message)
            self.client_socket.sendall(','.join(map(str, encrypted_message)).encode())
        except Exception as e:
            print('Error occurred while sending message:', str(e))

    # This function reads the content of a text file and then sends it to the server using the send_message function
    def send_text_file(self, file_path):
        with open(file_path, 'r') as file:
            file_contents = file.read()
        self.send_message(file_contents)

    # This function receives data from the server, decodes it and then returns it for further use
    def receive_encrypted_response(self):
        encrypted_response = self.client_socket.recv(1024).decode()
        return encrypted_response

    # This function receives the message using the receive_encrypted_response function and then decrypts 
    # it using the decrypt_message function and then returns it so it can be printed on the screen
    def receive_message(self):
        try:
            encrypted_response = self.receive_encrypted_response()
            response = self.rsa.decrypt_message(list(map(int, encrypted_response.split(','))))
            return response
        except Exception as e:
            print('Error occurred while receiving message:', str(e))

    def close_connection(self):
        self.client_socket.close()

if __name__ == '__main__':
    gui = GUI()
