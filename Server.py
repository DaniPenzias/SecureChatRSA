import socket
import threading
import sqlite3
from RSACode import RSAEncryption

# This class has all the function relating to the server work against the clients
class Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server_socket = None
        self.rsa = RSAEncryption()
        self.client_sockets = {}
        self.lock = threading.Lock()
        self.database_path = 'users.db'  # Database file path
        self.client_public_keys = {}

    # This function runs the server, opens the database, creates keypair of the RSA encryption
    def run(self):
        try:
            self.rsa.generate_keypair()
            self.setup_database()
            self.start_server()
        except Exception as e:
            print('Error occurred during server execution:', str(e))
            self.close_server()

    # This function creates the database used to store users information, and if already exists just opens it
    def setup_database(self):
        try:
            self.database = sqlite3.connect(self.database_path)
            cursor = self.database.cursor()
            cursor.execute('''CREATE TABLE IF NOT EXISTS users
                              (id INTEGER PRIMARY KEY AUTOINCREMENT,
                              username TEXT,
                              password TEXT)''')
            self.database.commit()
        except Exception as e:
            print('Error occurred during database setup:', str(e))
            self.close_server()

    # This function starts the actual server running so it listens to upcoming connections and creates threads for each new client
    def start_server(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            print('Server started on {}:{}'.format(self.host, self.port))

            while True:
                client_socket, client_address = self.server_socket.accept()
                client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
                client_thread.start()
                print(client_socket, client_address) #
        except Exception as e:
            print('Error occurred during server startup:', str(e))
            self.close_server()

    # This function receives the public key of each new client so the server can communicate with it
    def receive_public_key(self, client_socket):
        try:
            serialized_public_key = client_socket.recv(1024).decode()
            self.client_public_keys[client_socket] = serialized_public_key
        except Exception as e:
            print('Error occurred during receive_public_key:', str(e))
    
    # This function gets the desired public key of the current client on each thread
    def get_client_public_key(self, client_socket):
        return self.client_public_keys.get(client_socket)

    # This function sends the servers' public key to each client so they can communicate with each other
    def send_public_key(self, client_socket):
        public_key = self.rsa.get_public_key()
        public_key_data = repr(public_key)
        client_socket.sendall(public_key_data.encode())

    # This is the main function for handling each client, this function is doing all the 
    # communication regarding authentication and messages to pass between clients
    def handle_client(self, client_socket):
        username = None
        password = None
        try:
            # Step 1: Receive public key from client and send public key to client
            self.receive_public_key(client_socket)
            self.send_public_key(client_socket)

            # Step 2: Wait for the username and password
            state = 'WAITING_FOR_AUTHENTICATION'

            while True:
                data = client_socket.recv(1024).decode()
                if len(data) == 0:
                    print("Client closed the connection")
                    break

                if state == 'WAITING_FOR_AUTHENTICATION':
                    decrypted_data = self.rsa.decrypt_message(list(map(int, data.split(','))))
                    username, password = decrypted_data.split(':')
                    state = 'AUTHENTICATING'

                if state == 'AUTHENTICATING':
                    response = self.authenticate_user(username, password)

                    if response == 'Authentication successful.':
                        state = 'AUTHENTICATED'
                        # Sending a confirmation that the client has been authenticated
                        encrypted_data = self.rsa.encrypt_RSA(tuple(map(int, self.get_client_public_key(client_socket)[1:-1].split(', '))), 'Authentication successful.')
                        encoded_data = ','.join(map(str, encrypted_data)).encode()
                        client_socket.sendall(encoded_data)

                        # Add the client socket to the dictionary of active client sockets with username as the key
                        self.client_sockets[username] = client_socket
                    else:
                        encrypted_data = self.rsa.encrypt_RSA(tuple(map(int, self.get_client_public_key(client_socket)[1:-1].split(', '))), 'Authentication failed.')
                        encoded_data = ','.join(map(str, encrypted_data)).encode()
                        client_socket.sendall(encoded_data)
                        break

                elif state == 'AUTHENTICATED':
                    decrypted_data = self.rsa.decrypt_message(list(map(int, data.split(',')))) # The message the client sent
                    self.send_message_to_clients(decrypted_data, username)

        except ConnectionResetError as e: #Connection is abrubtly closed by client
            print('Connection reset by client:', client_socket)
        except Exception as e:
            print('Error type:', type(e))
            print('Error occurred during client handling:', str(e))
            encrypted_data = self.rsa.encrypt_RSA(tuple(map(int, self.get_client_public_key(client_socket)[1:-1].split(', '))), 'An error occurred during authentication.')
            encoded_data = ','.join(map(str, encrypted_data)).encode()
            client_socket.sendall(encoded_data)

        finally: # Closing connection no matter what happens (client closes window or other error)
            # Remove the client socket from the dictionary of active client sockets
            with self.lock:
                if username in self.client_sockets:
                    del self.client_sockets[username]
            client_socket.close()
    
    # This function takes a message and the client name who sends it and publishes 
    # it in a broadcast way to all other clients (including the sending one)
    def send_message_to_clients(self, message, sender_username):
        # Now we know who sent what
        temp_message = sender_username + ": " + message
        message = temp_message
        with self.lock:
            for username, client_socket in self.client_sockets.items():
                encrypted_data = self.rsa.encrypt_RSA(tuple(map(int, self.get_client_public_key(client_socket)[1:-1].split(', '))), message)
                encoded_data = ','.join(map(str, encrypted_data)).encode()
                client_socket.sendall(encoded_data)
    
    # This function is responsible for the authentication part of the connection
    # with each client as well as communication with the database for it
    def authenticate_user(self, username, password):
        try:
            cursor = None
            conn = None
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username=?", (username,))
            existing_user = cursor.fetchone()

            # User exists, checking password
            if existing_user:
                if existing_user[2] == password:
                    return 'Authentication successful.'
                else:
                    return 'Authentication failed.'
            else: # User doesn't exist, adding new user
                cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
                conn.commit()
                return 'Authentication successful.'  # New user added successfully

        except Exception as e:
            print('Error occurred during user authentication:', str(e))
            return 'Error occurred during user authentication.'

        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    # This function closes the server
    def close_server(self):
        if self.server_socket:
            self.server_socket.close()

        if self.database:
            self.database.close()

if __name__ == '__main__':
    server = Server('localhost', 12345)
    try:
        server.run()
    except KeyboardInterrupt:
        server.close_server()
