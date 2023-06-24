import os.path
from pathlib import Path
from datetime import datetime
import socket
import selectors
import uuid
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad
from base64 import b64decode, b64encode
from checksum import checksum
import database
import protocol


class Server:
    """
    Server code for mmn15 - Defensive System Programing
    course number 20937

    this is a simple server-client code for exchanging encrypted files based on users
    files are kept inside folders named as the user id of the client that sent them

    @author yonatan tzukerman
    @date 23/03/2023
    """
    DATABASE = "server.db"
    PACKET_SIZE = 1024
    BLOCK_FLAG = False

    def __init__(self, port, host=''):
        """
        set up server parameters
        :param host: hosting ip
        :param port: port number for server to be hosted on
        """
        self.host = host
        self.port = port
        self.users = []  # stores UUID of all users
        self.sel = selectors.DefaultSelector()

        # connect to the database and restore any previous data
        self.backup_db = database.Database(Server.DATABASE)
        self.load_backup_data()

        # keeps track of all files pending crc approval
        self.pending_crc = []

        # handlers for the protocols
        self.requestHandler = {
            protocol.RequestCodes.REQUEST_REGISTRATION.value: self.registration,
            protocol.RequestCodes.REQUEST_PUBLIC_KEY.value: self.public_key_request,
            protocol.RequestCodes.REQUEST_LOGIN.value: self.login_request,
            protocol.RequestCodes.REQUEST_SEND_FILE.value: self.file_request,
            protocol.RequestCodes.REQUEST_VALID_CRC.value: self.valid_crc,
            protocol.RequestCodes.REQUEST_WARNING_CRC.value: self.wrong_crc,
            protocol.RequestCodes.REQUEST_ERROR_CRC.value: self.failed_crc
        }

    def load_backup_data(self):
        """
        load backup user data from database
        """
        data = self.backup_db.fetch_data("clients", "ID, Name")
        self.users = data

        print("Printing user list:")
        for user in self.users:
            print(f"User name - {user[1]}, \nID - {user[0]}\n")

    def start(self):
        """
        Start up the server
        contains an infinite loop for listening to connections
        """
        try:
            # just some socket code to setup the server
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind((self.host, self.port))
            sock.listen()
            sock.setblocking(Server.BLOCK_FLAG)
            # register the accept connection function for the selector
            self.sel.register(sock, selectors.EVENT_READ, self.accept_connection)
        except Exception as e:
            print(f"Error while setting up server: {e}")
            return

        print(f"Server up and listening in {self.port}!")

        # the main loop
        while True:
            try:
                events = self.sel.select()
                for key, mask in events:
                    try:
                        callback = key.data
                        callback(key.fileobj)
                    except:
                        self.sel.unregister(key.fileobj)
            except Exception as e:
                print(f"Error while listening: {e}")

    def accept_connection(self, sock):
        """
        This function is called whenever there's a new connection
        :param sock: the socket setup in start
        """
        # accept the connection, log it and send to read()
        conn, addr = sock.accept()
        conn.setblocking(Server.BLOCK_FLAG)
        print(f"connection from {addr}")
        self.sel.register(conn, selectors.EVENT_READ, self.read)

    def read(self, conn: socket.socket):
        """
        this is called to read the data from any connection
        :param conn: socket connection
        :return: communicates back to the client if needed
        """
        data = conn.recv(Server.PACKET_SIZE)
        if data:
            try:
                # read the code from the header and send to the proper handler function
                req = protocol.RequestHeader()
                req.unpack(data)
                print(f"Received code: {req.code}")
                if req.code in self.requestHandler.keys():
                    result = self.requestHandler[req.code](conn, data)

                    # try to respond with 2107 if an error happened
                    if not result:
                        try:
                            response = protocol.ErrorResponse()
                            self.write(conn, response.pack())
                        except Exception as e:
                            print(f"failed to deliver exception message - {e}")
            except Exception as e:
                print(f"Exception while reading data from request - {e}")
        else:
            print("No data in connection")

        # closing things
        self.sel.unregister(conn)
        conn.close()

    def write(self, conn: socket.socket, data):
        """
        Write data to client
        :param conn: connection to write back to
        :param data: (bytes) a packed request based on the assignment protocol
        :return: True if sent, False if failed
        """
        size = len(data)
        sent = 0

        # in case data is somehow bigger than packet size (it shouldn't be), we send it in chunks
        while sent < size:
            send_size = min(size - sent, Server.PACKET_SIZE)
            send_data = data[sent:sent + send_size]

            # padding data with 0 until reached packet size
            if len(send_data) < Server.PACKET_SIZE:
                send_data += bytearray(Server.PACKET_SIZE - len(send_data))

            # try writing to client
            try:
                conn.send(send_data)
                sent += len(send_data)
            except:
                print(f"Failed to respond to {conn}")
                return False
        print("Response sent")
        return True

    def registration(self, conn: socket.socket, data):
        """
        CODE = 1100

        client wants to register for the server
        payload is the client name
        if client name is already taken, respond with 2101
        otherwise, register the client as a user with his own UUID and respond with 2100

        :param conn: connection to write back to
        :param data: Registration Request header + payload in bytes (packed)
        :return: (bool) succeeded?
        """
        try:
            request = protocol.RegistrationRequest()
            request.unpack(data)
            print(f"client trying to register as {request.name}")

            # check if name already registered:
            name_used = False
            for user in self.users:
                if user[1] == request.name:
                    name_used = True

            if not name_used:
                # username isn't taken. generate UUID and write him down
                user_id = uuid.uuid4()
                print(f"registration accepted. Generated UUID: {user_id.hex}")

                if not self.backup_db.query(f"INSERT INTO clients (ID, Name, LastSeen) VALUES (?, ?, ?)",
                                            [user_id.hex, request.name, str(datetime.now())]):
                    return False
                self.users.append((user_id.hex, request.name))

                # load data into a response and send it
                response = protocol.RegistrationResponse()  # 2100
                response.client_id = user_id.bytes
                response.header.payload_size = len(response.client_id)

                return self.write(conn, response.pack())
            else:
                # username already taken. send 2101
                response = protocol.RegistrationFailedResponse()
                return self.write(conn, response.pack())

        except Exception as e:
            # print and fall back on exception
            print(f"Exception in registration: {e}")
            return False

    def generate_keys(self, public_key, user_id):
        """
        inner function to generate AES session key
        and encrypt it using a public RSA key and

        :param public_key: public RSA key in base 64
        :param user_id: user id in hex
        :return: tuple - (encrypted session key, session key)
        """
        try:
            print(f"Generating session key for user {user_id}")

            # using Crypto (pycrypto) generate a random session key and encrypt it with public RSA key
            session_key = get_random_bytes(protocol.SYMMETRIC_KEY_SIZE)
            rsa_key = RSA.importKey(b64decode(public_key))
            rsa_cipher = PKCS1_OAEP.new(rsa_key)
            enc_session_key = rsa_cipher.encrypt(session_key)

            print(f"Public key is {public_key} \nSession key is {session_key.hex()}")
            return enc_session_key, session_key

        except Exception as e:
            print(f"Exception while generating keys {e}")
            return None

    def public_key_request(self, conn, data):
        """
        CODE = 1101

        a user is trying to start a new session with a new public key
        this can either be a user that wants to replace his public key, or just a new user
        payload is the client name + public key

        respond with 2102 containing the encrypted session key

        :param conn: connection to write back to
        :param data: Registration Request header + payload in bytes (packed)
        :return: (bool) succeeded?
        """
        try:
            # unpack the data from user
            request = protocol.PublicKeyRequest()
            request.unpack(data)

            user_id = request.header.client_id.hex()
            user_name = request.name
            pub_key = b64encode(request.public_key)

            # make sure user_id and username match the registered data
            if (user_id, user_name) not in self.users:
                return False

            # create an AES session key
            enc_session_key, session_key = self.generate_keys(pub_key, request.header.client_id.hex())

            # delete the old user data and insert the new data
            # this is basically like an update... I decided to divide the "half registered"
            # users from the fully registered ones so delete and insert seems more fitting
            self.backup_db.query(f"DELETE FROM clients WHERE ID = ? AND name = ?", [user_id, user_name])
            if not self.backup_db.query(f"INSERT INTO clients (ID, Name, PublicKey, LastSeen, AESKey) "
                                        f"VALUES (?, ?, ?, ?, ?)",
                                        [user_id, user_name, request.public_key, str(datetime.now()), session_key]):
                return False

            # load data into response and send it
            response = protocol.PublicKeyResponse()  # 2102
            response.client_id = request.header.client_id
            response.symmetric_key = enc_session_key
            response.header.payload_size = len(response.client_id) + len(response.symmetric_key)

            return self.write(conn, response.pack())

        except Exception as e:
            # print and fall back on exception
            print(f"Exception in public key request: {e}")
            return False

    def login_request(self, conn, data):
        """
        CODE = 1102

        a registered user is trying to log in
        need to make sure we have their details in the database before responding

        respond with 2105 containing the encrypted session key if all is good
        respond with 2106 with UUID if data is missing and user needs to register

        :param conn: connection to write back to
        :param data: Registration Request header + payload in bytes (packed)
        :return: (bool) succeeded?
        """
        try:
            # unpacking the data
            request = protocol.LoginRequest()
            request.unpack(data)
            user_id = request.header.client_id.hex()
            user_name = request.name

            # check if user is registered in the database
            query = self.backup_db.query_with_result(f"SELECT PublicKey FROM clients WHERE ID = ? AND Name = ?",
                                                     [user_id, user_name])
            if query:
                # if user is in database, we're all good to send 2105
                public_key = b64encode(query[0][0])

                # create session key
                enc_session_key, session_key = self.generate_keys(public_key, user_id)
                if not self.backup_db.query(f"UPDATE clients SET AESKey = ?, LastSeen = ? WHERE ID = ? AND Name = ?",
                                            [session_key, str(datetime.now()), user_id, user_name]):
                    return False

                # load data into response and send
                response = protocol.LoginResponse()  # 2105
                response.client_id = request.header.client_id
                response.symmetric_key = enc_session_key
                response.header.payload_size = protocol.CLIENT_ID_SIZE + len(response.symmetric_key)

                return self.write(conn, response.pack())
            else:
                # if no data found, we send 2106
                print(f"No data found for user {user_name}, {user_id} during login attempt. sending 2106")
                response = protocol.LoginFailedResponse()  # 2106
                response.client_id = request.header.client_id

                return self.write(conn, response.pack())

        except Exception as e:
            # print and fall back on exception
            print(f"Exception in login request: {e}")
            return False

    def send_checksum(self, conn, file_path, client_id, file_name):
        """
        "private" function to calculate and send the checksum
        this is seperated just in case we ever want to calculate and send the checksum in other functions

        :param conn: connection to write back to
        :param file_path: path to the file we're doing the checksum for
        :param client_id: client id that owns the file
        :param file_name: name of the actual file
        :return: (bool) succeeded?
        """
        try:
            # check the checksum
            cksum, content_size = checksum(str(file_path))
            print(f"check sum is {cksum}")

            # create and pack the response
            response = protocol.CRCResponse()  # 2103
            response.client_id = client_id
            response.content_size = content_size
            response.file_name = bytearray(file_name, 'utf-8')
            response.cksum = cksum

            response.header.payload_size = protocol.CLIENT_ID_SIZE + protocol.CONTENT_SIZE_SIZE
            response.header.payload_size += protocol.NAME_SIZE + protocol.CHECK_SUM_SIZE

            return self.write(conn, response.pack())
        except:
            # if an error happened, we fall back
            return False

    def file_request(self, conn, data):
        """
        CODE = 1103

        a registered user is trying to send a file
        the file should be encrypted using the most recent AES session key
        we want to decrypt it, save and return the details + CRC using 2103

        CRC is the error detecting code. a hashed version of the file data to make sure we (by very high probability)
        got the same file that the client sent us
        CRC is calculated in the same way it does in linux cksum command

        important note:
        this function can be very memory heavy
        that's because we're storing file data and there isn't really a limit on file size...
        I try to minimize it by writing to hard disk and not storing in memory for further use
        yet still the entire request is heavy...
        this can be optimized by decrypting and writing the file while reading the packets
        however, the code is already fairly messy and this will only complicate if further
        so for the current use, this should be fine.


        :param conn: connection to write back to
        :param data: Registration Request header + payload in bytes (packed)
        :return: (bool) succeeded?
        """
        try:
            # unpacking the data. because the file size can be very large,
            # we block other connections while reading and unpacking
            conn.setblocking(True)
            request = protocol.FileSendRequest()  # 1103
            request.unpack(conn, data)
            conn.setblocking(False)
            user_id_hex = request.header.client_id.hex()

            print(f"1103 request from user id is = {user_id_hex} \nFile name is {request.file_name} and size is {request.content_size}")

            # get AES key from db
            query = self.backup_db.query_with_result(f"SELECT AESKey FROM clients WHERE ID = ?",
                                                     [user_id_hex])
            if not query:
                print("Missing user session key for file decryption")
                return False

            session_key = query[0][0]

            # create a directory named after the user id (if non is there)
            path = os.path.join(Path().resolve(), user_id_hex)
            file_path = os.path.join(path, request.file_name)
            if not os.path.exists(user_id_hex):
                os.makedirs(path)

            # check if it's a file that's pending checksum result. in which case we need to check again
            if file_path not in self.pending_crc:
                # make sure user doesn't already have a file by this name another way to handle duplicate files is by
                # adding (1), (2) and so on.. but in that way we'll need to return the new name with the protocol
                # which as per my understanding of the assignment means changing the protocol,
                # and we're not allowed to do that
                if os.path.exists(file_path):
                    print(f"User already has a file by the name {request.file_name}")
                    return False
                self.pending_crc.append(file_path)
            else:
                # remove the file to rewrite it again before the checksum
                print(f"file path is {file_path}")
                os.remove(file_path)

            # decrypt file content
            iv = AES.block_size * b'\0'
            dec_bytes = b''
            for chunk in request.content:
                base64_chunk = b64encode(chunk)
                cipher = AES.new(session_key, AES.MODE_CBC, iv)
                dec_bytes += unpad(cipher.decrypt(b64decode(base64_chunk)), AES.block_size)

            # write the file
            # I'm writing it here and not after making sure the CRC is valid to not store everything in memory
            with open(file_path, "wb") as f:
                f.write(dec_bytes)

            # writing the file in database
            self.backup_db.query(f"INSERT INTO files (ID, FileName, FilePath, Verified) VALUES (?, ?, ?, ?)",
                                 [user_id_hex, request.file_name, file_path, 0])
            self.backup_db.query(f"UPDATE clients SET LastSeen = ? WHERE ID = ?",
                                 [str(datetime.now()), request.header.client_id.hex()])

            return self.send_checksum(conn, file_path, request.header.client_id, request.file_name)

        except Exception as e:
            print(f"Error while receiving file - {e}")
            return False

    def valid_crc(self, conn, data):
        """
        CODE = 1104

        the CRC we sent is valid!
        meaning we can change the status inside the database and remove from pending list

        respond with 2104

        :param conn: connection to write back to
        :param data: Registration Request header + payload in bytes (packed)
        :return: (bool) succeeded?
        """
        try:
            request = protocol.ValidCRCRequest()  # 1104
            request.unpack(data)
            file_name = request.file_name
            user_id = request.header.client_id.hex()

            print(f"CRC is VALID for file {file_name} by user {user_id}")

            # update db (and make sure it worked)
            db_flag_1 = self.backup_db.query(f"UPDATE clients SET LastSeen = ? WHERE ID = ?",
                                             [str(datetime.now()), user_id])
            db_flag_2 = self.backup_db.query(f"UPDATE files SET Verified = ? WHERE ID = ? AND fileName = ?",
                                             [1, user_id, file_name])
            if not db_flag_1 or not db_flag_2:
                return False

            # remove from pending list
            file_path = os.path.join(Path().resolve(), user_id, file_name)
            self.pending_crc.remove(file_path)

            # create and pack the response
            response = protocol.GenericResponse()  # 2104
            response.client_id = request.header.client_id
            return self.write(conn, response.pack())

        except Exception as e:
            print(f"Exception in valid CRC - {e}")
            return False

    def wrong_crc(self, conn, data):
        """
        CODE = 1105

        the CRC we sent is wrong.
        that means we should get a new file request from the user

        not responding with anything (unless 2107), but note that this should only happen 3 times
        I didn't add any checks for that from server side
        mainly because there's nothing stopping the client from sending more files or requests


        :param conn: connection to write back to
        :param data: Registration Request header + payload in bytes (packed)
        :return: (bool) succeeded?
        """
        try:
            request = protocol.WarningCRCRequest()  # 1105
            request.unpack(data)
            user_id = request.header.client_id.hex()
            file_name = request.file_name

            print(f"CRC is WRONG for file {file_name} by user {user_id}")

            # update last seen
            if not self.backup_db.query(f"UPDATE clients SET LastSeen = ? WHERE ID = ?",
                                        [str(datetime.now()), user_id]):
                return False
            return True
        except Exception as e:
            print(f"Exception in failed CRC - {e}")
            return False

    def failed_crc(self, conn, data):
        """
        CODE = 1106

        the CRC we sent is wrong, and we failed the 3 checks
        meaning we should remove the file from directory and pending list

        respond with 2104

        :param conn: connection to write back to
        :param data: Registration Request header + payload in bytes (packed)
        :return: (bool) succeeded?
        """
        try:
            request = protocol.ErrorCRCRequest()  # 1106
            request.unpack(data)

            file_name = request.file_name
            user_id = request.header.client_id.hex()

            print(f"CRC is WRONG. Checksum failed for file {file_name} by user {user_id}")

            db_flag_1 = self.backup_db.query(f"UPDATE clients SET LastSeen = ? WHERE ID = ?",
                                             [str(datetime.now()), user_id])
            query = self.backup_db.query_with_result(f"SELECT FilePath FROM files WHERE ID = ? AND fileName = ?",
                                                     [user_id, file_name])
            # no need to keep the file
            db_flag_2 = self.backup_db.query(f"DELETE FROM files WHERE ID = ? AND fileName = ?",
                                             [user_id, file_name])

            if not db_flag_1 or not db_flag_2 or not query:
                return False
            file_path = query[0][0]

            # TODO: validate that this is safe and we're not deleting anything important
            # it should be because it's ID based but it's always good to double check
            print(f"file path is {file_path}")
            os.remove(file_path)
            self.pending_crc.remove(file_path)

            # pack and send response
            response = protocol.GenericResponse()  # 2104
            response.client_id = request.header.client_id
            return self.write(conn, response.pack())

        except Exception as e:
            print(f"Exception in failed CRC - {e}")
            return False
