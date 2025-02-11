import socket
import threading
import hashlib
import re
import fnmatch
from collections import defaultdict
import time
import struct
import logging
from config import Config

# Configure logging
logging.basicConfig(
    filename="server.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

class MessageType:
    CREATE_ACCOUNT = 1
    LOGIN = 2
    LIST_ACCOUNTS = 3
    SEND_MESSAGE = 4
    GET_MESSAGES = 5
    GET_UNDELIVERED = 6
    DELETE_MESSAGES = 7
    DELETE_ACCOUNT = 8
    LOGOUT = 9
    RESPONSE = 10

class WireProtocolServer:
    def __init__(self, host=None, port=None):
        # Clear log file on server restart
        open("server.log", "w").close()

        self.config = Config()
        self.host = self.config.get("host")
        self.port = self.config.get("port")
        self.users = {}  # username -> (password_hash, settings)
        self.messages = defaultdict(list)  # username -> [messages]
        self.active_users = {}  # username -> connection
        self.message_id_counter = 0
        self.lock = threading.Lock()
        self.server = None
        self.running = False

    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def validate_password(self, password):
        if len(password) < 8:
            return False
        if not re.search(r"\d", password):
            return False
        if not re.search(r"[A-Z]", password):
            return False
        return True

    def pack_message(self, msg_type, success, data=""):
        """Pack message into binary format"""
        data_bytes = data.encode() if isinstance(data, str) else data
        header = struct.pack("!BBI", msg_type, 1 if success else 0, len(data_bytes))
        return header + data_bytes

    def unpack_message(self, data):
        """Unpack binary message"""
        msg_type, success, length = struct.unpack("!BBI", data[:6])
        payload = data[6:6+length].decode() if length > 0 else ""
        return msg_type, bool(success), payload

    def send_response(self, client_socket, success, message=""):
        """Send response to client"""
        response = self.pack_message(MessageType.RESPONSE, success, message)
        client_socket.send(response)

    def handle_client(self, client_socket, address):
        logging.info(f"New connection from {address}")
        current_user = None
        message_buffer = b""

        while True:
            try:
                # Receive header first
                header = client_socket.recv(6)
                if not header or len(header) < 6:
                    break

                msg_type, _, length = struct.unpack("!BBI", header)
                
                # Receive payload if any
                payload = b""
                while length > 0:
                    chunk = client_socket.recv(min(length, 4096))
                    if not chunk:
                        break
                    payload += chunk
                    length -= len(chunk)

                if length > 0:  # Incomplete message
                    break

                payload = payload.decode() if payload else ""

                with self.lock:
                    if msg_type == MessageType.CREATE_ACCOUNT:
                        username, password = payload.split(":", 1)
                        if not username or not password:
                            self.send_response(client_socket, False, "Username and password required")
                        elif not self.validate_password(password):
                            self.send_response(client_socket, False, 
                                "Password must be at least 8 characters with 1 number and 1 uppercase letter")
                        elif username in self.users:
                            self.send_response(client_socket, False, "Username already exists")
                        else:
                            self.users[username] = (self.hash_password(password), {})
                            self.messages[username] = []
                            self.send_response(client_socket, True, "Account created successfully")

                    elif msg_type == MessageType.LOGIN:
                        username, password = payload.split(":", 1)
                        if username not in self.users:
                            self.send_response(client_socket, False, "User not found")
                        elif self.users[username][0] != self.hash_password(password):
                            self.send_response(client_socket, False, "Invalid password")
                        elif username in self.active_users:
                            self.send_response(client_socket, False, "User already logged in")
                        else:
                            current_user = username
                            self.active_users[username] = client_socket
                            unread_count = len([msg for msg in self.messages[username] if not msg["read"]])
                            response_data = f"{username}:{unread_count}"
                            self.send_response(client_socket, True, response_data)

                    elif msg_type == MessageType.LIST_ACCOUNTS:
                        pattern = payload or "*"
                        matches = []
                        for username in self.users:
                            if fnmatch.fnmatch(username.lower(), pattern.lower()):
                                status = "online" if username in self.active_users else "offline"
                                matches.append(f"{username}:{status}")
                        self.send_response(client_socket, True, "|".join(matches))

                    elif msg_type == MessageType.SEND_MESSAGE:
                        if not current_user:
                            self.send_response(client_socket, False, "Not logged in")
                        else:
                            recipient, content = payload.split(":", 1)
                            if recipient not in self.users:
                                self.send_response(client_socket, False, "Recipient not found")
                            else:
                                message = {
                                    "id": self.message_id_counter,
                                    "from": current_user,
                                    "content": content,
                                    "timestamp": time.time(),
                                    "read": False
                                }
                                self.message_id_counter += 1
                                self.messages[recipient].append(message)
                                
                                if recipient in self.active_users:
                                    try:
                                        msg_data = f"{message['from']}:{message['content']}"
                                        response = self.pack_message(MessageType.SEND_MESSAGE, True, msg_data)
                                        self.active_users[recipient].send(response)
                                    except:
                                        pass

                                self.send_response(client_socket, True, "Message sent")

                    elif msg_type == MessageType.GET_MESSAGES:
                        if not current_user:
                            self.send_response(client_socket, False, "Not logged in")
                        else:
                            count = int(payload) if payload else self.config.get("message_fetch_limit")
                            messages = []
                            for msg in sorted(self.messages[current_user], 
                                           key=lambda x: x["timestamp"], 
                                           reverse=True)[:count]:
                                msg_str = f"{msg['id']}:{msg['from']}:{msg['content']}:{msg['timestamp']}"
                                messages.append(msg_str)
                            self.send_response(client_socket, True, "|".join(messages))

                    elif msg_type == MessageType.DELETE_MESSAGES:
                        if not current_user:
                            self.send_response(client_socket, False, "Not logged in")
                        else:
                            msg_ids = set(int(x) for x in payload.split(","))
                            self.messages[current_user] = [
                                m for m in self.messages[current_user] 
                                if m["id"] not in msg_ids
                            ]
                            self.send_response(client_socket, True, "Messages deleted")

                    elif msg_type == MessageType.DELETE_ACCOUNT:
                        if not current_user:
                            self.send_response(client_socket, False, "Not logged in")
                        else:
                            password = payload
                            if self.users[current_user][0] != self.hash_password(password):
                                self.send_response(client_socket, False, "Invalid password")
                            else:
                                del self.users[current_user]
                                del self.messages[current_user]
                                if current_user in self.active_users:
                                    del self.active_users[current_user]
                                current_user = None
                                self.send_response(client_socket, True, "Account deleted")

                    elif msg_type == MessageType.LOGOUT:
                        if not current_user:
                            self.send_response(client_socket, False, "Not logged in")
                        else:
                            if current_user in self.active_users:
                                del self.active_users[current_user]
                            current_user = None
                            self.send_response(client_socket, True, "Logged out successfully")

            except Exception as e:
                logging.error(f"Error handling client: {e}")
                break

        if current_user in self.active_users:
            del self.active_users[current_user]
        
        client_socket.close()

    def start(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((self.host, self.port))
        self.server.listen(5)
        self.running = True
        print(f"Server started on {self.host}:{self.port}")

        while self.running:
            try:
                client_socket, address = self.server.accept()
                threading.Thread(target=self.handle_client, 
                              args=(client_socket, address),
                              daemon=True).start()
            except Exception as e:
                print(f"Error accepting connection: {e}")
                if not self.running:
                    break

    def stop(self):
        self.running = False
        if self.server:
            self.server.close()

if __name__ == "__main__":
    server = WireProtocolServer()
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.stop()