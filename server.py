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

# Control characters for message separation
UNIT_SEP = b'\x1F'  # Separates major fields
RECORD_SEP = b'\x1E'  # Separates multiple records
GROUP_SEP = b'\x1D'  # Separates subfields

class MessageType:
    CREATE_ACCOUNT = 0x01
    LOGIN = 0x02
    LIST_ACCOUNTS = 0x03
    SEND_MESSAGE = 0x04
    GET_MESSAGES = 0x05
    GET_UNDELIVERED = 0x06
    DELETE_MESSAGES = 0x07
    DELETE_ACCOUNT = 0x08
    LOGOUT = 0x09
    NOTIFICATION = 0x0A

class ChatServer:
    def __init__(self, host=None, port=None):
        # Clear log file on server restart
        open("server.log", "w").close()

        self.config = Config()
        self.host = host or self.config.get("host")
        self.port = port or self.config.get("port")
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

    def pack_message(self, msg_type, success, payload=b""):
        """Pack message into binary format with header"""
        if isinstance(payload, str):
            payload = payload.encode()
        version = 0x01  # Protocol version 1
        header = struct.pack("!BBBI", version, msg_type, success, len(payload))
        return header + payload

    def handle_client(self, client_socket, address):
        logging.info(f"New connection from {address}")
        current_user = None

        try:
            while True:
                try:
                    # First read exactly 7 bytes for the header
                    header = client_socket.recv(7)
                    if not header:
                        logging.info(f"Client {address} disconnected")
                        break
                    if len(header) != 7:
                        logging.error(f"Invalid header length from {address}")
                        break

                    # Parse header
                    version, msg_type, success, length = struct.unpack("!BBBI", header)
                    logging.debug(f"Received message type {msg_type} from {address}")

                    # Read payload if any
                    payload = b""
                    remaining = length
                    while remaining > 0:
                        chunk = client_socket.recv(min(remaining, 4096))
                        if not chunk:
                            logging.error(f"Connection closed by {address} while reading payload")
                            return
                        payload += chunk
                        remaining -= len(chunk)

                    response = None
                    with self.lock:
                        if msg_type == MessageType.CREATE_ACCOUNT:
                            username, password = payload.split(UNIT_SEP)
                            username = username.decode()
                            password = password.decode()
                            
                            if not username or not password:
                                response = self.pack_message(msg_type, 0, "Username and password required")
                            elif not self.validate_password(password):
                                response = self.pack_message(msg_type, 0, 
                                    "Password must be at least 8 characters with 1 number and 1 uppercase letter")
                            elif username in self.users:
                                response = self.pack_message(msg_type, 0, "Username already exists")
                            else:
                                self.users[username] = (self.hash_password(password), {})
                                self.messages[username] = []
                                response = self.pack_message(msg_type, 1, "Account created successfully")

                        elif msg_type == MessageType.LOGIN:
                            username, password = payload.split(UNIT_SEP)
                            username = username.decode()
                            password = password.decode()
                            
                            if username not in self.users:
                                response = self.pack_message(msg_type, 0, "User not found")
                            elif self.users[username][0] != self.hash_password(password):
                                response = self.pack_message(msg_type, 0, "Invalid password")
                            elif username in self.active_users:
                                response = self.pack_message(msg_type, 0, "User already logged in")
                            else:
                                current_user = username
                                self.active_users[username] = client_socket
                                unread_count = len([msg for msg in self.messages[username] if not msg["read"]])
                                response_data = f"{username}{UNIT_SEP.decode()}{unread_count}"
                                response = self.pack_message(msg_type, 1, response_data)
                                logging.info(f"User {username} logged in from {address}")

                        elif msg_type == MessageType.LIST_ACCOUNTS:
                            pattern = payload.decode() if payload else "*"
                            matches = []
                            for username in self.users:
                                if fnmatch.fnmatch(username.lower(), pattern.lower()):
                                    status = "online" if username in self.active_users else "offline"
                                    matches.append(f"{username}{GROUP_SEP.decode()}{status}")
                            
                            response_data = RECORD_SEP.decode().join(matches) if matches else ""
                            response = self.pack_message(msg_type, 1, response_data)
                            logging.debug(f"Sent user list to {address}")

                        elif msg_type == MessageType.SEND_MESSAGE:
                            if not current_user:
                                response = self.pack_message(msg_type, 0, "Not logged in")
                            else:
                                recipient, content = payload.split(UNIT_SEP, 1)
                                recipient = recipient.decode()
                                content = content.decode()
                                
                                if recipient not in self.users:
                                    response = self.pack_message(msg_type, 0, "Recipient not found")
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
                                            # Create a properly formatted notification
                                            notification = (f"{current_user}{GROUP_SEP.decode()}"
                                                         f"{content}")
                                            notify_msg = self.pack_message(MessageType.NOTIFICATION, 1, notification)
                                            self.active_users[recipient].send(notify_msg)
                                            logging.info(f"Notification sent to {recipient}")
                                        except Exception as e:
                                            logging.error(f"Failed to notify {recipient}: {e}")
                                            # Don't break on notification failure
                                    
                                    response = self.pack_message(msg_type, 1, "Message sent")

                        elif msg_type == MessageType.GET_MESSAGES:
                            if not current_user:
                                response = self.pack_message(msg_type, 0, "Not logged in")
                            else:
                                count = int(payload.decode()) if payload else self.config.get("message_fetch_limit")
                                messages = []
                                sorted_messages = sorted(self.messages[current_user], 
                                                      key=lambda x: x["timestamp"], 
                                                      reverse=True)
                                for msg in sorted_messages[:count]:
                                    msg_str = (f"{msg['id']}{GROUP_SEP.decode()}"
                                             f"{msg['from']}{GROUP_SEP.decode()}"
                                             f"{msg['content']}{GROUP_SEP.decode()}"
                                             f"{msg['timestamp']}")
                                    messages.append(msg_str)
                                    msg["read"] = True
                                
                                response = self.pack_message(msg_type, 1, RECORD_SEP.decode().join(messages))

                        elif msg_type == MessageType.GET_UNDELIVERED:
                            if not current_user:
                                response = self.pack_message(msg_type, 0, "Not logged in")
                            else:
                                count = int(payload.decode()) if payload else self.config.get("message_fetch_limit")
                                unread_messages = [m for m in self.messages[current_user] if not m["read"]]
                                messages = []
                                for msg in sorted(unread_messages, 
                                               key=lambda x: x["timestamp"], 
                                               reverse=True)[:count]:
                                    msg_str = (f"{msg['id']}{GROUP_SEP.decode()}"
                                             f"{msg['from']}{GROUP_SEP.decode()}"
                                             f"{msg['content']}{GROUP_SEP.decode()}"
                                             f"{msg['timestamp']}")
                                    messages.append(msg_str)
                                    msg["read"] = True
                                
                                response = self.pack_message(msg_type, 1, RECORD_SEP.decode().join(messages))

                        elif msg_type == MessageType.DELETE_MESSAGES:
                            if not current_user:
                                response = self.pack_message(msg_type, 0, "Not logged in")
                            else:
                                msg_ids = set(int(x) for x in payload.decode().split(GROUP_SEP.decode()))
                                self.messages[current_user] = [
                                    m for m in self.messages[current_user] 
                                    if m["id"] not in msg_ids
                                ]
                                response = self.pack_message(msg_type, 1, "Messages deleted")

                        elif msg_type == MessageType.DELETE_ACCOUNT:
                            if not current_user:
                                response = self.pack_message(msg_type, 0, "Not logged in")
                            else:
                                password = payload.decode()
                                if self.users[current_user][0] != self.hash_password(password):
                                    response = self.pack_message(msg_type, 0, "Invalid password")
                                else:
                                    del self.users[current_user]
                                    del self.messages[current_user]
                                    if current_user in self.active_users:
                                        del self.active_users[current_user]
                                    current_user = None
                                    response = self.pack_message(msg_type, 1, "Account deleted")

                        elif msg_type == MessageType.LOGOUT:
                            if not current_user:
                                response = self.pack_message(msg_type, 0, "Not logged in")
                            else:
                                if current_user in self.active_users:
                                    del self.active_users[current_user]
                                current_user = None
                                response = self.pack_message(msg_type, 1, "Logged out successfully")

                        # Send response
                        if response is not None:
                            try:
                                client_socket.send(response)
                            except Exception as e:
                                logging.error(f"Failed to send response to {address}: {e}")
                                break

                except ConnectionError as e:
                    logging.error(f"Connection error for {address}: {e}")
                    break
                except Exception as e:
                    logging.error(f"Error handling message from {address}: {e}")
                    try:
                        error_response = self.pack_message(msg_type, 0, f"Server error: {str(e)}")
                        client_socket.send(error_response)
                    except:
                        break
                    continue

        finally:
            if current_user in self.active_users:
                del self.active_users[current_user]
                logging.info(f"User {current_user} disconnected")
            try:
                client_socket.close()
            except:
                pass
            logging.info(f"Connection closed for {address}")

    def start(self):
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server.bind((self.host, self.port))
            self.server.listen(5)
            self.running = True
            logging.info(f"Server started on {self.host}:{self.port}")
            print(f"Server started on {self.host}:{self.port}")

            while self.running:
                try:
                    client_socket, address = self.server.accept()
                    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                    # Start a new thread for each client
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, address),
                        daemon=True
                    )
                    client_thread.start()
                    logging.info(f"New client thread started for {address}")
                except Exception as e:
                    logging.error(f"Error accepting connection: {e}")
                    if not self.running:
                        break
                    continue

        except Exception as e:
            logging.error(f"Server error: {e}")
            print(f"Server error: {e}")
        finally:
            self.running = False
            try:
                self.server.close()
            except:
                pass
            logging.info("Server stopped")

    def stop(self):
        self.running = False
        if self.server:
            self.server.close()

if __name__ == "__main__":
    server = ChatServer()
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.stop()