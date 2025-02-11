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
from wire_protocol import Message, send_message

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
        """Handle client connection with improved wire protocol"""
        logging.info(f"New connection from {address}")
        current_user = None

        while True:
            try:
                # Receive a complete message
                message = Message.receive_message(client_socket)
                if not message:
                    break
                    
                payload = message.get_payload_string()
                
                with self.lock:
                    if message.msg_type == MessageType.CREATE_ACCOUNT:
                        if ":" not in payload:
                            send_message(client_socket, MessageType.RESPONSE, False, 
                                    "Invalid message format")
                            continue
                            
                        username, password = payload.split(":", 1)
                        if not username or not password:
                            send_message(client_socket, MessageType.RESPONSE, False,
                                    "Username and password required")
                        elif not self.validate_password(password):
                            send_message(client_socket, MessageType.RESPONSE, False,
                                "Password must be at least 8 characters with 1 number and 1 uppercase letter")
                        elif username in self.users:
                            send_message(client_socket, MessageType.RESPONSE, False,
                                    "Username already exists")
                        else:
                            self.users[username] = (self.hash_password(password), {})
                            self.messages[username] = []
                            logging.info(f"New account created: {username} from {address}")
                            send_message(client_socket, MessageType.RESPONSE, True,
                                    "Account created successfully")

                    elif message.msg_type == MessageType.LOGIN:
                        if ":" not in payload:
                            send_message(client_socket, MessageType.RESPONSE, False,
                                    "Invalid message format")
                            continue
                            
                        username, password = payload.split(":", 1)
                        if username not in self.users:
                            logging.warning(f"Failed login attempt from {address}: User '{username}' not found")
                            send_message(client_socket, MessageType.RESPONSE, False,
                                    "User not found")
                        elif self.users[username][0] != self.hash_password(password):
                            logging.warning(f"Failed login attempt from {address}: Incorrect password for '{username}'")
                            send_message(client_socket, MessageType.RESPONSE, False,
                                    "Invalid password")
                        elif username in self.active_users:
                            logging.warning(f"Failed login attempt from {address}: '{username}' already logged in")
                            send_message(client_socket, MessageType.RESPONSE, False,
                                    "User already logged in")
                        else:
                            current_user = username
                            self.active_users[username] = client_socket
                            unread_count = len([msg for msg in self.messages[username] 
                                            if not msg["read"]])
                            logging.info(f"User '{username}' logged in from {address}")
                            send_message(client_socket, MessageType.RESPONSE, True,
                                    f"{username}:{unread_count}")

                    elif message.msg_type == MessageType.LIST_ACCOUNTS:
                        pattern = payload or "*"
                        if not pattern.endswith("*"):
                            pattern = pattern + "*"
                            
                        matches = []
                        for username in self.users:
                            if fnmatch.fnmatch(username.lower(), pattern.lower()):
                                status = "online" if username in self.active_users else "offline"
                                matches.append(f"{username}:{status}")
                        
                        logging.info(f"User list requested from {address}, found {len(matches)} users")
                        send_message(client_socket, MessageType.RESPONSE, True,
                                "|".join(matches))

                    elif message.msg_type == MessageType.SEND_MESSAGE:
                        if not current_user:
                            send_message(client_socket, MessageType.RESPONSE, False,
                                    "Not logged in")
                        else:
                            if ":" not in payload:
                                send_message(client_socket, MessageType.RESPONSE, False,
                                        "Invalid message format")
                                continue
                                
                            recipient, content = payload.split(":", 1)
                            if recipient not in self.users:
                                logging.warning(f"Message failed: '{recipient}' does not exist (from {current_user})")
                                send_message(client_socket, MessageType.RESPONSE, False,
                                        "Recipient not found")
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
                                
                                # If recipient is active, send immediately
                                if recipient in self.active_users:
                                    try:
                                        msg_data = f"{message['from']}:{message['content']}"
                                        send_message(self.active_users[recipient],
                                                MessageType.SEND_MESSAGE,
                                                True, msg_data)
                                    except:
                                        pass  # Ignore delivery failure

                                logging.info(f"Message sent from '{current_user}' to '{recipient}'")
                                send_message(client_socket, MessageType.RESPONSE, True,
                                        "Message sent")

                    elif message.msg_type == MessageType.GET_MESSAGES:
                        if not current_user:
                            send_message(client_socket, MessageType.RESPONSE, False,
                                    "Not logged in")
                        else:
                            count = int(payload) if payload else self.config.get("message_fetch_limit")
                            messages = []
                            for msg in sorted(self.messages[current_user],
                                            key=lambda x: x["timestamp"],
                                            reverse=True)[:count]:
                                msg_str = f"{msg['id']}:{msg['from']}:{msg['content']}:{msg['timestamp']}"
                                messages.append(msg_str)
                                msg["read"] = True
                            
                            logging.info(f"User '{current_user}' retrieved {len(messages)} messages")
                            send_message(client_socket, MessageType.RESPONSE, True,
                                    "|".join(messages))

                    elif message.msg_type == MessageType.GET_UNDELIVERED:
                        if not current_user:
                            send_message(client_socket, MessageType.RESPONSE, False,
                                    "Not logged in")
                        else:
                            count = int(payload) if payload else self.config.get("message_fetch_limit")
                            unread = []
                            for msg in sorted(
                                [m for m in self.messages[current_user] if not m["read"]],
                                key=lambda x: x["timestamp"],
                                reverse=True
                            )[:count]:
                                msg_str = f"{msg['id']}:{msg['from']}:{msg['content']}:{msg['timestamp']}"
                                unread.append(msg_str)
                                msg["read"] = True
                            
                            logging.info(f"User '{current_user}' retrieved {len(unread)} unread messages")
                            send_message(client_socket, MessageType.RESPONSE, True,
                                    "|".join(unread))

                    elif message.msg_type == MessageType.DELETE_MESSAGES:
                        if not current_user:
                            send_message(client_socket, MessageType.RESPONSE, False,
                                    "Not logged in")
                        else:
                            msg_ids = set(int(x) for x in payload.split(","))
                            self.messages[current_user] = [
                                m for m in self.messages[current_user]
                                if m["id"] not in msg_ids
                            ]
                            
                            logging.info(f"User '{current_user}' deleted {len(msg_ids)} messages")
                            send_message(client_socket, MessageType.RESPONSE, True,
                                    "Messages deleted")

                    elif message.msg_type == MessageType.DELETE_ACCOUNT:
                        if not current_user:
                            send_message(client_socket, MessageType.RESPONSE, False,
                                    "Not logged in")
                        else:
                            password = payload
                            if self.users[current_user][0] != self.hash_password(password):
                                logging.warning(f"Failed account deletion for {current_user} - Incorrect password")
                                send_message(client_socket, MessageType.RESPONSE, False,
                                        "Invalid password")
                            else:
                                del self.users[current_user]
                                del self.messages[current_user]
                                if current_user in self.active_users:
                                    del self.active_users[current_user]
                                
                                logging.info(f"Account deleted: {current_user}")
                                current_user = None
                                send_message(client_socket, MessageType.RESPONSE, True,
                                        "Account deleted")

                    elif message.msg_type == MessageType.LOGOUT:
                        if not current_user:
                            send_message(client_socket, MessageType.RESPONSE, False,
                                    "Not logged in")
                        else:
                            if current_user in self.active_users:
                                del self.active_users[current_user]
                            
                            logging.info(f"User '{current_user}' logged out")
                            current_user = None
                            send_message(client_socket, MessageType.RESPONSE, True,
                                    "Logged out successfully")

            except Exception as e:
                logging.error(f"Error handling client {address}: {e}")
                break

        # Cleanup on disconnect
        if current_user and current_user in self.active_users:
            del self.active_users[current_user]
            logging.info(f"User '{current_user}' disconnected")
        
        try:
            client_socket.close()
        except:
            pass
        
        logging.info(f"Connection closed for {address}")

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