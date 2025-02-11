import socket
import struct
import threading
import hashlib
import re
import fnmatch
from collections import defaultdict
import time
import logging
from config import Config

# Configure logging
logging.basicConfig(
    filename="server.log",  # Change to None to print to console instead
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

class CustomWireProtocol:
    """
    Custom wire protocol for message encoding and decoding.
    Message format:
    - 4 bytes: Total message length
    - 2 bytes: Command type (unsigned short)
    - Remaining bytes: Payload
    """
    # Command type constants
    CMD_CREATE = 1
    CMD_LOGIN = 2
    CMD_LIST = 3
    CMD_SEND = 4
    CMD_GET_MESSAGES = 5
    CMD_GET_UNDELIVERED = 6
    CMD_DELETE_MESSAGES = 7
    CMD_DELETE_ACCOUNT = 8
    CMD_LOGOUT = 9

    @staticmethod
    def encode_message(cmd, payload):
        """
        Encode a message for transmission
        payload should be bytes
        """
        # Ensure payload is bytes
        if not isinstance(payload, bytes):
            payload = payload.encode('utf-8')
        
        # Pack total length (4 bytes), command (2 bytes), then payload
        header = struct.pack('!IH', len(payload) + 6, cmd)
        return header + payload

    @staticmethod
    def decode_message(data):
        """
        Decode an incoming message
        Returns (total_length, command, payload)
        """
        total_length, cmd = struct.unpack('!IH', data[:6])
        payload = data[6:total_length]
        return total_length, cmd, payload

    @staticmethod
    def encode_string(s):
        """Encode a string with length prefix"""
        encoded = s.encode('utf-8')
        return struct.pack('!H', len(encoded)) + encoded

    @staticmethod
    def decode_string(data):
        """Decode a length-prefixed string"""
        length = struct.unpack('!H', data[:2])[0]
        return data[2:2+length].decode('utf-8'), data[2+length:]

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
        self.protocol = CustomWireProtocol()

    def hash_password(self, password):
        """Hash password using SHA-256."""
        return hashlib.sha256(password.encode()).hexdigest()

    def validate_password(self, password):
        """Ensure password meets minimum requirements."""
        if len(password) < 8:
            return False
        if not re.search(r"\d", password):
            return False
        if not re.search(r"[A-Z]", password):
            return False
        return True

    def send_response(self, client_socket, success, message=None, additional_data=None):
        """
        Send a structured response using custom wire protocol
        """
        # Prepare response payload
        payload_parts = []
        
        # Success flag (1 byte)
        payload_parts.append(struct.pack('!?', success))
        
        # Optional message
        if message:
            payload_parts.append(self.protocol.encode_string(message))
        else:
            payload_parts.append(struct.pack('!H', 0))  # Zero-length string
        
        # Additional data handling (if needed)
        if additional_data:
            # Serialize additional data as needed
            # This is a placeholder and would need to be implemented based on specific requirements
            pass
        
        # Combine payload parts
        payload = b''.join(payload_parts)
        
        # Send encoded message
        client_socket.send(self.protocol.encode_message(
            CustomWireProtocol.CMD_LOGIN,  # Using login as generic response command
            payload
        ))

    def handle_client(self, client_socket, address):
        logging.info(f"New connection from {address}")
        current_user = None
        buffer = b''

        while True:
            try:
                # Receive data
                chunk = client_socket.recv(4096)
                if not chunk:
                    break
                
                buffer += chunk

                # Process complete messages
                while len(buffer) >= 6:
                    # Peek at message length
                    total_length = struct.unpack('!I', buffer[:4])[0]
                    
                    # Check if we have a complete message
                    if len(buffer) < total_length:
                        break
                    
                    # Extract full message
                    message_data = buffer[:total_length]
                    buffer = buffer[total_length:]

                    # Decode message
                    _, cmd, payload = self.protocol.decode_message(message_data)

                    # Process different command types
                    with self.lock:
                        if cmd == CustomWireProtocol.CMD_CREATE:
                            # Decode username and password
                            username, payload = self.protocol.decode_string(payload)
                            password, _ = self.protocol.decode_string(payload)

                            if not username or not password:
                                self.send_response(client_socket, False, "Username and password required")
                                continue

                            if not self.validate_password(password):
                                self.send_response(client_socket, False, 
                                    "Password must be at least 8 characters with 1 number and 1 uppercase letter")
                                continue

                            if username in self.users:
                                self.send_response(client_socket, False, "Username already exists")
                                continue

                            # Create account
                            self.users[username] = (self.hash_password(password), {})
                            self.messages[username] = []
                            logging.info(f"New account created: {username} from {address}")
                            
                            # Send success response
                            self.send_response(client_socket, True, "Account created successfully")

                        elif cmd == CustomWireProtocol.CMD_LOGIN:
                            # Decode username and password
                            username, payload = self.protocol.decode_string(payload)
                            password, _ = self.protocol.decode_string(payload)

                            if username not in self.users:
                                self.send_response(client_socket, False, "User not found")
                                continue

                            if self.users[username][0] != self.hash_password(password):
                                self.send_response(client_socket, False, "Invalid password")
                                continue

                            if username in self.active_users:
                                self.send_response(client_socket, False, "User already logged in")
                                continue

                            # Successful login
                            current_user = username
                            self.active_users[username] = client_socket
                            
                            # Send login success response
                            self.send_response(client_socket, True, "Login successful")

                        elif cmd == CustomWireProtocol.CMD_SEND:
                            if not current_user:
                                self.send_response(client_socket, False, "Not logged in")
                                continue

                            # Decode recipient and message content
                            recipient, payload = self.protocol.decode_string(payload)
                            content, _ = self.protocol.decode_string(payload)

                            if recipient not in self.users:
                                self.send_response(client_socket, False, "Recipient not found")
                                continue

                            # Create and store message
                            message = {
                                "id": self.message_id_counter,
                                "from": current_user,
                                "content": content,
                                "timestamp": time.time(),
                                "read": False,
                                "delivered_while_offline": recipient not in self.active_users
                            }
                            self.message_id_counter += 1
                            self.messages[recipient].append(message)
                            
                            # Send success response
                            self.send_response(client_socket, True, "Message sent")

                        elif cmd == CustomWireProtocol.CMD_LOGOUT:
                            if not current_user:
                                self.send_response(client_socket, False, "Not logged in")
                                continue

                            # Remove from active users
                            if current_user in self.active_users:
                                del self.active_users[current_user]

                            logging.info(f"User '{current_user}' logged out")
                            current_user = None
                            
                            # Send logout success response
                            self.send_response(client_socket, True, "Logged out successfully")

                        # Add other command handlers similarly...

            except Exception as e:
                logging.error(f"Error handling client: {e}")
                break

        # Handle disconnection
        if current_user in self.active_users:
            del self.active_users[current_user]
        
        client_socket.close()

    def start(self):
        # Find next available port
        try:
            self.port = self.find_free_port(self.port)
            config = Config()
            config.update("port", self.port)
        except RuntimeError as e:
            print(f"Server error: {e}")
            return

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.settimeout(1)

        try:
            self.server.bind((self.host, self.port))
            self.server.listen(5)
            self.running = True
            print(f"Server started on {self.host}:{self.port}")

            while self.running:
                try:
                    client_socket, address = self.server.accept()
                    client_socket.settimeout(None)
                    threading.Thread(target=self.handle_client, 
                                    args=(client_socket, address), 
                                    daemon=True).start()
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"Error accepting connection: {e}")
                    continue
        finally:
            self.server.close()

    def stop(self):
        self.running = False
        if self.server:
            self.server.close()

    def find_free_port(self, start_port):
        port = start_port
        max_port = 65535
        
        while port <= max_port:
            try:
                test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                test_socket.bind((self.host, port))
                test_socket.close()
                return port
            except OSError:
                port += 1
            finally:
                test_socket.close()
        raise RuntimeError("No free ports available")

if __name__ == "__main__":
    server = ChatServer()
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.stop()