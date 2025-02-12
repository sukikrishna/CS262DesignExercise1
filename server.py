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
    def encode_message(cmd, payload_parts):
        """
        Encode a message for transmission
        payload_parts should be a list of various types to be encoded
        """
        # Encode each payload part
        encoded_payload = []
        for part in payload_parts:
            if part is None:
                continue
            if isinstance(part, str):
                # Encode string with length prefix (2 bytes for length)
                encoded_str = part.encode('utf-8')
                encoded_payload.append(struct.pack('!H', len(encoded_str)))
                encoded_payload.append(encoded_str)
            elif isinstance(part, bytes):
                # If it's already bytes, add directly
                encoded_payload.append(part)
            elif isinstance(part, list):
                # Handle lists of IDs or other types
                if not part:
                    encoded_payload.append(struct.pack('!H', 0))
                else:
                    encoded_payload.append(struct.pack('!H', len(part)))
                    for item in part:
                        if isinstance(item, int):
                            # 4 bytes for integer IDs
                            encoded_payload.append(struct.pack('!I', item))
            elif isinstance(part, bool):
                # Boolean as 1 byte
                encoded_payload.append(struct.pack('!?', part))
            elif isinstance(part, int):
                # Handle different integer sizes
                if part > 65535:
                    # 4-byte integer
                    encoded_payload.append(struct.pack('!I', part))
                else:
                    # 2-byte integer for smaller numbers
                    encoded_payload.append(struct.pack('!H', part))
            elif isinstance(part, float):
                # 8-byte float for timestamps
                encoded_payload.append(struct.pack('!d', part))
        
        # Combine payload parts
        payload = b''.join(encoded_payload)
        
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
    def decode_string(data):
        """Decode a length-prefixed string"""
        if len(data) < 2:
            return "", data
        length = struct.unpack('!H', data[:2])[0]
        if len(data) < 2 + length:
            return "", data
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

    def send_success_response(self, client_socket, cmd, success, message=None, payload_parts=None):
        """
        Send a structured success response
        """
        response_parts = [success]
        
        # Add message if provided
        if message:
            response_parts.append(message)
        else:
            response_parts.append("")
        
        # Add any additional payload parts
        if payload_parts:
            response_parts.extend(payload_parts)
        
        # Send encoded response
        response = self.protocol.encode_message(cmd, response_parts)
        client_socket.send(response)

    def list_users(self, pattern):
        """
        Find users matching a pattern
        """
        matches = []
        for username in self.users:
            if fnmatch.fnmatch(username.lower(), pattern.lower()):
                matches.append({
                    "username": username,
                    "status": "online" if username in self.active_users else "offline"
                })
        return matches

    def get_unread_count(self, username):
        """Get count of messages received while user was offline."""
        return len([msg for msg in self.messages[username] if not msg["read"]])

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
                    try:
                        total_length = struct.unpack('!I', buffer[:4])[0]
                    except struct.error:
                        logging.error("Invalid message length")
                        break

                    # Check if we have a complete message
                    if len(buffer) < total_length:
                        break
                    
                    # Extract full message
                    message_data = buffer[:total_length]
                    buffer = buffer[total_length:]

                    # Safely decode message
                    try:
                        _, cmd, payload = self.protocol.decode_message(message_data)
                    except Exception as decode_error:
                        logging.error(f"Error decoding message: {decode_error}")
                        break

                    # Process different command types
                    with self.lock:
                        if cmd == CustomWireProtocol.CMD_CREATE:
                            # Decode username and password
                            username, payload = self.protocol.decode_string(payload)
                            password, _ = self.protocol.decode_string(payload)

                            if not username or not password:
                                self.send_success_response(
                                    client_socket, 
                                    cmd, 
                                    False, 
                                    "Username and password required"
                                )
                                continue

                            if not self.validate_password(password):
                                self.send_success_response(
                                    client_socket, 
                                    cmd, 
                                    False, 
                                    "Password must be at least 8 characters with 1 number and 1 uppercase letter"
                                )
                                continue

                            if username in self.users:
                                self.send_success_response(
                                    client_socket, 
                                    cmd, 
                                    False, 
                                    "Username already exists"
                                )
                                continue

                            # Create account
                            self.users[username] = (self.hash_password(password), {})
                            self.messages[username] = []
                            logging.info(f"New account created: {username} from {address}")
                            
                            self.send_success_response(
                                client_socket, 
                                cmd, 
                                True, 
                                "Account created successfully"
                            )

                        elif cmd == CustomWireProtocol.CMD_LOGIN:
                            # Decode username and password
                            username, payload = self.protocol.decode_string(payload)
                            password, _ = self.protocol.decode_string(payload)

                            if username not in self.users:
                                self.send_success_response(
                                    client_socket, 
                                    cmd, 
                                    False, 
                                    "User not found"
                                )
                                continue

                            if self.users[username][0] != self.hash_password(password):
                                self.send_success_response(
                                    client_socket, 
                                    cmd, 
                                    False, 
                                    "Invalid password"
                                )
                                continue

                            if username in self.active_users:
                                self.send_success_response(
                                    client_socket, 
                                    cmd, 
                                    False, 
                                    "User already logged in"
                                )
                                continue

                            # Successful login
                            current_user = username
                            self.active_users[username] = client_socket
                            
                            # Send login success response
                            unread_count = self.get_unread_count(username)
                            self.send_success_response(
                                client_socket, 
                                cmd, 
                                True, 
                                username,
                                [unread_count]
                            )

                        elif cmd == CustomWireProtocol.CMD_LIST:
                            # Decode search pattern
                            pattern, _ = self.protocol.decode_string(payload)
                            if not pattern:
                                pattern = "*"
                            elif not pattern.endswith("*"):
                                pattern = pattern + "*"

                            # Find matching users
                            matches = self.list_users(pattern)
                            
                            # Construct response payload
                            response_parts = []
                            for user in matches:
                                response_parts.append(user['username'])
                                response_parts.append(user['status'])
                            
                            # Send response
                            self.send_success_response(
                                client_socket, 
                                cmd, 
                                True,
                                None,
                                response_parts
                            )

                        elif cmd == CustomWireProtocol.CMD_SEND:
                            if not current_user:
                                self.send_success_response(
                                    client_socket, 
                                    cmd, 
                                    False, 
                                    "Not logged in"
                                )
                                continue

                            # Decode recipient and message content
                            recipient, payload = self.protocol.decode_string(payload)
                            content, _ = self.protocol.decode_string(payload)

                            if recipient not in self.users:
                                self.send_success_response(
                                    client_socket, 
                                    cmd, 
                                    False, 
                                    "Recipient not found"
                                )
                                continue

                            # Create and store message
                            message = {
                                "id": self.message_id_counter,
                                "from": current_user,
                                "content": content,
                                "timestamp": int(time.time()),  # Store as integer timestamp
                                "read": False,
                                "delivered_while_offline": recipient not in self.active_users
                            }
                            self.message_id_counter += 1
                            self.messages[recipient].append(message)
                            
                            # If recipient is active, send notification
                            if recipient in self.active_users:
                                try:
                                    notification = self.protocol.encode_message(
                                        CustomWireProtocol.CMD_SEND,
                                        [True, "new_message", current_user, content]
                                    )
                                    self.active_users[recipient].send(notification)
                                except:
                                    pass  # Ignore notification failures
                            
                            # Send success response to sender
                            self.send_success_response(
                                client_socket, 
                                cmd, 
                                True, 
                                "Message sent"
                            )

                        elif cmd == CustomWireProtocol.CMD_GET_MESSAGES:
                            if not current_user:
                                self.send_success_response(
                                    client_socket, 
                                    cmd, 
                                    False, 
                                    "Not logged in"
                                )
                                continue

                            # Decode desired message count
                            count = struct.unpack('!H', payload[:2])[0] if payload else 50
                            
                            # Get messages sorted by timestamp
                            messages = sorted(
                                [msg for msg in self.messages[current_user] if msg["read"]],
                                key=lambda x: x['timestamp'],
                                reverse=True
                            )
                            
                            # Construct response payload
                            response_parts = []
                            
                            for msg in messages:
                                packed_id = struct.pack('!I', msg['id'])
                                packed_timestamp = struct.pack('!I', msg['timestamp'])
                                response_parts.extend([packed_id, msg['from'], msg['content'], packed_timestamp])
                                                       
                            self.send_success_response(
                                client_socket, 
                                cmd, 
                                True,
                                None,
                                response_parts
                            )

                        elif cmd == CustomWireProtocol.CMD_GET_UNDELIVERED:
                            if not current_user:
                                self.send_success_response(
                                    client_socket, 
                                    cmd, 
                                    False, 
                                    "Not logged in"
                                )
                                continue

                            # Decode desired message count
                            count = struct.unpack('!H', payload[:2])[0] if payload else 50
                            
                            # Get unread messages
                            unread_messages = sorted(
                                [msg for msg in self.messages[current_user] if not msg["read"]],
                                key=lambda x: x['timestamp'],
                                reverse=True
                            )[:count]
                            
                            # Mark messages as read
                            for msg in unread_messages:
                                msg["read"] = True
                            
                            # Construct response payload
                            response_parts = []
                            for msg in unread_messages:
                                packed_id = struct.pack('!I', msg['id'])
                                packed_timestamp = struct.pack('!I', msg['timestamp'])
                                response_parts.extend([packed_id, msg['from'], msg['content'], packed_timestamp])
                            
                            # Send response
                            self.send_success_response(
                                client_socket, 
                                cmd, 
                                True,
                                None,
                                response_parts
                            )

                        elif cmd == CustomWireProtocol.CMD_DELETE_MESSAGES:
                            if not current_user:
                                self.send_success_response(
                                    client_socket, 
                                    cmd, 
                                    False, 
                                    "Not logged in"
                                )
                                continue

                            # Decode message IDs to delete
                            id_count = struct.unpack('!H', payload[:2])[0]
                            ids_to_delete = struct.unpack(f'!{id_count}I', payload[2:2+4*id_count])
                            
                            # Remove specified messages
                            self.messages[current_user] = [
                                msg for msg in self.messages[current_user] 
                                if msg['id'] not in ids_to_delete
                            ]
                            
                            # Send success response
                            self.send_success_response(
                                client_socket, 
                                cmd, 
                                True, 
                                "Messages deleted"
                            )

                        elif cmd == CustomWireProtocol.CMD_DELETE_ACCOUNT:
                            if not current_user:
                                self.send_success_response(
                                    client_socket, 
                                    cmd, 
                                    False, 
                                    "Not logged in"
                                )
                                continue

                            # Decode password
                            password, _ = self.protocol.decode_string(payload)

                            if self.users[current_user][0] != self.hash_password(password):
                                self.send_success_response(
                                    client_socket, 
                                    cmd, 
                                    False, 
                                    "Invalid password"
                                )
                                continue

                            # Delete account
                            del self.users[current_user]
                            del self.messages[current_user]

                            if current_user in self.active_users:
                                del self.active_users[current_user]

                            logging.info(f"Account deleted: {current_user}")
                            current_user = None
                            
                            # Send success response
                            self.send_success_response(
                                client_socket, 
                                cmd, 
                                True, 
                                "Account deleted"
                            )

                        elif cmd == CustomWireProtocol.CMD_LOGOUT:
                            if not current_user:
                                self.send_success_response(
                                    client_socket, 
                                    cmd, 
                                    False, 
                                    "Not logged in"
                                )
                                continue

                            # Remove from active users
                            if current_user in self.active_users:
                                del self.active_users[current_user]

                            logging.info(f"User '{current_user}' logged out")
                            current_user = None
                            
                            # Send logout success response
                            self.send_success_response(
                                client_socket, 
                                cmd, 
                                True, 
                                "Logged out successfully"
                            )

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
            logging.info(f"Server error: {e}")
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
                    logging.info(f"Error accepting connection: {e}")
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