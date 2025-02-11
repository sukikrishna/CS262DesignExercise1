# custom_server.py
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

class ChatServer:
    def __init__(self):
        # Configure logging
        logging.basicConfig(
            filename="custom_server.log",
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s"
        )
        
        # Clear log file on server restart
        open("custom_server.log", "w").close()

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

    def get_unread_count(self, username):
        """Get count of messages received while user was offline."""
        return len([msg for msg in self.messages[username] if not msg["read"]])

    def encode_message(self, message):
        """Encode message using binary format."""
        encoded_data = b""
        for key, value in message.items():
            key_bytes = str(key).encode('utf-8')
            value_bytes = str(value).encode('utf-8')
            encoded_data += struct.pack("!H", len(key_bytes))
            encoded_data += struct.pack("!H", len(value_bytes))
            encoded_data += key_bytes
            encoded_data += value_bytes

        # Add total message length prefix
        message_length = len(encoded_data)
        return struct.pack("!I", message_length) + encoded_data

    def decode_message(self, data):
        """Decode binary format message."""
        message = {}
        index = 0
        
        while index < len(data):
            try:
                # Get key length
                key_length = struct.unpack("!H", data[index:index+2])[0]
                index += 2
                
                # Get value length
                value_length = struct.unpack("!H", data[index:index+2])[0]
                index += 2
                
                # Extract key and value
                key = data[index:index+key_length].decode('utf-8')
                index += key_length
                value = data[index:index+value_length].decode('utf-8')
                index += value_length
                
                # Try to convert numeric strings to numbers
                try:
                    if '.' in value:
                        value = float(value)
                    else:
                        value = int(value)
                except ValueError:
                    pass
                    
                message[key] = value
            except struct.error:
                break
            
        return message

    def send_message(self, client_socket, message):
        """Send message using binary protocol."""
        try:
            encoded_msg = self.encode_message(message)
            client_socket.sendall(encoded_msg)
        except Exception as e:
            logging.error(f"Error sending message: {e}")
            raise

    def handle_client(self, client_socket, address):
        logging.info(f"New connection from {address}")
        current_user = None

        while True:
            try:
                # Get message length first
                length_bytes = client_socket.recv(4)
                if not length_bytes:
                    break
                    
                msg_length = struct.unpack("!I", length_bytes)[0]
                
                # Get complete message
                data = b""
                while len(data) < msg_length:
                    chunk = client_socket.recv(min(msg_length - len(data), 4096))
                    if not chunk:
                        break
                    data += chunk

                if len(data) < msg_length:
                    break  # Incomplete message, connection probably lost
                
                message = self.decode_message(data)
                if not message:
                    break

                # Version Check
                if "version" not in message or message["version"] != "1":
                    logging.warning(f"Client {address} sent unsupported version: {message.get('version')}")
                    response = {"success": False, "error": "Unsupported protocol version"}
                    self.send_message(client_socket, response)
                    continue

                # Get the operation code
                cmd = message.get("cmd")
                response = {"success": False, "message": "Invalid command"}
                
                with self.lock:
                    if cmd == "create":
                        username = message.get("username")
                        password = message.get("password")

                        if not username or not password:
                            logging.warning(f"Failed account creation from {address}: Missing fields")
                            response = {"success": False, "message": "Username and password required"}
                        elif not self.validate_password(password):
                            logging.warning(f"Failed account creation from {address}: Weak password")
                            response = {
                                "success": False,
                                "message": "Password must be at least 8 characters with 1 number and 1 uppercase letter"
                            }
                        elif username in self.users:
                            logging.warning(f"Failed account creation from {address}: Username '{username}' already exists")
                            response = {"success": False, "message": "Username already exists"}
                        else:
                            self.users[username] = (self.hash_password(password), {})
                            self.messages[username] = []
                            logging.info(f"New account created: {username} from {address}")
                            
                            # Broadcast updated user list to all clients
                            users_list = self.broadcast_user_list()
                            response = {
                                "success": True,
                                "message": "Account created successfully",
                                "username": username,
                                "users": users_list
                            }

                    elif cmd == "login":
                        username = message.get("username")
                        password = message.get("password")

                        if username not in self.users:
                            logging.warning(f"Failed login attempt from {address}: User '{username}' not found")
                            response = {"success": False, "message": "User not found"}
                        elif self.users[username][0] != self.hash_password(password):
                            logging.warning(f"Failed login attempt from {address}: Incorrect password for '{username}'")
                            response = {"success": False, "message": "Invalid password"}
                        elif username in self.active_users:
                            logging.warning(f"Failed login attempt from {address}: '{username}' already logged in")
                            response = {"success": False, "message": "User already logged in"}
                        else:
                            current_user = username
                            self.active_users[username] = client_socket
                            unread_count = self.get_unread_count(username)
                            logging.info(f"User '{username}' logged in from {address}")

                            response = {
                                "success": True,
                                "message": "Login successful",
                                "username": username,
                                "unread": unread_count
                            }

                            # Send initial login response
                            self.send_message(client_socket, response)

                            # Send user list in separate message
                            users_list = []
                            for user in self.users:
                                users_list.append({
                                    "username": user,
                                    "status": "online" if user in self.active_users else "offline"
                                })
                            
                            user_response = {
                                "success": True,
                                "users": users_list
                            }
                            self.send_message(client_socket, user_response)

                            # Notify other users about new login
                            self.broadcast_user_list()
                            continue  # Skip final response send since we already sent responses

                    elif cmd == "list":
                        pattern = message.get("pattern", "*")
                        if not pattern:
                            pattern = "*"
                        elif not pattern.endswith("*"):
                            pattern = pattern + "*"

                        matches = []
                        for user in self.users:
                            if fnmatch.fnmatch(user.lower(), pattern.lower()):
                                matches.append({
                                    "username": user,
                                    "status": "online" if user in self.active_users else "offline"
                                })

                        response = {"success": True, "users": matches}
                        logging.info(f"User list requested from {address}, found {len(matches)} users")

                    elif cmd == "send":
                        if not current_user:
                            response = {"success": False, "message": "Not logged in"}
                        else:
                            recipient = message.get("to")
                            content = message.get("content")

                            if recipient not in self.users:
                                logging.warning(f"Message failed: '{recipient}' does not exist (from {current_user})")
                                response = {"success": False, "message": "Recipient not found"}
                            else:
                                new_message = {
                                    "id": self.message_id_counter,
                                    "from": current_user,
                                    "content": content,
                                    "timestamp": time.time(),
                                    "read": False
                                }
                                self.message_id_counter += 1
                                self.messages[recipient].append(new_message)
                                
                                # If recipient is active, send immediately
                                if recipient in self.active_users:
                                    try:
                                        real_time_message = {
                                            "success": True,
                                            "message_type": "new_message",
                                            "message": new_message
                                        }
                                        self.send_message(self.active_users[recipient], real_time_message)
                                    except:
                                        pass

                                logging.info(f"Message sent from '{current_user}' to '{recipient}'")
                                response = {"success": True, "message": "Message sent"}

                    elif cmd == "get_messages":
                        if not current_user:
                            response = {"success": False, "message": "Not logged in"}
                            logging.warning(f"Unauthorized get_messages request from {address}")
                        else:
                            messages = [msg for msg in self.messages[current_user] if msg["read"]]
                            messages.sort(key=lambda x: x["timestamp"], reverse=True)
                            response = {"success": True, "messages": messages}
                            logging.info(f"User '{current_user}' retrieved {len(messages)} messages")

                    elif cmd == "get_undelivered":
                        if not current_user:
                            response = {"success": False, "message": "Not logged in"}
                        else:
                            unread = [msg for msg in self.messages[current_user] if not msg["read"]]
                            unread.sort(key=lambda x: x["timestamp"], reverse=True)
                            count = message.get("count", self.config.get("message_fetch_limit"))
                            unread = unread[:count]
                            
                            # Mark messages as read
                            for msg in unread:
                                msg["read"] = True
                                
                            response = {"success": True, "messages": unread}
                            logging.info(f"User '{current_user}' retrieved {len(unread)} undelivered messages")

                    elif cmd == "delete_messages":
                        if not current_user:
                            response = {"success": False, "message": "Not logged in"}
                        else:
                            msg_ids = set(message.get("message_ids", []))
                            self.messages[current_user] = [
                                msg for msg in self.messages[current_user] 
                                if msg["id"] not in msg_ids
                            ]
                            response = {"success": True, "message": "Messages deleted"}
                            logging.info(f"User '{current_user}' deleted {len(msg_ids)} messages")

                    elif cmd == "delete_account":
                        if not current_user:
                            response = {"success": False, "message": "Not logged in"}
                        else:
                            password = message.get("password")
                            if self.users[current_user][0] != self.hash_password(password):
                                response = {"success": False, "message": "Invalid password"}
                            else:
                                del self.users[current_user]
                                del self.messages[current_user]
                                if current_user in self.active_users:
                                    del self.active_users[current_user]
                                logging.info(f"Account deleted: {current_user}")
                                current_user = None
                                
                                response = {
                                    "success": True,
                                    "message": "Account deleted"
                                }
                                self.broadcast_user_list()

                    elif cmd == "logout":
                        if not current_user:
                            response = {"success": False, "message": "Not logged in"}
                        else:
                            if current_user in self.active_users:
                                del self.active_users[current_user]
                            logging.info(f"User '{current_user}' logged out")
                            current_user = None
                            response = {"success": True, "message": "Logged out successfully"}
                            self.broadcast_user_list()

                # Send response
                self.send_message(client_socket, response)

            except Exception as e:
                logging.error(f"Error handling client {address}: {e}")
                break

        # Cleanup on disconnect
        if current_user in self.active_users:
            del self.active_users[current_user]
            self.broadcast_user_list()
        
        client_socket.close()
        logging.info(f"Connection closed for {address}")

    def broadcast_user_list(self):
        """Send updated user list to all active clients."""
        users_list = []
        for user in self.users:
            users_list.append({
                "username": user,
                "status": "online" if user in self.active_users else "offline"
            })
        
        message = {"success": True, "users": users_list}
        
        for client in self.active_users.values():
            try:
                self.send_message(client, message)
            except:
                pass
                
        return users_list

    def find_free_port(self, start_port):
        """Find next available port starting from start_port."""
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

    def start(self):
        # Find next available port if needed
        try:
            self.port = self.find_free_port(self.port)
            # Update config with the new port
            config = Config()
            config.update("port", self.port)
        except RuntimeError as e:
            logging.error(f"Server error: {e}")
            print(f"Server error: {e}")
            return

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.settimeout(1)  # 1 second timeout for accept()

        try:
            self.server.bind((self.host, self.port))
            self.server.listen(5)
            self.running = True
            print(f"Server started on {self.host}:{self.port}")
            logging.info(f"Server started on {self.host}:{self.port}")

            while self.running:
                try:
                    client_socket, address = self.server.accept()
                    client_socket.settimeout(None)  # Clear timeout for client socket
                    logging.info(f"New connection accepted from {address}")
                    
                    # Start client handler thread
                    thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, address),
                        daemon=True
                    )
                    thread.start()
                    
                except socket.timeout:
                    continue  # Normal timeout, just continue the loop
                except Exception as e:
                    if self.running:  # Only log if we're still meant to be running
                        logging.error(f"Error accepting connection: {e}")
                        print(f"Error accepting connection: {e}")
        except Exception as e:
            logging.error(f"Server error: {e}")
            print(f"Server error: {e}")
        finally:
            self.stop()

    def stop(self):
        """Stop the server and clean up."""
        self.running = False
        logging.info("Server shutting down...")
        
        # Close all client connections
        for user, client_socket in self.active_users.items():
            try:
                client_socket.close()
                logging.info(f"Closed connection for user: {user}")
            except:
                pass
        self.active_users.clear()
        
        # Close server socket
        if self.server:
            try:
                self.server.close()
                logging.info("Server socket closed")
            except:
                pass
            self.server = None
            
        logging.info("Server shutdown complete")
        print("Server shutdown complete")

def main():
    server = ChatServer()
    try:
        print("Starting chat server...")
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.stop()
    except Exception as e:
        print(f"Unexpected error: {e}")
        logging.error(f"Unexpected error: {e}")
        server.stop()

if __name__ == "__main__":
    main()