import socket
import json
import struct
import threading
import hashlib
import re
import fnmatch
import time
import logging
from collections import defaultdict
from config import Config

class ChatServer:
    def __init__(self, use_json=True):
        # Determine the correct log file based on the protocol flag
        log_filename = "json_server.log" if use_json else "custom_server.log"

        # Configure logging to print to the console or save to a file
        logging.basicConfig(
            filename=log_filename,  # Change to None to print to console instead
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s"
        )
        #Clear log file on server restart
        open(log_filename, "w").close() # Clears log file

        self.config = Config()
        self.host = self.config.get("host")
        self.port = self.config.get("port")
        self.use_json = use_json  # Choose protocol
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

    def encode_custom(self, message):
        """Encode message using a compact binary format with length prefix."""
        encoded_data = b""
        for key, value in message.items():
            key_bytes = key.encode('utf-8')
            value_bytes = str(value).encode('utf-8')
            encoded_data += struct.pack("!B H", len(key_bytes), len(value_bytes)) + key_bytes + value_bytes

        total_length = len(encoded_data)
        header = struct.pack("!B B I B", 1, ord(message["cmd"][0]), total_length, 0)
        full_message = header + encoded_data
        return struct.pack("!I", len(full_message)) + full_message  # Prepend length


    def decode_custom(self, data):
        """Decode compact binary message format."""
        version, msg_type, total_length, flags = struct.unpack("!B B I B", data[:7])
        payload = data[7:]

        message = {"version": version, "cmd": chr(msg_type), "flags": flags}
        index = 0
        while index < len(payload):
            key_len, value_len = struct.unpack("!B H", payload[index:index+3])
            index += 3
            key = payload[index:index+key_len].decode('utf-8')
            index += key_len
            value = payload[index:index+value_len].decode('utf-8')
            index += value_len
            message[key] = value
        return message

    def send_data(self, client_socket, message):
        """Send data using selected protocol and log size & time."""
        start_time = time.monotonic_ns()
        if self.use_json:
            encoded_msg = json.dumps(message).encode()
        else:
            encoded_msg = self.encode_custom(message)

        client_socket.sendall(encoded_msg)
        elapsed_time = time.monotonic_ns() - start_time
        logging.info(f"Sent {len(encoded_msg)} bytes: {message}")
        logging.info(f"Encoding & Sending took {elapsed_time} ns")

    def receive_data(self, client_socket):
        """Receive data using selected protocol and log size & time."""
        start_time = time.monotonic_ns()
        if self.use_json:
            data = client_socket.recv(4096).decode()
            parsed_data = json.loads(data)
        else:
            length_bytes = client_socket.recv(4)
            if not length_bytes:
                return None
            msg_length = struct.unpack("!I", length_bytes)[0]

            data = client_socket.recv(msg_length)
            if len(data) < msg_length:
                return None  # Ensure complete message received

            parsed_data = self.decode_custom(data)

        elapsed_time = time.monotonic_ns() - start_time
        logging.info(f"Received {len(data)} bytes: {parsed_data}")
        logging.info(f"Decoding took {elapsed_time} ns")

        return parsed_data

    def handle_client(self, client_socket, address):
        logging.info(f"New connection from {address}")
        current_user = None

        while True:
            try:
                msg = self.receive_data(client_socket)
                if not msg:
                    break                
                # data = client_socket.recv(4096).decode()
                # if not data:
                #     break

                # try:
                #     msg = json.loads(data)  # Ensure valid JSON
                # except json.JSONDecodeError:
                #     logging.warning(f"Invalid JSON received from {address}")
                #     response = {"success": False, "error": "Invalid JSON format"}
                #     client_socket.send(json.dumps(response).encode())
                #     continue  

                # Version Check
                if "version" not in msg or msg["version"] != "1":
                    logging.warning(f"Client {address} sent unsupported version: {msg.get('version')}")
                    response = {"success": False, "error": "Unsupported protocol version"}
                    self.send_data(client_socket, response)
                    continue   

                # Get the operation code
                cmd = msg.get("cmd")
                response = {"success": False, "message": "Invalid command"}
                
                with self.lock:
                    if cmd == "create":
                        username = msg.get("username")
                        password = msg.get("password")

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
                            
                            # Broadcast updated user list to all clients and include in response
                            users_list = self.broadcast_user_list()
                            response = {
                                "success": True,
                                "message": "Account created successfully",
                                "username": username,
                                "users": users_list
                            } # fix??

                    elif cmd == "login":
                        username = msg.get("username")
                        password = msg.get("password")

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

                            # Construct response for successful login
                            response = {
                                "success": True,
                                "message": "Login successful",
                                "username": username,
                                "unread": unread_count
                            }

                            # Build the list of all users with online/offline status
                            users_list = []
                            for user in self.users:
                                users_list.append({
                                    "username": user,
                                    "status": "online" if user in self.active_users else "offline"
                                })

                            # Send login success response + user list to the logged-in client
                            user_response = {
                                "success": True,
                                "users": users_list
                            }
                            if self.use_json:
                                client_socket.send(json.dumps(response).encode())
                                client_socket.send(json.dumps(user_response).encode())
                            else:
                                encoded_response = self.encode_custom(response)
                                encoded_user_response = self.encode_custom(user_response)
                                client_socket.send(struct.pack("!I", len(encoded_response)) + encoded_response)
                                client_socket.send(struct.pack("!I", len(encoded_user_response)) + encoded_user_response)

                            # Broadcast updated user list to all active clients
                            for active_client in self.active_users.values():
                                if active_client != client_socket:
                                    try:
                                        if self.use_json:
                                            active_client.send(json.dumps({"success": True, "users": users_list}).encode())
                                        else:
                                            encoded_broadcast = self.encode_custom({"success": True, "users": users_list})
                                            active_client.send(struct.pack("!I", len(encoded_broadcast)) + encoded_broadcast)
                                    except Exception:
                                        pass

                    elif cmd == "list":
                        pattern = msg.get("pattern", "*")

                        # Ensure a valid pattern (default to "*")
                        if not pattern:
                            pattern = "*"
                        elif not pattern.endswith("*"):
                            pattern = pattern + "*"

                        # Find matching users
                        matches = []
                        for username in self.users:
                            if fnmatch.fnmatch(username.lower(), pattern.lower()):
                                matches.append({
                                    "username": username,
                                    "status": "online" if username in self.active_users else "offline"
                                })

                        response = {"success": True, "users": matches}
                        logging.info(f"User list requested from {address}, found {len(matches)} users")

                    elif cmd == "send":
                        if not current_user:
                            response = {"success": False, "message": "Not logged in"}
                        else:
                            recipient = msg.get("to")
                            content = msg.get("content")

                            if recipient not in self.users:
                                logging.warning(f"Message failed: '{recipient}' does not exist (from {current_user})")
                                response = {"success": False, "message": "Recipient not found"}
                            else:
                                message = {
                                    "id": self.message_id_counter,
                                    "from": current_user,
                                    "content": content,
                                    "timestamp": time.time(),
                                    "read": False,
                                }
                                self.message_id_counter += 1
                                self.messages[recipient].append(message)
                                
                                # If recipient is active, send immediately
                                if recipient in self.active_users:
                                    try:
                                        real_time_message = {
                                            "success": True,
                                            "message_type": "new_message",
                                            "message": message
                                        }
                                        if self.use_json:
                                            self.active_users[recipient].send(json.dumps(real_time_message).encode())
                                        else:
                                            encoded_message = self.encode_custom(real_time_message)
                                            self.active_users[recipient].send(encoded_message)
                                    except:
                                        pass

                                logging.info(f"Message sent from '{current_user}' to '{recipient}'")
                                response = {"success": True, "message": "Message sent"}

                    elif cmd == "get_messages":
                        if not current_user:
                            response = {"success": False, "message": "Not logged in"}
                            logging.warning(f"Unauthorized get_messages request from {address}")
                        else:
                            count = msg.get("count", self.config.get("message_fetch_limit"))
                            messages = self.get_messages(current_user)
                            response = {"success": True, "messages": messages}
                            logging.info(f"User '{current_user}' retrieved {len(messages)} messages")

                    elif cmd == "get_undelivered":
                        if not current_user:
                            response = {"success": False, "message": "Not logged in"}
                            logging.warning(f"Unauthorized get_undelivered request from {address}")
                        else:
                            count = msg.get("count", self.config.get("message_fetch_limit"))

                            unread = self.get_unread_messages(current_user, count)
                            
                            # Mark messages as read
                            for m in unread:
                                m["read"] = True
                                
                            response = {"success": True, "messages": unread}
                            logging.info(f"User '{current_user}' retrieved {len(unread)} undelivered messages")

                    elif cmd == "delete_messages":
                        if not current_user:
                            response = {"success": False, "message": "Not logged in"}
                            logging.warning(f"Unauthorized delete_messages request from {address}")
                        else:
                            msg_ids = set(msg.get("message_ids", []))  # Get message IDs to delete

                            # Keep only messages that are not in the list of IDs to delete
                            self.messages[current_user] = [
                                m for m in self.messages[current_user] if m["id"] not in msg_ids
                            ]

                            response = {"success": True, "message": "Messages deleted"}
                            logging.info(f"User '{current_user}' deleted {len(msg_ids)} messages")

                    elif cmd == "delete_account":
                        if not current_user:
                            response = {"success": False, "message": "Not logged in"}
                            logging.warning(f"Unauthorized delete_account request from {address}")
                        else:
                            password = msg.get("password")

                            if self.users[current_user][0] != self.hash_password(password):
                                response = {"success": False, "message": "Invalid password"}
                                logging.warning(f"Failed account deletion for {current_user} - Incorrect password")
                            else:
                                del self.users[current_user]
                                del self.messages[current_user]

                                if current_user in self.active_users:
                                    del self.active_users[current_user]

                                logging.info(f"Account deleted: {current_user}")
                                current_user = None
                                
                                # Broadcast updated user list to all clients and include in response
                                users_list = self.broadcast_user_list()
                                response = {
                                    "success": True,
                                    "message": "Account deleted",
                                    "users": users_list
                                }

                    elif cmd == "logout":
                        if not current_user:
                            response = {"success": False, "message": "Not logged in"}
                            logging.warning(f"Unauthorized logout request from {address}")
                        else:
                            if current_user in self.active_users:
                                del self.active_users[current_user]

                            logging.info(f"User '{current_user}' logged out")

                            # Build updated user list to notify other clients
                            users_list = []
                            for user in self.users:
                                users_list.append({
                                    "username": user,
                                    "status": "online" if user in self.active_users else "offline"
                                })

                            # Notify all active clients about the updated user list
                            for client in self.active_users.values():
                                try:
                                    if self.use_json:
                                        client.send(json.dumps({"success": True, "users": users_list}).encode())
                                    else:
                                        encoded_broadcast = self.encode_custom({"success": True, "users": users_list})
                                        client.send(struct.pack("!I", len(encoded_broadcast)) + encoded_broadcast)
                                except:
                                    pass  # Ignore failed sends

                            current_user = None
                            response = {"success": True, "message": "Logged out successfully"}
            
                self.send_data(client_socket, response)

            except Exception as e:
                logging.info(f"Error handling client: {e}")
                break

        # When connection is lost or client disconnects
        if current_user in self.active_users:
            del self.active_users[current_user]
            
            # Broadcast updated user list to all active clients
            users_list = []
            for user in self.users:
                users_list.append({
                    "username": user,
                    "status": "online" if user in self.active_users else "offline"
                })
            
            for client in self.active_users.values():
                try:
                    if self.use_json:
                        client.send(json.dumps({"success": True, "users": users_list}).encode())
                    else:
                        encoded_broadcast = self.encode_custom({"success": True, "users": users_list})
                        client.send(struct.pack("!I", len(encoded_broadcast)) + encoded_broadcast)
                except:
                    pass
        
        client_socket.close()

    def broadcast_user_list(self):
        """Helper method to broadcast updated user list to all active clients"""
        users_list = []
        for user in self.users:
            users_list.append({
                "username": user,
                "status": "online" if user in self.active_users else "offline"
            })
        
        # Send to all active clients
        for client in self.active_users.values():
            try:
                if self.use_json:
                    client.send(json.dumps({"success": True, "users": users_list}).encode())
                else:
                    encoded_broadcast = self.encode_custom({"success": True, "users": users_list})
                    client.send(encoded_broadcast)
            except:
                pass  # Ignore failed sends

        return users_list

    def get_messages(self, username):
        """Get messages for a user, excluding unread ones."""
        messages = self.messages[username]
        read_messages = [m for m in messages if m["read"]]
        return sorted(read_messages, key=lambda x: x["timestamp"], reverse=True)

    def get_unread_messages(self, username, count):
        """Get unread messages for a user."""
        messages = self.messages[username]
        unread_messages = [m for m in messages if not m["read"]]
        return sorted(unread_messages, key=lambda x: x["timestamp"], reverse=True)[:count]
        # return sorted(unread_messages, key=lambda x: x["timestamp"])[:count]


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

    def start(self):
        # Find next available port if needed
        try:
            self.port = self.find_free_port(self.port)
            # Update config with the new port
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

if __name__ == "__main__":
    server = ChatServer()
    try:
        parser = argparse.ArgumentParser(description="Chat Server")
        parser.add_argument("--json", action="store_true", help="Use JSON wire protocol")
        parser.add_argument("--custom", action="store_true", help="Use custom wire protocol")

        args = parser.parse_args()
        use_json = args.json  # Default to JSON if specified

        server = ChatServer(use_json)
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.stop()