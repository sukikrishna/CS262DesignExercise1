import socket
import json
import struct
import threading
import tkinter as tk
import time
import argparse
import logging
from tkinter import ttk, messagebox
from config import Config

class MessageFrame(ttk.Frame):
    def __init__(self, parent, message_data, on_select=None):
        super().__init__(parent)
        
        self.configure(relief='raised', borderwidth=1, padding=5)
        self.message_id = message_data["id"]
        
        header_frame = ttk.Frame(self)
        header_frame.pack(fill='x', expand=True)
        
        self.select_var = tk.BooleanVar()
        select_cb = ttk.Checkbutton(header_frame, variable=self.select_var)
        select_cb.pack(side='left', padx=(0, 5))
        
        time_str = time.strftime('%Y-%m-%d %H:%M:%S', 
                               time.localtime(message_data["timestamp"]))
        sender_label = ttk.Label(
            header_frame, 
            text=f"From: {message_data['from']} at {time_str}",
            style='Bold.TLabel'
        )
        sender_label.pack(side='left')
    
        content = ttk.Label(
            self,
            text=message_data["content"],
            wraplength=400
        )
        content.pack(fill='x', pady=(5, 0))

class ChatClient:
    def __init__(self, host, use_json):
        self.root = tk.Tk()
        self.root.title("Chat Application")
        self.root.geometry("1000x800")
        
        self.config = Config()
        self.host = host
        self.port = self.config.get("port")
        self.use_json = use_json  # Choose protocol
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.username = None
        self.setup_gui()
        self.running = True
        threading.Thread(target=self.receive_messages, daemon=True).start()

        # Determine the correct log file based on the protocol flag
        log_filename = "json_client.log" if use_json else "custom_client.log"

        # Configure logging
        logging.basicConfig(
            filename=log_filename,
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s"
        )

        try:
            self.socket.connect((self.host, self.port))
        except ConnectionRefusedError:
            messagebox.showerror("Error", "Could not connect to server")
            logging.error("Could not connect to the server.")
            self.root.destroy()
            return
    

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

    def send_data(self, message):
        """Send data using selected protocol and log size & time."""
        start_time = time.monotonic_ns()
        if self.use_json:
            encoded_msg = json.dumps(message).encode()
        else:
            encoded_msg = self.encode_custom(message)

        self.socket.sendall(encoded_msg)
        elapsed_time = time.monotonic_ns() - start_time
        logging.info(f"Sent {len(encoded_msg)} bytes: {message}")
        logging.info(f"Encoding & Sending took {elapsed_time} ns")

    def receive_data(self):
        """Receive data using selected protocol and log size & time."""
        start_time = time.monotonic_ns()
        if self.use_json:
            data = self.socket.recv(4096).decode()
            parsed_data = json.loads(data)

        else:
            length_bytes = self.socket.recv(4)
            if not length_bytes:
                return None
            msg_length = struct.unpack("!I", length_bytes)[0]

            data = b""
            while len(data) < msg_length:
                chunk = self.socket.recv(msg_length - len(data))
                if not chunk:
                    return None  # Connection lost
                data += chunk  # Append new chunk

            parsed_data = self.decode_custom(data)


        elapsed_time = time.monotonic_ns() - start_time
        logging.info(f"Received {len(data)} bytes: {parsed_data}")
        logging.info(f"Decoding took {elapsed_time} ns")

        return parsed_data

    def setup_gui(self):
        style = ttk.Style()
        style.configure('Bold.TLabel', font=('TkDefaultFont', 9, 'bold'))
        
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill='both', padx=5, pady=5)
        
        self.auth_frame = ttk.Frame(self.notebook)
        self.chat_frame = ttk.Frame(self.notebook)
        self.accounts_frame = ttk.Frame(self.notebook)
        
        self.notebook.add(self.auth_frame, text='Login/Register')
        self.notebook.add(self.accounts_frame, text='Users')
        self.notebook.add(self.chat_frame, text='Chat')
        
        self.setup_auth_frame()
        self.setup_accounts_frame()
        self.setup_chat_frame()
        
        self.status_var = tk.StringVar(value="Not logged in")
        status = ttk.Label(self.root, textvariable=self.status_var)
        status.pack(side='bottom', fill='x', padx=5, pady=2)
        
    def setup_auth_frame(self):
        frame = ttk.LabelFrame(self.auth_frame, text="Authentication", padding=10)
        frame.pack(expand=True, fill='both', padx=10, pady=10)
        
        ttk.Label(frame, text="Username:").pack(pady=5)
        self.username_entry = ttk.Entry(frame)
        self.username_entry.pack(pady=5)
        
        ttk.Label(frame, text="Password:").pack(pady=5)
        self.password_entry = ttk.Entry(frame, show="*")
        self.password_entry.pack(pady=5)
        
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Login", command=self.login).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Create Account", 
                  command=self.create_account).pack(side='left', padx=5)
        
    def setup_chat_frame(self):
        left_frame = ttk.Frame(self.chat_frame)
        left_frame.pack(side='left', fill='both', expand=True)
        
        self.messages_canvas = tk.Canvas(left_frame)
        scrollbar = ttk.Scrollbar(left_frame, orient="vertical", 
                                command=self.messages_canvas.yview)
        
        self.messages_frame = ttk.Frame(self.messages_canvas)
        self.messages_frame.bind(
            "<Configure>",
            lambda e: self.messages_canvas.configure(
                scrollregion=self.messages_canvas.bbox("all")
            )
        )
        
        self.messages_canvas.create_window((0, 0), window=self.messages_frame, 
                                        anchor="nw", width=600)
        
        self.messages_canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.messages_canvas.pack(side="left", fill="both", expand=True)
        
        right_frame = ttk.Frame(self.chat_frame, padding=5)
        right_frame.pack(side='right', fill='y')
        
        controls = ttk.LabelFrame(right_frame, text="Message Controls", padding=5)
        controls.pack(fill='x', pady=5)
        
        ttk.Label(controls, text="Unread messages to fetch:").pack()
        self.msg_count = ttk.Entry(controls, width=5)
        self.msg_count.insert(0, self.config.get("message_fetch_limit"))
        self.msg_count.pack()
        
        ttk.Button(controls, text="Unread Messages", 
                command=self.refresh_unread_messages).pack(fill='x', pady=(5, 25))
        ttk.Button(controls, text="Message History", 
                command=self.refresh_messages).pack(fill='x', pady=10)
    
        ttk.Button(controls, text="Delete Selected Messages", 
                  command=self.delete_selected_messages).pack(fill='x', pady=5)

        delete_frame = ttk.LabelFrame(right_frame, text="Settings", padding=5)
        delete_frame.pack(fill='x', padx=5, pady=5)

        ttk.Label(delete_frame, text="Confirm password:").pack(anchor='w', padx=5, pady=2)
        self.delete_password = ttk.Entry(delete_frame, show="*")
        self.delete_password.pack(fill='x', padx=5, pady=5)
        
        ttk.Button(delete_frame, text="Delete Account",
                  command=self.delete_account).pack(fill='x', padx=5, pady=5)
        
        ttk.Button(delete_frame, text="Logout",
            command=self.logout).pack(fill='x', pady=(25, 5))

    def setup_accounts_frame(self):
        controls_frame = ttk.Frame(self.accounts_frame)
        controls_frame.pack(fill='x', padx=5, pady=5)
        
        search_frame = ttk.LabelFrame(controls_frame, text="Search", padding=5)
        search_frame.pack(fill='x')
        
        ttk.Label(search_frame, text="Username:").pack(side='left', padx=5)
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        search_entry.pack(side='left', fill='x', expand=True, padx=5)
        
        ttk.Button(search_frame, text="Search", 
                command=self.search_accounts).pack(side='right', padx=5)

        tree_frame = ttk.Frame(self.accounts_frame)
        tree_frame.pack(expand=True, fill='both', padx=5, pady=5)

        self.accounts_list = ttk.Treeview(tree_frame, 
                                        columns=('username', 'status'),
                                        show='headings',
                                        height=15)
                                        
        yscroll = ttk.Scrollbar(tree_frame, orient='vertical', 
                            command=self.accounts_list.yview)
        xscroll = ttk.Scrollbar(tree_frame, orient='horizontal', 
                            command=self.accounts_list.xview)
        
        self.accounts_list.configure(yscrollcommand=yscroll.set, 
                                xscrollcommand=xscroll.set)

        self.accounts_list.heading('username', text='Username')
        self.accounts_list.heading('status', text='Status')
        self.accounts_list.column('username', width=150, minwidth=100)
        self.accounts_list.column('status', width=100, minwidth=70)

        self.accounts_list.grid(row=0, column=0, sticky='nsew')
        yscroll.grid(row=0, column=1, sticky='ns')
        xscroll.grid(row=1, column=0, sticky='ew')

        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        self.accounts_list.bind('<Double-1>', self.on_user_select)
        
        send_frame = ttk.LabelFrame(self.accounts_frame, text="Send Message (double click on username to select)", padding=5)
        send_frame.pack(fill='x', padx=5, pady=5)
        
        to_frame = ttk.Frame(send_frame)
        to_frame.pack(fill='x', pady=0)
        
        ttk.Label(to_frame, text="To:").pack(side='left', padx=(0, 5))
        self.recipient_var = tk.StringVar()
        self.recipient_entry = ttk.Entry(to_frame, textvariable=self.recipient_var, state='readonly')
        self.recipient_entry.pack(side='left', fill='x', expand=True)
        
        ttk.Label(send_frame).pack()
        self.message_text = tk.Text(send_frame, height=4, width=250)
        self.message_text.pack()
        
        ttk.Button(send_frame, text="Send", 
                command=self.send_message).pack(fill='x', pady=5)

        status_frame = ttk.Frame(self.accounts_frame)
        status_frame.pack(fill='x', padx=5, pady=5)
        
        # Create container for user counts
        counts_frame = ttk.Frame(status_frame)
        counts_frame.pack(side='left', fill='x')
        
        self.user_count_var = tk.StringVar(value="Users found: 0")
        self.online_count_var = tk.StringVar(value="Online users: 0")
        
        ttk.Label(status_frame, textvariable=self.user_count_var).pack(side='left')
        ttk.Label(status_frame, text=" | ").pack(side='left', padx=5)
        ttk.Label(status_frame, textvariable=self.online_count_var).pack(side='left')

    def create_account(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showwarning("Warning", "Please enter username and password")
            return
        
        message = {
            "cmd": "create",
            "version": 1,
            "username": username,
            "password": password
        }
        self.send_data(message)

        # response = self.receive_data()
        # if response and response.get("success"):
        #     logging.info(f"Login successful for {username}")
        #     return True
        # else:
        #     logging.error(f"Login failed: {response.get('message', 'Unknown error')}")
        #     return False

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showwarning("Warning", "Please enter username and password")
            return
        
        message = {
            "cmd": "login",
            "version": 1,
            "username": username,
            "password": password
        }
        self.send_data(message)

        response = self.receive_data()
        # if response and response.get("success"):
        #     logging.info(f"Login successful for {username}")
        #     return True
        # else:
        #     logging.error(f"Login failed: {response.get('message', 'Unknown error')}")
        #     return False

    def send_message(self):
        if not self.username:
            messagebox.showwarning("Warning", "Please login first")
            return
            
        recipient = self.recipient_var.get()
        message = self.message_text.get("1", tk.END).strip()
        
        if not recipient or not message:
            messagebox.showwarning("Warning", "Please enter recipient and message")
            return
            
        message = {
            "cmd": "send",
            "version": 1,
            "to": recipient,
            "content": message
        }
        self.send_data(message)

        # response = self.receive_data()
        # if response and response.get("success"):
        #     logging.info("Message sent successfully")
        #     self.message_text.delete("1.0", tk.END)  # Clears the input field
        # else:
        #     logging.error(f"Failed to send message: {response.get('message', 'Unknown error')}")
            
    def delete_message(self, msg_id):
        if messagebox.askyesno("Confirm", "Delete this message?"):
            message = {
                "cmd": "delete_messages",
                "version": 1,
                "message_ids": [msg_id]
            }
            self.send_data(message)

            # response = self.receive_data()
            # if response and response.get("success"):
            #     logging.info("Messages deleted successfully")
            # else:
            #     logging.error(f"Failed to delete messages: {response.get('message', 'Unknown error')}")

            # Remove the message frame immediately
            for widget in self.messages_frame.winfo_children():
                if isinstance(widget, MessageFrame) and getattr(widget, 'message_id', None) == msg_id:
                    widget.destroy()
                    break

    def delete_selected_messages(self):
        """Delete selected messages from the server."""
        selected_ids = []
        for widget in self.messages_frame.winfo_children():
            if isinstance(widget, MessageFrame) and widget.select_var.get():
                selected_ids.append(widget.message_id)

        if selected_ids:
            if messagebox.askyesno("Confirm", f"Delete {len(selected_ids)} selected messages?"):
                message = {
                    "cmd": "delete_messages",
                    "version": 1,
                    "message_ids": selected_ids
                }
                self.send_data(message)

                response = self.receive_data()
                # if response and response.get("success"):
                #     # Remove the message frames immediately
                for widget in self.messages_frame.winfo_children():
                    if isinstance(widget, MessageFrame) and widget.message_id in selected_ids:
                        widget.destroy()
                #     logging.info(f"Deleted {len(selected_ids)} messages")
                # else:
                #     logging.error(f"Failed to delete messages: {response.get('message', 'Unknown error')}")


    def refresh_messages(self):
        try:
            count = int(self.msg_count.get())
        except ValueError:
            count = self.config.get("message_fetch_limit")

        message = {
            "cmd": "get_messages",
            "version": 1,
            "count": count
        }
        self.send_data(message)

        response = self.receive_data()
        if response and response.get("success"):
            self.clear_messages()
            for msg in response["messages"]:
                frame = MessageFrame(self.messages_frame, msg)
                frame.message_id = msg["id"]
                frame.pack(fill='x', padx=5, pady=2)
            logging.info(f"Retrieved {len(response['messages'])} messages")
        else:
            logging.error(f"Failed to fetch messages: {response.get('message', 'Unknown error')}")


    def refresh_unread_messages(self):
        """Get only undelivered messages"""
        try:
            count = int(self.msg_count.get())
        except ValueError:
            count = self.config.get("message_fetch_limit") 
                
        message = {
            "cmd": "get_undelivered",
            "version": 1,
            "count": count
        }
        self.send_data(message)

        response = self.receive_data()
        if response and response.get("success"):
            self.clear_messages()
            for msg in response["messages"]:
                frame = MessageFrame(self.messages_frame, msg)
                frame.message_id = msg["id"]
                frame.pack(fill='x', padx=5, pady=2)
            logging.info(f"Retrieved {len(response['messages'])} unread messages")
        else:
            logging.error(f"Failed to fetch unread messages: {response.get('message', 'Unknown error')}")


    def on_user_select(self, event):
        selection = self.accounts_list.selection()
        if selection:
            item = self.accounts_list.item(selection[0])
            username = item['values'][0]
            self.recipient_var.set(username)
            self.notebook.select(1)  # Switch to chat tab

    def search_accounts(self):
        pattern = self.search_var.get()
        if pattern and not pattern.endswith("*"):
            pattern = pattern + "*"
        message = {
            "cmd": "list",
            "version": 1,
            "pattern": pattern
        }
        self.send_data(message)

        response = self.receive_data()
        if response and response.get("success"):
            users = response.get("users", [])
            if users:
                logging.info(f"Found {len(users)} users:")
                for user in users:
                    print(f"Username: {user['username']} (Status: {user['status']})")
            else:
                logging.info("No users found.")
        else:
            logging.error(f"User search failed: {response.get('message', 'Unknown error')}")

    def delete_account(self):
        if not self.username:
            messagebox.showwarning("Warning", "Please login first")
            return
            
        password = self.delete_password.get()
        if not password:
            messagebox.showwarning("Warning", "Please enter your password")
            return
            
        if messagebox.askyesno("Confirm", 
                              "Delete your account? This cannot be undone."):
            message = {
                "cmd": "delete_account",
                "version": 1,
                "password": password
            }
            self.send_data(message)

            response = self.receive_data()
            if response and response.get("success"):
                logging.info("Account deleted successfully")
                self.username = None  # Clear username
            else:
                logging.error(f"Failed to delete account: {response.get('message', 'Unknown error')}")

    def logout(self):
        """Logout from the server if logged in."""
        if not self.username:
            logging.warning("Cannot logout: No user is currently logged in.")
            return

        message = {"cmd": "logout", "version": 1}
        self.send_data(message)

        response = self.receive_data()
        if response and response.get("success"):
            logging.info("Logged out successfully")
            self.username = None  # Clear username after logout
        else:
            logging.error(f"Logout failed: {response.get('message', 'Unknown error')}")

    def clear_messages(self):
        for widget in self.messages_frame.winfo_children():
            widget.destroy()

    # def send_command(self, command):
    #     """Ensure every command includes the version field before sending."""
    #     command["version"] = "1"  # Add version to every message
    #     try:
    #         self.socket.send(json.dumps(command).encode())
    #     except Exception as e:
    #         messagebox.showerror("Error", f"Failed to send command: {e}")
    #         self.on_connection_lost()

    def receive_messages(self):
        buffer = b"" if not self.use_json else ""  # Handle binary data for custom protocol
        while self.running:
            try:
                data = self.socket.recv(4096)
                if not data:
                    self.on_connection_lost()
                    break

                buffer += data if not self.use_json else data.decode()  # Accumulate binary or text data

                while True:
                    try:
                        if self.use_json:
                            # Process complete JSON messages
                            message_end = buffer.index("}{") if "}{" in buffer else len(buffer)
                            message = json.loads(buffer[:message_end+1])
                            buffer = buffer[message_end+1:]
                        else:
                            # Process custom protocol message
                            if len(buffer) < 4:
                                break  # Not enough data for length prefix
                            msg_length = struct.unpack("!I", buffer[:4])[0]
                            if len(buffer) < 4 + msg_length:
                                break  # Not enough data yet
                            message = self.decode_custom(buffer[4:4+msg_length])
                            buffer = buffer[4+msg_length:]

                        self.root.after(0, self.handle_message, message)

                    except (ValueError, json.JSONDecodeError, struct.error):
                                break  # Incomplete message, wait for more data

            except Exception as e:
                if self.running:
                    print(f"Error receiving message: {e}")
                    self.root.after(0, self.on_connection_lost)
                break

    def handle_message(self, message):
        if message.get("success"):
            if "username" in message:
                if "unread" in message:
                    self.username = message["username"]
                    self.status_var.set(f"Logged in as: {self.username}")
                    self.notebook.select(1)
                    messagebox.showinfo("Messages", f"You have {message['unread']} unread messages")
                else:
                    messagebox.showinfo("Account Created", "Account created successfully! Please log in to continue.")
            elif message.get("message_type") == "new_message":
                messagebox.showinfo("New Message", 
                    f"New message from {message['message']['from']}")
                    
            elif "messages" in message:
                self.clear_messages()
                for msg in message["messages"]:
                    frame = MessageFrame(self.messages_frame, msg)
                    frame.message_id = msg["id"]
                    frame.pack(fill='x', padx=5, pady=2)
                    
            elif "users" in message:
                self.accounts_list.delete(*self.accounts_list.get_children())
                
                for user in message["users"]:
                    username = user["username"]
                    status = user["status"]
                    self.accounts_list.insert("", "end", values=(username, status))
                
                # Update both total and online user counts
                total_users = len(message['users'])
                online_users = sum(1 for user in message['users'] if user['status'] == 'online')
                self.user_count_var.set(f"Users found: {total_users}")
                self.online_count_var.set(f"Online users: {online_users}")
                    
            elif message.get("message") == "Logged out successfully":
                self.username = None
                self.status_var.set("Not logged in")
                self.notebook.select(0)
                self.clear_messages()
                    
            elif message.get("message") == "Account deleted":
                self.username = None
                self.status_var.set("Not logged in")
                self.notebook.select(0)
                self.clear_messages()
                messagebox.showinfo("Success", "Account deleted successfully")
        else:
            messagebox.showerror("Error", message.get("message", "Unknown error occurred"))

    def on_connection_lost(self):
        if self.running:
            self.running = False
            messagebox.showerror("Error", "Connection to server lost")
            self.root.destroy()

    def run(self):
        def check_users_periodically():
            if self.username and self.running:
                self.search_accounts()
                self.root.after(1000, check_users_periodically)

        self.root.after(1000, check_users_periodically)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.search_accounts()
        self.root.mainloop()

    def on_closing(self):
        self.running = False
        if self.username:
            try:
                self.logout()
            except:
                pass
        try:
            self.socket.close()
        except:
            pass
        self.root.destroy()

def main():
    parser = argparse.ArgumentParser(description="Chat Client")
    parser.add_argument("host", help="Server IP")
    parser.add_argument("--json", action="store_true", help="Use JSON wire protocol")
    parser.add_argument("--custom", action="store_true", help="Use custom wire protocol")

    args = parser.parse_args()
    use_json = args.json  # Default to JSON if specified

    client = ChatClient(args.host, use_json)
    client.run()

if __name__ == "__main__":
    main()