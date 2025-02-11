import socket
import threading
import tkinter as tk
import time
import argparse
import struct
from tkinter import ttk, messagebox
from config import Config

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
    def __init__(self, host):
        self.config = Config()
        self.host = host
        self.port = self.config.get("port")
        self.username = None
        self.running = False
        
        # Create the root window first
        self.root = tk.Tk()
        self.root.title("Chat Application")
        self.root.geometry("1000x800")
        
        # Show connecting message
        self.connecting_label = ttk.Label(self.root, text="Connecting to server...")
        self.connecting_label.pack(expand=True)
        
        # Schedule connection attempt after GUI starts
        self.root.after(100, self.connect_to_server)
        
    def connect_to_server(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(5.0)  # Add timeout for connection
            self.socket.connect((self.host, self.port))
            self.socket.settimeout(None)  # Remove timeout for normal operation
            
            # Initialize variables
            self.search_var = tk.StringVar()
            self.user_count_var = tk.StringVar(value="Users found: 0")
            self.online_count_var = tk.StringVar(value="Online users: 0")
            self.recipient_var = tk.StringVar()
            self.status_var = tk.StringVar(value="Not logged in")
            
            # Connection successful, setup GUI
            self.connecting_label.destroy()
            self.setup_gui()
            self.running = True
            threading.Thread(target=self.receive_messages, daemon=True).start()
            
        except ConnectionRefusedError:
            messagebox.showerror("Error", "Could not connect to server")
            self.root.destroy()
        except Exception as e:
            messagebox.showerror("Error", f"Connection error: {e}")
            self.root.destroy()
        
    def pack_message(self, msg_type, payload=b""):
        """Pack message into binary format with header"""
        if isinstance(payload, str):
            payload = payload.encode()
        version = 0x01  # Protocol version 1
        success = 0x01  # Not used in client->server messages
        header = struct.pack("!BBBI", version, msg_type, success, len(payload))
        return header + payload

    def unpack_message(self, header, payload=b""):
        """Unpack binary message"""
        version, msg_type, success, length = struct.unpack("!BBBI", header)
        return version, msg_type, bool(success), payload.decode() if payload else ""

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
        
        ttk.Label(controls, text="Messages to fetch:").pack()
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
        
        send_frame = ttk.LabelFrame(self.accounts_frame, text="Send Message", padding=5)
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
        
        payload = f"{username}{UNIT_SEP.decode()}{password}"
        message = self.pack_message(MessageType.CREATE_ACCOUNT, payload)
        try:
            self.socket.send(message)
            response_header = self.socket.recv(7)
            version, msg_type, success, length = struct.unpack("!BBBI", response_header)
            response_payload = self.socket.recv(length) if length > 0 else b""
            
            if success:
                messagebox.showinfo("Success", "Account created successfully! Please log in.")
            else:
                messagebox.showerror("Error", response_payload.decode())
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create account: {e}")

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showwarning("Warning", "Please enter username and password")
            return
        
        payload = f"{username}{UNIT_SEP.decode()}{password}"
        message = self.pack_message(MessageType.LOGIN, payload)
        try:
            self.socket.send(message)
            response_header = self.socket.recv(7)
            version, msg_type, success, length = struct.unpack("!BBBI", response_header)
            response_payload = self.socket.recv(length) if length > 0 else b""
            
            if success:
                username, unread_count = response_payload.decode().split(UNIT_SEP.decode())
                self.username = username
                self.status_var.set(f"Logged in as: {self.username}")
                self.notebook.select(1)  # Switch to users tab
                messagebox.showinfo("Login Successful", f"You have {unread_count} unread messages")
                self.search_accounts()  # Refresh user list
            else:
                messagebox.showerror("Error", response_payload.decode())
        except Exception as e:
            messagebox.showerror("Error", f"Failed to login: {e}")

    def send_message(self):
        if not self.username:
            messagebox.showwarning("Warning", "Please login first")
            return
            
        recipient = self.recipient_var.get()
        message = self.message_text.get("1.0", tk.END).strip()
        
        if not recipient or not message:
            messagebox.showwarning("Warning", "Please enter recipient and message")
            return
            
        payload = f"{recipient}{UNIT_SEP.decode()}{message}"
        message_data = self.pack_message(MessageType.SEND_MESSAGE, payload)
        try:
            self.socket.send(message_data)
            response_header = self.socket.recv(7)
            version, msg_type, success, length = struct.unpack("!BBBI", response_header)
            response_payload = self.socket.recv(length) if length > 0 else b""
            
            if success:
                self.message_text.delete("1.0", tk.END)
            else:
                messagebox.showerror("Error", response_payload.decode())
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send message: {e}")

    def refresh_messages(self):
        try:
            count = int(self.msg_count.get())
        except ValueError:
            count = self.config.get("message_fetch_limit")
                
        message = self.pack_message(MessageType.GET_MESSAGES, str(count))
        try:
            self.socket.send(message)
            response_header = self.socket.recv(7)
            version, msg_type, success, length = struct.unpack("!BBBI", response_header)
            response_payload = self.socket.recv(length) if length > 0 else b""
            
            if success:
                self.clear_messages()
                if response_payload:
                    message_list = response_payload.decode().split(RECORD_SEP.decode())
                    for msg_str in message_list:
                        msg_id, sender, content, timestamp = msg_str.split(GROUP_SEP.decode())
                        message_data = {
                            "id": int(msg_id),
                            "from": sender,
                            "content": content,
                            "timestamp": float(timestamp)
                        }
                        frame = MessageFrame(self.messages_frame, message_data)
                        frame.pack(fill='x', padx=5, pady=2)
            else:
                messagebox.showerror("Error", response_payload.decode())
        except Exception as e:
            messagebox.showerror("Error", f"Failed to fetch messages: {e}")

    def refresh_unread_messages(self):
        try:
            count = int(self.msg_count.get())
        except ValueError:
            count = self.config.get("message_fetch_limit")
                
        message = self.pack_message(MessageType.GET_UNDELIVERED, str(count))
        try:
            self.socket.send(message)
            response_header = self.socket.recv(7)
            version, msg_type, success, length = struct.unpack("!BBBI", response_header)
            response_payload = self.socket.recv(length) if length > 0 else b""
            
            if success:
                self.clear_messages()
                if response_payload:
                    message_list = response_payload.decode().split(RECORD_SEP.decode())
                    for msg_str in message_list:
                        msg_id, sender, content, timestamp = msg_str.split(GROUP_SEP.decode())
                        message_data = {
                            "id": int(msg_id),
                            "from": sender,
                            "content": content,
                            "timestamp": float(timestamp)
                        }
                        frame = MessageFrame(self.messages_frame, message_data)
                        frame.pack(fill='x', padx=5, pady=2)
            else:
                messagebox.showerror("Error", response_payload.decode())
        except Exception as e:
            messagebox.showerror("Error", f"Failed to fetch unread messages: {e}")

    def search_accounts(self):
        pattern = self.search_var.get()
        if pattern and not pattern.endswith("*"):
            pattern = pattern + "*"
            
        message = self.pack_message(MessageType.LIST_ACCOUNTS, pattern)
        try:
            self.socket.send(message)
            response_header = self.socket.recv(7)
            version, msg_type, success, length = struct.unpack("!BBBI", response_header)
            response_payload = self.socket.recv(length) if length > 0 else b""
            
            if success:
                self.accounts_list.delete(*self.accounts_list.get_children())
                if response_payload:
                    users = response_payload.decode().split(RECORD_SEP.decode())
                    online_count = 0
                    for user_str in users:
                        if GROUP_SEP.decode() in user_str:  # Check if the string contains the separator
                            username, status = user_str.split(GROUP_SEP.decode())
                            self.accounts_list.insert("", "end", values=(username, status))
                            if status == "online":
                                online_count += 1
                        else:
                            # Handle malformed user string
                            print(f"Malformed user string received: {user_str}")
                            continue
                    
                    self.user_count_var.set(f"Users found: {len(users)}")
                    self.online_count_var.set(f"Online users: {online_count}")
            else:
                messagebox.showerror("Error", response_payload.decode())
        except Exception as e:
            messagebox.showerror("Error", f"Failed to fetch user list: {e}")

    def delete_selected_messages(self):
        selected_ids = []
        for widget in self.messages_frame.winfo_children():
            if isinstance(widget, MessageFrame) and widget.select_var.get():
                selected_ids.append(widget.message_id)
        
        if selected_ids:
            if messagebox.askyesno("Confirm", f"Delete {len(selected_ids)} selected messages?"):
                payload = GROUP_SEP.decode().join(str(id) for id in selected_ids)
                message = self.pack_message(MessageType.DELETE_MESSAGES, payload)
                try:
                    self.socket.send(message)
                    response_header = self.socket.recv(7)
                    version, msg_type, success, length = struct.unpack("!BBBI", response_header)
                    response_payload = self.socket.recv(length) if length > 0 else b""
                    
                    if success:
                        for widget in self.messages_frame.winfo_children():
                            if isinstance(widget, MessageFrame) and widget.message_id in selected_ids:
                                widget.destroy()
                    else:
                        messagebox.showerror("Error", response_payload.decode())
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to delete messages: {e}")

    def delete_account(self):
        if not self.username:
            messagebox.showwarning("Warning", "Please login first")
            return
            
        password = self.delete_password.get()
        if not password:
            messagebox.showwarning("Warning", "Please enter your password")
            return
            
        if messagebox.askyesno("Confirm", "Delete your account? This cannot be undone."):
            message = self.pack_message(MessageType.DELETE_ACCOUNT, password)
            try:
                self.socket.send(message)
                response_header = self.socket.recv(7)
                version, msg_type, success, length = struct.unpack("!BBBI", response_header)
                response_payload = self.socket.recv(length) if length > 0 else b""
                
                if success:
                    self.username = None
                    self.status_var.set("Not logged in")
                    self.notebook.select(0)
                    self.clear_messages()
                    messagebox.showinfo("Success", "Account deleted successfully")
                else:
                    messagebox.showerror("Error", response_payload.decode())
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete account: {e}")

    def logout(self):
        if self.username:
            message = self.pack_message(MessageType.LOGOUT)
            try:
                self.socket.send(message)
                response_header = self.socket.recv(7)
                version, msg_type, success, length = struct.unpack("!BBBI", response_header)
                response_payload = self.socket.recv(length) if length > 0 else b""
                
                if success:
                    self.username = None
                    self.status_var.set("Not logged in")
                    self.notebook.select(0)
                    self.clear_messages()
                else:
                    messagebox.showerror("Error", response_payload.decode())
            except Exception as e:
                messagebox.showerror("Error", f"Failed to logout: {e}")

    def on_user_select(self, event):
        selection = self.accounts_list.selection()
        if selection:
            item = self.accounts_list.item(selection[0])
            username = item['values'][0]
            self.recipient_var.set(username)
            self.notebook.select(2)  # Switch to chat tab

    def clear_messages(self):
        for widget in self.messages_frame.winfo_children():
            widget.destroy()

    def send_and_receive(self, message, timeout=5.0):
        """Send a message and receive response with timeout"""
        try:
            self.socket.settimeout(timeout)
            self.socket.send(message)
            
            # Receive header
            response_header = self.socket.recv(7)
            if len(response_header) != 7:
                raise ConnectionError("Incomplete response header")
                
            version, msg_type, success, length = struct.unpack("!BBBI", response_header)
            
            # Receive payload if any
            response_payload = b""
            while length > 0:
                chunk = self.socket.recv(min(length, 4096))
                if not chunk:
                    raise ConnectionError("Connection closed while receiving payload")
                response_payload += chunk
                length -= len(chunk)
                
            self.socket.settimeout(None)
            return version, msg_type, success, response_payload
            
        except socket.timeout:
            raise TimeoutError("Server response timeout")
        finally:
            self.socket.settimeout(None)
            
    def create_account(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showwarning("Warning", "Please enter username and password")
            return
        
        payload = f"{username}{UNIT_SEP.decode()}{password}"
        message = self.pack_message(MessageType.CREATE_ACCOUNT, payload)
        
        try:
            version, msg_type, success, response_payload = self.send_and_receive(message)
            
            if success:
                messagebox.showinfo("Success", "Account created successfully! Please log in.")
            else:
                messagebox.showerror("Error", response_payload.decode())
                
        except TimeoutError:
            messagebox.showerror("Error", "Server not responding")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create account: {e}")
            
    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showwarning("Warning", "Please enter username and password")
            return
        
        payload = f"{username}{UNIT_SEP.decode()}{password}"
        message = self.pack_message(MessageType.LOGIN, payload)
        
        try:
            version, msg_type, success, response_payload = self.send_and_receive(message)
            
            if success:
                username, unread_count = response_payload.decode().split(UNIT_SEP.decode())
                self.username = username
                self.status_var.set(f"Logged in as: {self.username}")
                self.notebook.select(1)  # Switch to users tab
                messagebox.showinfo("Login Successful", f"You have {unread_count} unread messages")
                self.search_accounts()  # Refresh user list
            else:
                messagebox.showerror("Error", response_payload.decode())
                
        except TimeoutError:
            messagebox.showerror("Error", "Server not responding")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to login: {e}")

    def receive_messages(self):
        """Handle incoming messages from server"""
        while self.running:
            try:
                self.socket.settimeout(1.0)  # Short timeout for checking running status
                header = self.socket.recv(7)
                
                if not header or len(header) != 7:
                    if self.running:  # Only show error if we're still meant to be running
                        self.root.after(0, self.on_connection_lost)
                    break

                version, msg_type, success, length = struct.unpack("!BBBI", header)
                
                # Receive payload if any
                payload = b""
                while length > 0:
                    chunk = self.socket.recv(min(length, 4096))
                    if not chunk:
                        break
                    payload += chunk
                    length -= len(chunk)

                if length > 0:  # Incomplete message
                    if self.running:
                        self.root.after(0, self.on_connection_lost)
                    break

                # Handle message based on type
                if msg_type == MessageType.NOTIFICATION:
                    if success:
                        sender, content = payload.decode().split(GROUP_SEP.decode())
                        self.root.after(0, lambda s=sender: messagebox.showinfo(
                            "New Message", f"New message from {s}"))
                            
            except socket.timeout:
                continue  # Just check running status again
            except Exception as e:
                if self.running:
                    print(f"Error receiving message: {e}")
                    self.root.after(0, self.on_connection_lost)
                break

    def on_connection_lost(self):
        if self.running:
            self.running = False
            messagebox.showerror("Error", "Connection to server lost")
            self.root.destroy()

    def run(self):
        def check_users_periodically():
            if self.username and self.running:
                try:
                    self.search_accounts()
                except Exception as e:
                    print(f"Error in periodic update: {e}")
                finally:
                    if self.running:
                        self.root.after(5000, check_users_periodically)  # Increased interval to 5 seconds

        # Wait a bit for GUI to be fully initialized before starting periodic checks
        self.root.after(5000, check_users_periodically)  # Start first check after 5 seconds
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
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
    parser.add_argument("host", help="Server IP or hostname")
    args = parser.parse_args()

    client = ChatClient(args.host)
    client.run()

if __name__ == "__main__":
    main()