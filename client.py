import socket
import struct
import threading
import tkinter as tk
import time
import argparse
from tkinter import ttk, messagebox
from config import Config

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
        payload_parts should be a list of bytes or strings to be encoded
        """
        # Encode each payload part
        encoded_payload = []
        for part in payload_parts:
            if isinstance(part, str):
                # Encode string with length prefix
                encoded_str = part.encode('utf-8')
                encoded_payload.append(struct.pack('!H', len(encoded_str)))
                encoded_payload.append(encoded_str)
            elif isinstance(part, bytes):
                encoded_payload.append(part)
            elif isinstance(part, list):
                # For list of message IDs
                encoded_payload.append(struct.pack('!H', len(part)))
                for item in part:
                    encoded_payload.append(struct.pack('!I', item))
            elif isinstance(part, bool):
                # For boolean values
                encoded_payload.append(struct.pack('!?', part))
            elif isinstance(part, int):
                # For counts and IDs
                encoded_payload.append(struct.pack('!H', part))
        
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
        length = struct.unpack('!H', data[:2])[0]
        return data[2:2+length].decode('utf-8'), data[2+length:]

    @staticmethod
    def decode_success_response(payload):
        """
        Decode a standard success response
        Returns (success, message, remaining_payload)
        """
        success = struct.unpack('!?', payload[:1])[0]
        payload = payload[1:]
        
        # Decode message string
        message, payload = CustomWireProtocol.decode_string(payload)
        
        return success, message, payload

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
        self.root = tk.Tk()
        self.root.title("Chat Application (Custom Wire Protocol)")
        self.root.geometry("1000x800")
        
        self.config = Config()
        self.host = host
        self.port = self.config.get("port")
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.protocol = CustomWireProtocol()
        
        try:
            self.socket.connect((self.host, self.port))
        except ConnectionRefusedError:
            messagebox.showerror("Error", "Could not connect to server")
            self.root.destroy()
            return
            
        self.username = None
        self.setup_gui()
        self.running = True
        threading.Thread(target=self.receive_messages, daemon=True).start()
        
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
        
        # Encode create account message using custom wire protocol
        message = self.protocol.encode_message(
            CustomWireProtocol.CMD_CREATE, 
            [username, password]
        )
        
        try:
            self.socket.send(message)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send create account request: {e}")
            self.on_connection_lost()

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showwarning("Warning", "Please enter username and password")
            return
        
        # Encode login message using custom wire protocol
        message = self.protocol.encode_message(
            CustomWireProtocol.CMD_LOGIN, 
            [username, password]
        )
        
        try:
            self.socket.send(message)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send login request: {e}")
            self.on_connection_lost()

    def send_message(self):
        if not self.username:
            messagebox.showwarning("Warning", "Please login first")
            return
            
        recipient = self.recipient_var.get()
        message = self.message_text.get("1.0", tk.END).strip()
        
        if not recipient or not message:
            messagebox.showwarning("Warning", "Please enter recipient and message")
            return
        
        # Encode send message using custom wire protocol
        message_payload = self.protocol.encode_message(
            CustomWireProtocol.CMD_SEND, 
            [recipient, message]
        )
        
        try:
            self.socket.send(message_payload)
            self.message_text.delete("1.0", tk.END)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send message: {e}")
            self.on_connection_lost()

    def search_accounts(self):
        pattern = self.search_var.get()
        if pattern and not pattern.endswith("*"):
            pattern = pattern + "*"
        
        # Encode list accounts message
        message = self.protocol.encode_message(
            CustomWireProtocol.CMD_LIST, 
            [pattern]
        )
        
        try:
            self.socket.send(message)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to search accounts: {e}")
            self.on_connection_lost()

    def delete_selected_messages(self):
        selected_ids = []
        for widget in self.messages_frame.winfo_children():
            if isinstance(widget, MessageFrame) and widget.select_var.get():
                selected_ids.append(widget.message_id)
        
        if selected_ids:
            if messagebox.askyesno("Confirm", f"Delete {len(selected_ids)} selected messages?"):
                # Encode delete messages
                message = self.protocol.encode_message(
                    CustomWireProtocol.CMD_DELETE_MESSAGES, 
                    [selected_ids]
                )
                
                try:
                    self.socket.send(message)
                    # Remove the message frames immediately
                    for widget in self.messages_frame.winfo_children():
                        if isinstance(widget, MessageFrame) and widget.message_id in selected_ids:
                            widget.destroy()
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to delete messages: {e}")
                    self.on_connection_lost()

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
            # Encode delete account message
            message = self.protocol.encode_message(
                CustomWireProtocol.CMD_DELETE_ACCOUNT, 
                [password]
            )
            
            try:
                self.socket.send(message)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete account: {e}")
                self.on_connection_lost()

    def logout(self):
        if self.username:
            # Encode logout message
            message = self.protocol.encode_message(
                CustomWireProtocol.CMD_LOGOUT, 
                []
            )
            
            try:
                self.socket.send(message)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to logout: {e}")
                self.on_connection_lost()

    def refresh_messages(self):
        """Get all messages for history view"""
        try:
            count = int(self.msg_count.get())
        except ValueError:
            count = self.config.get("message_fetch_limit")
        
        # Encode get messages request
        message = self.protocol.encode_message(
            CustomWireProtocol.CMD_GET_MESSAGES, 
            [count]
        )
        
        try:
            self.socket.send(message)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get messages: {e}")
            self.on_connection_lost()

    def refresh_unread_messages(self):
        """Get only undelivered messages"""
        try:
            count = int(self.msg_count.get())
        except ValueError:
            count = self.config.get("message_fetch_limit")
        
        # Encode get unread messages request
        message = self.protocol.encode_message(
            CustomWireProtocol.CMD_GET_UNDELIVERED, 
            [count]
        )
        
        try:
            self.socket.send(message)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get unread messages: {e}")
            self.on_connection_lost()

    def receive_messages(self):
        buffer = b''
        while self.running:
            try:
                chunk = self.socket.recv(4096)
                if not chunk:
                    self.on_connection_lost()
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
                    
                    # Process the message
                    self.root.after(0, self.handle_message, cmd, payload)
                    
            except Exception as e:
                if self.running:
                    print(f"Error receiving message: {e}")
                    self.root.after(0, self.on_connection_lost)
                break

    def handle_message(self, cmd, payload):
        try:
            # Decode success response
            success, message, remaining_payload = self.protocol.decode_success_response(payload)
            
            if success:
                # Handle different command responses
                if cmd == CustomWireProtocol.CMD_LOGIN:
                    # Login success - username is the message
                    self.username = message
                    # Decode unread count
                    unread_count = struct.unpack('!H', remaining_payload)[0] if remaining_payload else 0
                    self.status_var.set(f"Logged in as: {self.username}")
                    self.notebook.select(1)
                    messagebox.showinfo("Login", f"Successfully logged in. {unread_count} unread messages.")
                
                elif cmd == CustomWireProtocol.CMD_CREATE:
                    messagebox.showinfo("Account Created", "Account created successfully! Please log in to continue.")
                
                elif cmd == CustomWireProtocol.CMD_LIST:
                    # Decode list of users
                    users = []
                    while remaining_payload:
                        # Decode username
                        username, remaining_payload = self.protocol.decode_string(remaining_payload)
                        # Decode status 
                        status, remaining_payload = self.protocol.decode_string(remaining_payload)
                        users.append({"username": username, "status": status})
                    
                    # Update accounts list
                    self.accounts_list.delete(*self.accounts_list.get_children())
                    for user in users:
                        self.accounts_list.insert("", "end", values=(user["username"], user["status"]))
                    
                    # Update both total and online user counts
                    total_users = len(users)
                    online_users = sum(1 for user in users if user['status'] == 'online')
                    self.user_count_var.set(f"Users found: {total_users}")
                    self.online_count_var.set(f"Online users: {online_users}")
                
                elif cmd == CustomWireProtocol.CMD_GET_MESSAGES or cmd == CustomWireProtocol.CMD_GET_UNDELIVERED:
                    # Decode messages
                    messages = []
                    while remaining_payload:
                        # Ensure enough bytes for message ID
                        if len(remaining_payload) < 4:
                            break
                        
                        # Decode message ID
                        msg_id = struct.unpack('!I', remaining_payload[:4])[0]
                        remaining_payload = remaining_payload[4:]
                        
                        # Decode sender
                        sender, remaining_payload = self.protocol.decode_string(remaining_payload)
                        
                        # Decode content
                        content, remaining_payload = self.protocol.decode_string(remaining_payload)
                        
                        # Decode timestamp
                        if len(remaining_payload) < 8:
                            break
                        timestamp = struct.unpack('!d', remaining_payload[:8])[0]
                        remaining_payload = remaining_payload[8:]
                        
                        messages.append({
                            "id": msg_id,
                            "from": sender,
                            "content": content,
                            "timestamp": timestamp
                        })
                    
                    # Clear existing messages
                    self.clear_messages()
                    
                    # Display messages
                    for msg in messages:
                        frame = MessageFrame(self.messages_frame, msg)
                        frame.pack(fill='x', padx=5, pady=2)
                
                elif cmd == CustomWireProtocol.CMD_LOGOUT:
                    self.username = None
                    self.status_var.set("Not logged in")
                    self.notebook.select(0)
                    self.clear_messages()
                    messagebox.showinfo("Logout", "Logged out successfully")
                
                elif cmd == CustomWireProtocol.CMD_DELETE_ACCOUNT:
                    self.username = None
                    self.status_var.set("Not logged in")
                    self.notebook.select(0)
                    self.clear_messages()
                    messagebox.showinfo("Success", "Account deleted successfully")
            
            else:
                # Handle error cases
                messagebox.showerror("Error", message)
        
        except Exception as e:
            # More robust error handling
            print(f"Error processing message: {e}")
            # Prevent the entire error from breaking the receive loop
            self.status_var.set(f"Error: {str(e)}")

    def clear_messages(self):
        for widget in self.messages_frame.winfo_children():
            widget.destroy()

    def on_user_select(self, event):
        selection = self.accounts_list.selection()
        if selection:
            item = self.accounts_list.item(selection[0])
            username = item['values'][0]
            self.recipient_var.set(username)
            self.notebook.select(1)  # Switch to chat tab

    def on_closing(self):
        self.running = False
        if self.username:
            try:
                # Encode logout message
                message = self.protocol.encode_message(
                    CustomWireProtocol.CMD_LOGOUT, 
                    []
                )
                self.socket.send(message)
            except:
                pass
        try:
            self.socket.close()
        except:
            pass
        self.root.destroy()

    def on_connection_lost(self):
        if self.running:
            self.running = False
            messagebox.showerror("Error", "Connection to server lost")
            self.root.destroy()

    def run(self):
        def check_users_periodically():
            try:
                if self.username and self.running:
                    self.search_accounts()
            except Exception as e:
                print(f"Error in periodic user check: {e}")
            finally:
                # Always schedule the next check, even if there's an error
                self.root.after(5000, check_users_periodically)

        self.root.after(5000, check_users_periodically)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.search_accounts()
        self.root.mainloop()

def main():
    parser = argparse.ArgumentParser(description="Chat Client (Custom Wire Protocol)")
    parser.add_argument("host", help="Server IP or hostname")
    args = parser.parse_args()

    client = ChatClient(args.host)
    client.run()

if __name__ == "__main__":
    main()