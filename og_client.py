import socket
import json
import threading
import tkinter as tk
import time
import argparse
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
    def __init__(self, host):
        self.root = tk.Tk()
        self.root.title("Chat Application")
        self.root.geometry("1000x800")
        
        self.config = Config()
        self.host = host
        self.port = self.config.get("port")
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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
        
        self.send_command({
            "cmd": "create",
            "username": username,
            "password": password
        })

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showwarning("Warning", "Please enter username and password")
            return
        
        self.send_command({
            "cmd": "login",
            "username": username,
            "password": password
        })

    def send_message(self):
        if not self.username:
            messagebox.showwarning("Warning", "Please login first")
            return
            
        recipient = self.recipient_var.get()
        message = self.message_text.get("1.0", tk.END).strip()
        
        if not recipient or not message:
            messagebox.showwarning("Warning", "Please enter recipient and message")
            return
            
        self.send_command({
            "cmd": "send",
            "to": recipient,
            "content": message
        })
        
        self.message_text.delete("1.0", tk.END)

    def delete_message(self, msg_id):
        if messagebox.askyesno("Confirm", "Delete this message?"):
            self.send_command({
                "cmd": "delete_messages",
                "message_ids": [msg_id]
            })
            # Remove the message frame immediately
            for widget in self.messages_frame.winfo_children():
                if isinstance(widget, MessageFrame) and getattr(widget, 'message_id', None) == msg_id:
                    widget.destroy()
                    break

    def delete_selected_messages(self):
        selected_ids = []
        for widget in self.messages_frame.winfo_children():
            if isinstance(widget, MessageFrame) and widget.select_var.get():
                selected_ids.append(widget.message_id)
        
        if selected_ids:
            if messagebox.askyesno("Confirm", f"Delete {len(selected_ids)} selected messages?"):
                self.send_command({
                    "cmd": "delete_messages",
                    "message_ids": selected_ids
                })
                # Remove the message frames immediately
                for widget in self.messages_frame.winfo_children():
                    if isinstance(widget, MessageFrame) and widget.message_id in selected_ids:
                        widget.destroy()

    def refresh_messages(self):
        """Get all messages for history view"""
        try:
            count = int(self.msg_count.get())
        except ValueError:
            count = self.config.get("message_fetch_limit")
                
        self.send_command({
            "cmd": "get_messages",
            "count": count
        })

    def refresh_unread_messages(self):
        """Get only undelivered messages"""
        try:
            count = int(self.msg_count.get())
        except ValueError:
            count = self.config.get("message_fetch_limit") 
                
        self.send_command({
            "cmd": "get_undelivered",
            "count": count
        })

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
        self.send_command({
            "cmd": "list",
            "pattern": pattern
        })

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
            self.send_command({
                "cmd": "delete_account",
                "password": password
            })

    def logout(self):
        if self.username:
            self.send_command({"cmd": "logout"})

    def clear_messages(self):
        for widget in self.messages_frame.winfo_children():
            widget.destroy()

    def send_command(self, command):
        """Ensure every command includes the version field before sending."""
        command["version"] = "1.0"  # Add version to every message
        try:
            self.socket.send(json.dumps(command).encode())
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send command: {e}")
            self.on_connection_lost()

    def receive_messages(self):
        buffer = ""
        while self.running:
            try:
                data = self.socket.recv(4096).decode()
                if not data:
                    self.on_connection_lost()
                    break
                    
                buffer += data
                
                # Process complete JSON messages
                while True:
                    try:
                        message_end = buffer.index("}{") if "}{" in buffer else len(buffer)
                        message = json.loads(buffer[:message_end+1])
                        buffer = buffer[message_end+1:]
                        
                        self.root.after(0, self.handle_message, message)
                    except ValueError:
                        # Incomplete message or no more complete messages
                        break
                    
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
    parser.add_argument("host", help="Server IP or hostname")
    args = parser.parse_args()

    client = ChatClient(args.host)
    client.run()

if __name__ == "__main__":
    main()