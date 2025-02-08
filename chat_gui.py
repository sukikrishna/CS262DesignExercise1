#chat_gui.py

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import json
import argparse
import configparser
from typing import Optional, List, Dict
from datetime import datetime
from custom_protocol import CustomProtocolClient
import threading
import time

class ChatGUI:
    def __init__(self, protocol_type: str = "custom", config_file: Optional[str] = None):
        self.root = tk.Tk()
        self.root.title("Chat Application")
        self.root.geometry("1000x600")
        
        # Initialize connection parameters
        self.host = "localhost"
        self.port = 50002
        
        # Load config if provided
        if config_file:
            self.load_config(config_file)
            
        # Initialize client
        self.client = CustomProtocolClient(self.host, self.port)
        
        # Initialize state variables
        self.current_chat_user = None
        self.message_update_thread = None
        self.message_update_active = False
        self.chat_history = {}  # Store chat history for each user
        
        self.setup_gui()
        self.connect_to_server()
        
    def load_config(self, config_file: str):
        """Load connection settings from config file"""
        config = configparser.ConfigParser()
        config.read(config_file)
        
        if 'Connection' in config:
            self.host = config['Connection'].get('host', self.host)
            self.port = config['Connection'].getint('port', self.port)
            
    def setup_gui(self):
        """Set up the GUI components"""
        # Create main container
        self.main_container = ttk.Frame(self.root, padding="10")
        self.main_container.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Create notebook for different sections
        self.notebook = ttk.Notebook(self.main_container)
        self.notebook.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Create all frames
        self.auth_frame = ttk.Frame(self.notebook, padding="10")
        self.chat_frame = ttk.Frame(self.notebook, padding="10")
        self.accounts_frame = ttk.Frame(self.notebook, padding="10")
        self.settings_frame = ttk.Frame(self.notebook, padding="10")
        
        # Add frames to notebook
        self.notebook.add(self.auth_frame, text="Login/Register")
        self.notebook.add(self.accounts_frame, text="Accounts")
        self.notebook.add(self.chat_frame, text="Messages")
        self.notebook.add(self.settings_frame, text="Settings")
        
        # Setup all frames
        self.setup_auth_frame()
        self.setup_accounts_frame()
        self.setup_chat_frame()
        self.setup_settings_frame()
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        self.main_container.columnconfigure(0, weight=1)
        self.main_container.rowconfigure(0, weight=1)
        
    def setup_auth_frame(self):
        """Set up the authentication frame"""
        # Username field
        ttk.Label(self.auth_frame, text="Username:").grid(row=0, column=0, pady=5)
        self.username_var = tk.StringVar()
        self.username_entry = ttk.Entry(self.auth_frame, textvariable=self.username_var)
        self.username_entry.grid(row=0, column=1, pady=5)
        
        # Password field
        ttk.Label(self.auth_frame, text="Password:").grid(row=1, column=0, pady=5)
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(self.auth_frame, textvariable=self.password_var, show="*")
        self.password_entry.grid(row=1, column=1, pady=5)
        
        # Buttons
        ttk.Button(self.auth_frame, text="Login", command=self.login).grid(row=2, column=0, pady=10)
        ttk.Button(self.auth_frame, text="Register", command=self.register).grid(row=2, column=1, pady=10)
        
    def setup_accounts_frame(self):
        """Set up the accounts listing frame"""
        # Search frame
        search_frame = ttk.Frame(self.accounts_frame)
        search_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=5)
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(search_frame, text="Search", command=self.search_accounts).pack(side=tk.LEFT, padx=5)
        
        # Accounts list with more details
        columns = ('username', 'status', 'unread')
        self.accounts_tree = ttk.Treeview(self.accounts_frame, columns=columns, show='headings')
        
        # Define column headings
        self.accounts_tree.heading('username', text='Username')
        self.accounts_tree.heading('status', text='Status')
        self.accounts_tree.heading('unread', text='Unread Messages')
        
        # Define column widths
        self.accounts_tree.column('username', width=150)
        self.accounts_tree.column('status', width=100)
        self.accounts_tree.column('unread', width=100)
        
        self.accounts_tree.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        # Scrollbar for accounts list
        scrollbar = ttk.Scrollbar(self.accounts_frame, orient=tk.VERTICAL, command=self.accounts_tree.yview)
        scrollbar.grid(row=1, column=2, sticky=(tk.N, tk.S))
        self.accounts_tree.configure(yscrollcommand=scrollbar.set)
        
        # Buttons frame
        buttons_frame = ttk.Frame(self.accounts_frame)
        buttons_frame.grid(row=2, column=0, columnspan=2, pady=5)
        
        ttk.Button(buttons_frame, text="Start Chat", command=self.start_chat).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Refresh", command=self.search_accounts).pack(side=tk.LEFT, padx=5)
        
        self.accounts_frame.columnconfigure(0, weight=1)
        self.accounts_frame.rowconfigure(1, weight=1)
        
    def setup_chat_frame(self):
        """Set up the chat frame"""
        # Chat header
        self.chat_header = ttk.Label(self.chat_frame, text="No chat selected", font=('', 12, 'bold'))
        self.chat_header.grid(row=0, column=0, columnspan=2, pady=5, sticky=(tk.W))
        
        # Message display area
        self.message_area = scrolledtext.ScrolledText(self.chat_frame, wrap=tk.WORD)
        self.message_area.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        # Message input area
        self.message_input = scrolledtext.ScrolledText(self.chat_frame, wrap=tk.WORD, height=4)
        self.message_input.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=5)
        
        # Send button
        send_button = ttk.Button(self.chat_frame, text="Send", command=self.send_message)
        send_button.grid(row=2, column=1, pady=5, padx=5)
        
        # Message management
        self.message_list = ttk.Treeview(self.chat_frame, columns=('time', 'content'), show='headings', height=5)
        self.message_list.heading('time', text='Time')
        self.message_list.heading('content', text='Message')
        self.message_list.column('time', width=150)
        self.message_list.column('content', width=400)
        self.message_list.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # Delete button
        ttk.Button(self.chat_frame, text="Delete Selected", command=self.delete_messages).grid(row=4, column=0, columnspan=2, pady=5)
        
        # Configure weights
        self.chat_frame.columnconfigure(0, weight=1)
        self.chat_frame.rowconfigure(1, weight=1)
        
    def setup_settings_frame(self):
        """Set up the settings frame"""
        # Messages per fetch
        ttk.Label(self.settings_frame, text="Messages per fetch:").grid(row=0, column=0, pady=5)
        self.msgs_per_fetch_var = tk.StringVar(value="10")
        ttk.Entry(self.settings_frame, textvariable=self.msgs_per_fetch_var).grid(row=0, column=1, pady=5)
        
        # Delete messages on account deletion
        self.delete_msgs_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(self.settings_frame, text="Delete messages on account deletion",
                       variable=self.delete_msgs_var).grid(row=1, column=0, columnspan=2, pady=5)
        
        # Connection settings
        ttk.Label(self.settings_frame, text="Host:").grid(row=2, column=0, pady=5)
        self.host_var = tk.StringVar(value=self.host)
        ttk.Entry(self.settings_frame, textvariable=self.host_var).grid(row=2, column=1, pady=5)
        
        ttk.Label(self.settings_frame, text="Port:").grid(row=3, column=0, pady=5)
        self.port_var = tk.StringVar(value=str(self.port))
        ttk.Entry(self.settings_frame, textvariable=self.port_var).grid(row=3, column=1, pady=5)
        
        # Save settings button
        ttk.Button(self.settings_frame, text="Save Settings", command=self.save_settings).grid(row=4, column=0, columnspan=2, pady=10)
        
        # Delete account section
        ttk.Label(self.settings_frame, text="Delete Account", font=('', 12, 'bold')).grid(row=5, column=0, columnspan=2, pady=20)
        ttk.Label(self.settings_frame, text="Password:").grid(row=6, column=0, pady=5)
        self.delete_password_var = tk.StringVar()
        ttk.Entry(self.settings_frame, textvariable=self.delete_password_var, show="*").grid(row=6, column=1, pady=5)
        
        # Delete account button
        ttk.Button(self.settings_frame, text="Delete Account",
                  command=self.delete_account,
                  style="Danger.TButton").grid(row=7, column=0, columnspan=2, pady=10)
        
        # Logout button
        ttk.Button(self.settings_frame, text="Logout",
                  command=self.logout).grid(row=8, column=0, columnspan=2, pady=20)
        
    def connect_to_server(self):
        """Connect to the chat server"""
        if not self.client.connect():
            messagebox.showerror("Connection Error", "Failed to connect to server")
            self.root.quit()
            
    def login(self):
        """Handle login attempt"""
        username = self.username_var.get()
        password = self.password_var.get()
        
        if not username or not password:
            messagebox.showwarning("Warning", "Please enter both username and password")
            return
            
        response = self.client.login(username, password)
        if "Login successful" in response:
            messagebox.showinfo("Success", response)
            self.start_message_updates()
            self.notebook.select(1)  # Switch to accounts tab
            self.search_accounts()
        else:
            messagebox.showerror("Error", response)
            
    def register(self):
        """Handle registration attempt"""
        username = self.username_var.get()
        password = self.password_var.get()
        
        if not username or not password:
            messagebox.showwarning("Warning", "Please enter both username and password")
            return
            
        response = self.client.create_account(username, password)
        if "created successfully" in response:
            messagebox.showinfo("Success", response)
        else:
            messagebox.showerror("Error", response)
            
    def search_accounts(self):
        """Search for accounts matching pattern"""
        pattern = self.search_var.get()
        accounts = self.client.list_accounts(pattern)
        
        # Clear existing items
        for item in self.accounts_tree.get_children():
            self.accounts_tree.delete(item)
            
        # Add accounts to tree with more details
        for account_info in accounts:
            if ':' in account_info:
                username, status = account_info.split(':')
                # Get unread message count for this user
                unread_count = 0
                if username in self.chat_history:
                    unread_count = sum(1 for msg in self.chat_history[username] if not msg.get('read', False))
                self.accounts_tree.insert('', tk.END, values=(username, status, unread_count))
                
    def start_chat(self):
        """Start chat with selected user"""
        selection = self.accounts_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a user to chat with")
            return
            
        self.current_chat_user = self.accounts_tree.item(selection[0])['values'][0]
        self.chat_header.config(text=f"Chat with {self.current_chat_user}")
        self.notebook.select(2)  # Switch to chat tab
        self.message_area.delete('1.0', tk.END)
        self.refresh_messages()

    def send_message(self):
        """Send message to current chat user"""
        if not self.current_chat_user:
            messagebox.showwarning("Warning", "No chat recipient selected")
            return
            
        message = self.message_input.get('1.0', tk.END).strip()
        if not message:
            return
            
        response = self.client.send_message(self.current_chat_user, message)
        if "sent successfully" in response:
            self.message_input.delete('1.0', tk.END)
            self.refresh_messages()
        else:
            messagebox.showerror("Error", response)
            
    def refresh_messages(self):
        """Refresh messages in chat and message list"""
        if not self.current_chat_user:
            return
            
        messages = self.client.read_messages()
        
        # Clear message displays
        self.message_area.delete('1.0', tk.END)
        for item in self.message_list.get_children():
            self.message_list.delete(item)
            
        # Process and display messages
        for message in messages:
            if message and ':' in message:
                try:
                    msg_parts = message.split(':', 3)
                    if len(msg_parts) >= 4:
                        msg_id, sender, timestamp, content = msg_parts
                        # Convert timestamp to readable format
                        time_str = datetime.fromtimestamp(float(timestamp)).strftime('%Y-%m-%d %H:%M')
                        
                        # Add to message area
                        self.message_area.insert(tk.END, f"{sender} ({time_str}):\n{content}\n\n")
                        
                        # Add to message list for deletion
                        self.message_list.insert('', tk.END, iid=msg_id, 
                                               values=(time_str, f"{content[:50]}..." if len(content) > 50 else content))
                        
                        # Update chat history
                        if sender not in self.chat_history:
                            self.chat_history[sender] = []
                        self.chat_history[sender].append({
                            'id': msg_id,
                            'content': content,
                            'timestamp': timestamp,
                            'read': True
                        })
                except ValueError:
                    print(f"Error processing message: {message}")
                    continue
                
        self.message_area.see(tk.END)
        self.search_accounts()  # Refresh account list to update unread counts
        
    def delete_messages(self):
        """Delete selected messages"""
        selection = self.message_list.selection()
        if not selection:
            return
            
        if messagebox.askyesno("Confirm", "Delete selected messages?"):
            message_ids = [int(item) for item in selection]
            response = self.client.delete_messages(message_ids)
            if "deleted successfully" in response:
                self.refresh_messages()
            else:
                messagebox.showerror("Error", response)
                
    def save_settings(self):
        """Save user settings"""
        try:
            new_settings = {
                'messages_per_fetch': int(self.msgs_per_fetch_var.get()),
                'delete_messages_on_account_deletion': self.delete_msgs_var.get()
            }
            response = self.client.update_settings(new_settings)
            if "updated successfully" in response:
                messagebox.showinfo("Success", "Settings saved successfully")
            else:
                messagebox.showerror("Error", response)
        except ValueError:
            messagebox.showerror("Error", "Invalid messages per fetch value")
            
    def delete_account(self):
        """Delete user account"""
        if not messagebox.askyesno("Confirm", "Are you sure you want to delete your account? This cannot be undone."):
            return
            
        password = self.delete_password_var.get()
        if not password:
            messagebox.showwarning("Warning", "Please enter your password")
            return
            
        response = self.client.delete_account(password)
        if "deleted successfully" in response:
            messagebox.showinfo("Success", "Account deleted successfully")
            self.notebook.select(0)  # Return to login tab
        else:
            messagebox.showerror("Error", response)
            
    def logout(self):
        """Log out current user"""
        response = self.client.logout()
        if "Logged out successfully" in response:
            self.stop_message_updates()
            self.current_chat_user = None
            self.notebook.select(0)  # Return to login tab
            messagebox.showinfo("Success", "Logged out successfully")
        else:
            messagebox.showerror("Error", response)
            
    def start_message_updates(self):
        """Start background message updates"""
        self.message_update_active = True
        self.message_update_thread = threading.Thread(target=self._update_messages)
        self.message_update_thread.daemon = True
        self.message_update_thread.start()
        
    def stop_message_updates(self):
        """Stop background message updates"""
        self.message_update_active = False
        if self.message_update_thread:
            self.message_update_thread.join()
            
    def _update_messages(self):
        """Background thread for updating messages"""
        while self.message_update_active:
            if self.current_chat_user:
                self.refresh_messages()
            time.sleep(5)  # Update every 5 seconds
            
    def run(self):
        """Start the GUI application"""
        self.root.mainloop()
        self.stop_message_updates()
        self.client.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Chat Client")
    parser.add_argument("--config", type=str, help="Path to config file")
    args = parser.parse_args()
    
    gui = ChatGUI(config_file=args.config)
    gui.run()