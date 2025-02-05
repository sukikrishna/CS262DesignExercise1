from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit, QLineEdit, QLabel
import sys
from client import ChatClient

class ChatGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.client = ChatClient(use_json=True)  # Set to False for Custom Binary Protocol
        self.init_ui()
    
    def init_ui(self):
        self.setWindowTitle("Chat Application")
        self.setGeometry(100, 100, 400, 500)
        
        layout = QVBoxLayout()
        
        self.username_label = QLabel("Username:")
        self.username_input = QLineEdit()
        self.password_label = QLabel("Password:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        
        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.login)
        
        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        
        self.message_input = QLineEdit()
        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self.send_message)
        
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.login_button)
        layout.addWidget(self.chat_display)
        layout.addWidget(self.message_input)
        layout.addWidget(self.send_button)
        
        self.setLayout(layout)
    
    def login(self):
        username = self.username_input.text()
        password = self.password_input.text()
        success = self.client.login(username, password)
        if success:
            self.chat_display.append("Logged in successfully.")
        else:
            self.chat_display.append("Login failed.")
    
    def send_message(self):
        message = self.message_input.text()
        self.client.send_message(self.username_input.text(), "bob", message)
        self.chat_display.append(f"You: {message}")
        self.message_input.clear()
    
if __name__ == "__main__":
    app = QApplication(sys.argv)
    gui = ChatGUI()
    gui.show()
    sys.exit(app.exec_())