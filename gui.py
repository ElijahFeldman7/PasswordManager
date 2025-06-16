# gui.py
import sys
import os
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLineEdit, QLabel, QListWidget, QListWidgetItem,
    QDialog, QMessageBox, QGridLayout, QInputDialog, QDialogButtonBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont

import auth
import sync
import crypto

LOCAL_VAULT_PATH = 'vault.dat'

class Worker(QThread):
    finished = pyqtSignal(object)
    error = pyqtSignal(str)
    status_update = pyqtSignal(str)

    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs

    def run(self):
        try:
            self.status_update.emit(f"Running '{self.fn.__name__}' in background...")
            result = self.fn(*self.args, **self.kwargs)
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))
            self.finished.emit(None)

class AddEditDialog(QDialog):
    def __init__(self, service_name=None, username="", password="", parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add New Password" if service_name is None else f"Edit '{service_name}'")

        layout = QGridLayout(self)

        self.service_input = QLineEdit(service_name)
        self.service_input.setPlaceholderText("Service Name (e.g., Google)")
        self.username_input = QLineEdit(username)
        self.username_input.setPlaceholderText("Username or Email")
        self.password_input = QLineEdit(password)
        self.password_input.setEchoMode(QLineEdit.Password)

        layout.addWidget(QLabel("Service:"), 0, 0)
        layout.addWidget(self.service_input, 0, 1)
        layout.addWidget(QLabel("Username:"), 1, 0)
        layout.addWidget(self.username_input, 1, 1)
        layout.addWidget(QLabel("Password:"), 2, 0)
        layout.addWidget(self.password_input, 2, 1)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons, 3, 0, 1, 2)

    def get_data(self):
        return {
            "service": self.service_input.text().strip(),
            "username": self.username_input.text().strip(),
            "password": self.password_input.text()
        }

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Password Manager")
        self.setGeometry(100, 100, 600, 400)

        self.vault_data = None
        self.master_password = ""
        self.drive_service = None
        
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)

        self.status_label = QLabel("Initializing...")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(self.status_label)
        
        self.password_list = QListWidget()
        self.password_list.itemDoubleClicked.connect(self.view_password)
        self.layout.addWidget(self.password_list)

        button_layout = QHBoxLayout()
        self.add_button = QPushButton("Add Password")
        self.add_button.clicked.connect(self.add_password)
        self.delete_button = QPushButton("Delete Password")
        self.delete_button.clicked.connect(self.delete_password)
        self.sync_button = QPushButton("Save & Sync")
        self.sync_button.clicked.connect(self.save_and_sync)
        
        button_layout.addWidget(self.add_button)
        button_layout.addWidget(self.delete_button)
        button_layout.addWidget(self.sync_button)
        self.layout.addLayout(button_layout)
        
        self.set_ui_locked(True)
        self.start_initialization()

    def set_ui_locked(self, locked):
        """Enable or disable main UI controls."""
        self.password_list.setEnabled(not locked)
        self.add_button.setEnabled(not locked)
        self.delete_button.setEnabled(not locked)
        self.sync_button.setEnabled(not locked)

    def start_initialization(self):
        self.status_label.setText("Authenticating with cloud service...")
        self.worker = Worker(auth.get_drive_service)
        self.worker.finished.connect(self.on_auth_finished)
        self.worker.error.connect(self.show_error)
        self.worker.start()

    def on_auth_finished(self, service):
        if service:
            self.drive_service = service
            self.status_label.setText("Cloud authentication successful. Syncing...")
            self.run_sync()
        else:
            self.status_label.setText("Authentication failed.")
            self.show_error("Could not authenticate with Google Drive.")

    def run_sync(self):
        self.worker = Worker(sync.find_remote_vault, self.drive_service)
        self.worker.finished.connect(self.on_sync_check_finished)
        self.worker.error.connect(self.show_error)
        self.worker.start()

    def on_sync_check_finished(self, result):
        remote_id, _ = result
        if remote_id and not os.path.exists(LOCAL_VAULT_PATH):
            self.status_label.setText("Downloading vault from cloud...")
            self.worker = Worker(sync.download_vault, self.drive_service, remote_id, LOCAL_VAULT_PATH)
            self.worker.finished.connect(self.on_download_finished)
            self.worker.start()
        else:
             self.prompt_for_password()

    def on_download_finished(self, _):
        self.status_label.setText("Vault downloaded.")
        self.prompt_for_password()

    def prompt_for_password(self):
        if os.path.exists(LOCAL_VAULT_PATH):
            while self.vault_data is None:
                password, ok = QInputDialog.getText(self, "Unlock Vault", "Enter Master Password:", QLineEdit.Password)
                if ok and password:
                    self.master_password = password
                    with open(LOCAL_VAULT_PATH, 'rb') as f:
                        salt = f.read(crypto.SALT_LENGTH)
                        encrypted_data = f.read()
                    key = crypto.derive_key(self.master_password, salt)
                    self.vault_data = crypto.decrypt(encrypted_data, key)
                    if self.vault_data is None:
                        QMessageBox.warning(self, "Error", "Incorrect password or corrupted vault.")
                else:
                    self.close()
                    return
        else:
            dialog = QDialog(self)
            dialog.setWindowTitle("Create New Vault")
            layout = QVBoxLayout()

            layout.addWidget(QLabel("No vault found. Please create a new master password."))
            p1_input = QLineEdit()
            p1_input.setEchoMode(QLineEdit.Password)
            p2_input = QLineEdit()
            p2_input.setEchoMode(QLineEdit.Password)
            layout.addWidget(QLabel("New Master Password:"))
            layout.addWidget(p1_input)
            layout.addWidget(QLabel("Confirm Master Password:"))
            layout.addWidget(p2_input)
            
            buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
            layout.addWidget(buttons)
            dialog.setLayout(layout)
            
            buttons.accepted.connect(dialog.accept)
            buttons.rejected.connect(dialog.reject)

            if dialog.exec_():
                p1 = p1_input.text()
                p2 = p2_input.text()
                if p1 and p1 == p2:
                    self.master_password = p1
                    self.vault_data = {'passwords': {}}
                    self.save_and_sync()
                else:
                    QMessageBox.warning(self, "Error", "Passwords do not match or are empty.")
                    self.prompt_for_password()
                    return
            else:
                self.close()
                return

        self.status_label.setText("Vault Unlocked")
        self.set_ui_locked(False)
        self.populate_list()
        
    def populate_list(self):
        self.password_list.clear()
        if self.vault_data:
            for service_name in sorted(self.vault_data['passwords'].keys()):
                self.password_list.addItem(service_name)

    def add_password(self):
        dialog = AddEditDialog(parent=self)
        if dialog.exec_():
            data = dialog.get_data()
            if data['service']:
                self.vault_data['passwords'][data['service']] = {
                    'username': data['username'],
                    'password': data['password']
                }
                self.populate_list()
            else:
                self.show_error("Service name cannot be empty.")

    def view_password(self, item):
        service_name = item.text()
        entry = self.vault_data['passwords'].get(service_name)
        if entry:
            QMessageBox.information(self, f"Credentials for '{service_name}'", 
                f"Username: {entry['username']}\nPassword: {entry['password']}")

    def delete_password(self):
        current_item = self.password_list.currentItem()
        if not current_item:
            self.show_error("Please select a service to delete.")
            return

        service_name = current_item.text()
        reply = QMessageBox.question(self, "Confirm Delete", 
            f"Are you sure you want to delete the entry for '{service_name}'?",
            QMessageBox.Yes | QMessageBox.No, 
            QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            del self.vault_data['passwords'][service_name]
            self.populate_list()

    def save_and_sync(self):
        self.status_label.setText("Encrypting and saving...")
        salt = os.urandom(crypto.SALT_LENGTH)
        key = crypto.derive_key(self.master_password, salt)
        encrypted_blob = crypto.encrypt(self.vault_data, key)
        with open(LOCAL_VAULT_PATH, 'wb') as f:
            f.write(salt)
            f.write(encrypted_blob)
        
        self.status_label.setText("Uploading to cloud...")
        self.worker = Worker(sync.upload_vault, self.drive_service, LOCAL_VAULT_PATH)
        self.worker.finished.connect(lambda: self.status_label.setText("Sync complete."))
        self.worker.error.connect(self.show_error)
        self.worker.start()
        
    def show_error(self, message):
        QMessageBox.critical(self, "Error", message)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())