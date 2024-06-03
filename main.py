from PyQt5 import QtWidgets, QtGui, QtCore
from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
import sys

# Playfair Cipher helper functions
letter_list = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'


def remove_duplicates(key):
    key = key.upper()
    _key = ''
    for ch in key:
        if ch == 'J':
            ch = 'I'
        if ch in _key:
            continue
        else:
            _key += ch
    return _key


def create_matrix(key):
    key = remove_duplicates(key)
    key = key.replace(' ', '')
    for ch in letter_list:
        if ch not in key:
            key += ch
    keys = [[i for j in range(5)] for i in range(5)]
    for i in range(len(key)):
        keys[i // 5][i % 5] = key[i]
    return keys


def get_matrix_index(ch, keys):
    for i in range(5):
        for j in range(5):
            if ch == keys[i][j]:
                return i, j


def get_ctext(ch1, ch2, keys):
    index1 = get_matrix_index(ch1, keys)
    index2 = get_matrix_index(ch2, keys)
    r1, c1, r2, c2 = index1[0], index1[1], index2[0], index2[1]
    if r1 == r2:
        ch1 = keys[r1][(c1 + 1) % 5]
        ch2 = keys[r2][(c2 + 1) % 5]
    elif c1 == c2:
        ch1 = keys[(r1 + 1) % 5][c1]
        ch2 = keys[(r2 + 1) % 5][c2]
    else:
        ch1 = keys[r1][c2]
        ch2 = keys[r2][c1]
    text = ''
    text += ch1
    text += ch2
    return text


def get_ptext(ch1, ch2, keys):
    index1 = get_matrix_index(ch1, keys)
    index2 = get_matrix_index(ch2, keys)
    r1, c1, r2, c2 = index1[0], index1[1], index2[0], index2[1]
    if r1 == r2:
        ch1 = keys[r1][(c1 - 1) % 5]
        ch2 = keys[r2][(c2 - 1) % 5]
    elif c1 == c2:
        ch1 = keys[(r1 - 1) % 5][c1]
        ch2 = keys[(r2 - 1) % 5][c2]
    else:
        ch1 = keys[r1][c2]
        ch2 = keys[r2][c1]
    text = ''
    text += ch1
    text += ch2
    return text


def playfair_encode(plaintext, key):
    plaintext = plaintext.replace(" ", "")
    plaintext = plaintext.upper()
    plaintext = plaintext.replace("J", "I")
    plaintext = list(plaintext)
    plaintext.append('#')
    plaintext.append('#')
    keys = create_matrix(key)
    ciphertext = ''
    i = 0
    while plaintext[i] != '#':
        if plaintext[i] == plaintext[i + 1]:
            plaintext.insert(i + 1, 'X')
        if plaintext[i + 1] == '#':
            plaintext[i + 1] = 'X'
        ciphertext += get_ctext(plaintext[i], plaintext[i + 1], keys)
        i += 2
    return ciphertext


def playfair_decode(ciphertext, key):
    keys = create_matrix(key)
    i = 0
    plaintext = ''
    while i < len(ciphertext):
        plaintext += get_ptext(ciphertext[i], ciphertext[i + 1], keys)
        i += 2
    _plaintext = ''
    _plaintext += plaintext[0]
    for i in range(1, len(plaintext) - 1):
        if plaintext[i] != 'X':
            _plaintext += plaintext[i]
        elif plaintext[i] == 'X':
            if plaintext[i - 1] != plaintext[i + 1]:
                _plaintext += plaintext[i]
    _plaintext += plaintext[-1]
    _plaintext = _plaintext.lower()
    return _plaintext


# Main Crypto Toolbox UI
class CryptoToolbox(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("密码大师")
        self.setGeometry(100, 100, 600, 400)
        self.setWindowIcon(QtGui.QIcon('image/icon.png'))  # Set your icon file here

        layout = QtWidgets.QVBoxLayout()

        self.tabs = QtWidgets.QTabWidget()
        self.tabs.addTab(self.createShiftTab(), "Shift Cipher")
        self.tabs.addTab(self.createPlayfairTab(), "Playfair Cipher")
        self.tabs.addTab(self.createDESTab(), "DES")
        self.tabs.addTab(self.createRSATab(), "RSA")

        layout.addWidget(self.tabs)
        self.setLayout(layout)

    def createShiftTab(self):
        tab = QtWidgets.QWidget()
        layout = QtWidgets.QFormLayout()

        self.shift_input = QtWidgets.QLineEdit()
        self.shift_input.setPlaceholderText("请输入明文")
        self.shift_key = QtWidgets.QSpinBox()
        self.shift_key.setRange(0, 25)
        self.shift_encrypt_button = QtWidgets.QPushButton("加密")
        self.shift_encrypt_button.setIcon(QtGui.QIcon('image/encrypt.png'))  # Set your icon file here
        self.shift_encrypt_button.clicked.connect(self.shift_encrypt)
        self.shift_decrypt_button = QtWidgets.QPushButton("解密")
        self.shift_decrypt_button.setIcon(QtGui.QIcon('image/decrypt.png'))  # Set your icon file here
        self.shift_decrypt_button.clicked.connect(self.shift_decrypt)
        self.shift_output = QtWidgets.QLineEdit()
        self.shift_output.setPlaceholderText("输出")

        layout.addRow("输入:", self.shift_input)
        layout.addRow("密钥:", self.shift_key)
        layout.addRow(self.shift_encrypt_button, self.shift_decrypt_button)
        layout.addRow("输出:", self.shift_output)

        tab.setLayout(layout)
        return tab

    def shift_encrypt(self):
        text = self.shift_input.text()
        key = self.shift_key.value()
        encrypted_text = ''.join([chr((ord(char) - 65 + key) % 26 + 65) if char.isupper() else
                                  chr((ord(char) - 97 + key) % 26 + 97) if char.islower() else char for char in text])
        self.shift_output.setText(encrypted_text)

    def shift_decrypt(self):
        text = self.shift_output.text()
        key = self.shift_key.value()
        decrypted_text = ''.join([chr((ord(char) - 65 - key) % 26 + 65) if char.isupper() else
                                  chr((ord(char) - 97 - key) % 26 + 97) if char.islower() else char for char in text])
        self.shift_output.setText(decrypted_text)

    def createPlayfairTab(self):
        tab = QtWidgets.QWidget()
        layout = QtWidgets.QFormLayout()

        self.playfair_input = QtWidgets.QLineEdit()
        self.playfair_input.setPlaceholderText("请输入文本")
        self.playfair_key = QtWidgets.QLineEdit()
        self.playfair_key.setPlaceholderText("请输入密钥")
        self.playfair_encrypt_button = QtWidgets.QPushButton("加密")
        self.playfair_encrypt_button.setIcon(QtGui.QIcon('image/encrypt.png'))  # Set your icon file here
        self.playfair_encrypt_button.clicked.connect(self.playfair_encrypt)
        self.playfair_decrypt_button = QtWidgets.QPushButton("解密")
        self.playfair_decrypt_button.setIcon(QtGui.QIcon('image/decrypt.png'))  # Set your icon file here
        self.playfair_decrypt_button.clicked.connect(self.playfair_decrypt)
        self.playfair_output = QtWidgets.QLineEdit()
        self.playfair_output.setPlaceholderText("输出")

        layout.addRow("输入:", self.playfair_input)
        layout.addRow("密钥:", self.playfair_key)
        layout.addRow(self.playfair_encrypt_button, self.playfair_decrypt_button)
        layout.addRow("输出:", self.playfair_output)

        tab.setLayout(layout)
        return tab

    def playfair_encrypt(self):
        text = self.playfair_input.text()
        key = self.playfair_key.text()
        encrypted_text = playfair_encode(text, key)
        self.playfair_output.setText(encrypted_text)

    def playfair_decrypt(self):
        text = self.playfair_output.text()
        key = self.playfair_key.text()
        decrypted_text = playfair_decode(text, key)
        self.playfair_output.setText(decrypted_text)

    def createDESTab(self):
        tab = QtWidgets.QWidget()
        layout = QtWidgets.QFormLayout()

        self.des_input = QtWidgets.QLineEdit()
        self.des_input.setPlaceholderText("Enter text")
        self.des_key = QtWidgets.QLineEdit()
        self.des_key.setPlaceholderText("Enter 8-byte key")
        self.des_encrypt_button = QtWidgets.QPushButton("加密")
        self.des_encrypt_button.setIcon(QtGui.QIcon('image/encrypt.png'))  # Set your icon file here
        self.des_encrypt_button.clicked.connect(self.des_encrypt)
        self.des_decrypt_button = QtWidgets.QPushButton("解密")
        self.des_decrypt_button.setIcon(QtGui.QIcon('image/decrypt.png'))  # Set your icon file here
        self.des_decrypt_button.clicked.connect(self.des_decrypt)
        self.des_output = QtWidgets.QLineEdit()
        self.des_output.setPlaceholderText("输出")

        layout.addRow("输入:", self.des_input)
        layout.addRow("密钥:", self.des_key)
        layout.addRow(self.des_encrypt_button, self.des_decrypt_button)
        layout.addRow("输出:", self.des_output)

        tab.setLayout(layout)
        return tab

    def des_encrypt(self):
        text = self.des_input.text()
        key = self.des_key.text().encode('utf-8')
        if len(key) != 8:
            self.des_output.setText("Key must be 8 bytes")
            return

        cipher = DES.new(key, DES.MODE_ECB)
        padded_text = pad(text.encode('utf-8'), DES.block_size)
        encrypted_text = cipher.encrypt(padded_text)
        self.des_output.setText(encrypted_text.hex())

    def des_decrypt(self):
        encrypted_text = bytes.fromhex(self.des_output.text())
        key = self.des_key.text().encode('utf-8')
        if len(key) != 8:
            self.des_output.setText("密钥必须为 8 个字节")
            return

        cipher = DES.new(key, DES.MODE_ECB)
        decrypted_text = unpad(cipher.decrypt(encrypted_text), DES.block_size)
        self.des_output.setText(decrypted_text.decode('utf-8'))

    def createRSATab(self):
        tab = QtWidgets.QWidget()
        layout = QtWidgets.QFormLayout()

        self.rsa_input = QtWidgets.QLineEdit()
        self.rsa_input.setPlaceholderText("请输入文本")
        self.rsa_key_size = QtWidgets.QSpinBox()
        self.rsa_key_size.setRange(512, 4096)
        self.rsa_key_size.setValue(2048)
        self.rsa_generate_keys_button = QtWidgets.QPushButton("生成密钥")
        self.rsa_generate_keys_button.setIcon(QtGui.QIcon('image/generate_keys.png'))  # Set your icon file here
        self.rsa_generate_keys_button.clicked.connect(self.rsa_generate_keys)
        self.rsa_public_key = QtWidgets.QTextEdit()
        self.rsa_public_key.setPlaceholderText("公钥")
        self.rsa_private_key = QtWidgets.QTextEdit()
        self.rsa_private_key.setPlaceholderText("私钥")
        self.rsa_encrypt_button = QtWidgets.QPushButton("加密")
        self.rsa_encrypt_button.setIcon(QtGui.QIcon('image/encrypt.png'))  # Set your icon file here
        self.rsa_encrypt_button.clicked.connect(self.rsa_encrypt)
        self.rsa_decrypt_button = QtWidgets.QPushButton("解密")
        self.rsa_decrypt_button.setIcon(QtGui.QIcon('image/decrypt.png'))  # Set your icon file here
        self.rsa_decrypt_button.clicked.connect(self.rsa_decrypt)
        self.rsa_output = QtWidgets.QLineEdit()
        self.rsa_output.setPlaceholderText("输出")

        layout.addRow("输入:", self.rsa_input)
        layout.addRow("Key Size:", self.rsa_key_size)
        layout.addRow(self.rsa_generate_keys_button)
        layout.addRow("公钥:", self.rsa_public_key)
        layout.addRow("私钥:", self.rsa_private_key)
        layout.addRow(self.rsa_encrypt_button, self.rsa_decrypt_button)
        layout.addRow("输出:", self.rsa_output)

        tab.setLayout(layout)
        return tab

    def rsa_generate_keys(self):
        key_size = self.rsa_key_size.value()
        key = RSA.generate(key_size)
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        self.rsa_private_key.setText(private_key.decode('utf-8'))
        self.rsa_public_key.setText(public_key.decode('utf-8'))

    def rsa_encrypt(self):
        text = self.rsa_input.text().encode('utf-8')
        public_key = RSA.import_key(self.rsa_public_key.toPlainText().encode('utf-8'))
        cipher = PKCS1_OAEP.new(public_key)
        encrypted_text = cipher.encrypt(text)
        self.rsa_output.setText(encrypted_text.hex())

    def rsa_decrypt(self):
        encrypted_text = bytes.fromhex(self.rsa_output.text())
        private_key = RSA.import_key(self.rsa_private_key.toPlainText().encode('utf-8'))
        cipher = PKCS1_OAEP.new(private_key)
        decrypted_text = cipher.decrypt(encrypted_text)
        self.rsa_output.setText(decrypted_text.decode('utf-8'))


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    ex = CryptoToolbox()
    ex.show()
    sys.exit(app.exec_())
