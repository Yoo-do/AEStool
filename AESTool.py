import sys
import AESUtil
from PyQt5.QtWidgets import QApplication, QComboBox, QWidget, QBoxLayout, QHBoxLayout, QLabel, QTextEdit, QLineEdit, QPushButton


class MainInterface:
    def __init__(self):

        self.app = QApplication(sys.argv)
        self.main_window = QWidget()
        self.main_window_init()

        sys.exit(self.app.exec_())

    def main_window_init(self):
        """
        初始化主窗口
        :return:
        """
        self.main_window.setWindowTitle('AES加密解密工具')
        self.main_window.resize(800, 600)
        self.main_window.show()

        main_layout = QBoxLayout(QHBoxLayout.TopToBottom, self.main_window)

        # 输入提示
        input_label_tittle = QLabel('请输入需要加密或解密的内容', self.main_window)
        input_label_tittle.show()
        main_layout.addWidget(input_label_tittle)

        # input_text_edit
        self.input_text_edit = QTextEdit(self.main_window)
        self.input_text_edit.show()
        main_layout.addWidget(self.input_text_edit)

        # 密钥和向量
        key_and_iv_layout = QHBoxLayout()

        # 输入提示
        key_label_tittle = QLabel('密钥', self.main_window)
        key_label_tittle.show()
        key_and_iv_layout.addWidget(key_label_tittle)

        # key_text_edit
        self.key_line_edit = QLineEdit(self.main_window)
        self.key_line_edit.show()
        key_and_iv_layout.addWidget(self.key_line_edit)

        # key填充方式
        self.padding_combox = QComboBox(self.main_window)
        self.padding_combox.show()
        types = ['ZeroPadding', 'PKCS5Padding', 'PKCS7Padding']
        self.padding_combox.addItems(types)
        key_and_iv_layout.addWidget(self.padding_combox)

        # 输入提示
        key_label_tittle = QLabel('偏移量', self.main_window)
        key_label_tittle.show()
        key_and_iv_layout.addWidget(key_label_tittle)

        # iv_text_edit
        self.iv_line_edit = QLineEdit(self.main_window)
        self.iv_line_edit.show()
        self.iv_line_edit.setText('0000000000000000')
        key_and_iv_layout.addWidget(self.iv_line_edit)

        # 字符集
        self.character_set_combox = QComboBox(self.main_window)
        self.character_set_combox.show()
        character_sets = ['utf-8']
        self.character_set_combox.addItems(character_sets)
        key_and_iv_layout.addWidget(self.character_set_combox)

        main_layout.addLayout(key_and_iv_layout)

        # 输入提示
        output_label_tittle = QLabel('加密或解密后的内容', self.main_window)
        output_label_tittle.show()
        main_layout.addWidget(output_label_tittle)

        # output_text_edit
        self.output_text_edit = QTextEdit(self.main_window)
        self.output_text_edit.show()
        main_layout.addWidget(self.output_text_edit)

        # 横向布局
        bottom_layout = QHBoxLayout()

        # 加密方式
        self.select_type_combox = QComboBox(self.main_window)
        self.select_type_combox.show()
        modes = ['CTR', 'CBC', 'ECB']
        self.select_type_combox.addItems(modes)
        bottom_layout.addWidget(self.select_type_combox)

        # 加密按钮
        encryption_btn = QPushButton('加密', self.main_window)
        encryption_btn.show()
        encryption_btn.clicked.connect(lambda: self.encrypt())
        bottom_layout.addWidget(encryption_btn)

        # 解密按钮
        decryption_btn = QPushButton('解密', self.main_window)
        decryption_btn.show()
        decryption_btn.clicked.connect(lambda: self.decrypt())
        bottom_layout.addWidget(decryption_btn)

        main_layout.addLayout(bottom_layout)

    def encrypt(self):
        key = self.key_line_edit.text().encode('utf-8')
        mode = None
        if self.select_type_combox.currentText() == 'CBC':
            mode = AESUtil.AES.MODE_CBC
        elif self.select_type_combox.currentText() == 'ECB':
            mode = AESUtil.AES.MODE_ECB
        elif self.select_type_combox.currentText() == 'CTR':
            mode = AESUtil.AES.MODE_CTR
        iv = self.iv_line_edit.text().encode('utf-8')
        paddingMode = self.padding_combox.currentText()
        try:
            ase = AESUtil.AEScryptor(key, mode, iv, paddingMode=paddingMode, characterSet='utf-8')
            data = self.input_text_edit.toPlainText()
            rData = ase.encryptFromString(data)
            self.output_text_edit.setText(rData.toBase64())
        except Exception as e:
            self.output_text_edit.setText(e.__str__())

    def decrypt(self):
        key = self.key_line_edit.text().encode('utf-8')
        mode = None
        if self.select_type_combox.currentText() == 'CBC':
            mode = AESUtil.AES.MODE_CBC
        elif self.select_type_combox.currentText() == 'ECB':
            mode = AESUtil.AES.MODE_ECB
        elif self.select_type_combox.currentText() == 'CTR':
            mode = AESUtil.AES.MODE_CTR
        iv = self.iv_line_edit.text().encode('utf-8')
        paddingMode = self.padding_combox.currentText()
        try:
            ase = AESUtil.AEScryptor(key, mode, iv, paddingMode=paddingMode, characterSet='utf-8')
            data = self.input_text_edit.toPlainText()
            rData = AESUtil.MData(data.encode('utf-8'))
            rData.fromBase64(data)
            print(rData)
            output = ase.decryptFromBase64(rData.toBase64())
            self.output_text_edit.setText(output.__str__())
        except Exception as e:
            self.output_text_edit.setText(e.__str__())


if __name__ == '__main__':
    interface = MainInterface()
