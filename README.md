### 软件名称
密码大师

### 软件简介
密码大师是一款用户友好的加密和解密工具箱，支持多种经典加密算法，包括Shift Cipher、Playfair Cipher、DES和RSA。该工具箱适用于学习和了解基本加密技术以及实际的加密解密应用。

![Snipaste_2024-06-03_10-10-32](C:\Users\JokerAlger\Desktop\2023-2024第二学期\密码学\programs\Snipaste_2024-06-03_10-10-32.png)

### 功能概述

1. **Shift Cipher**
    - **加密**: 输入明文和密钥，通过移位密码对文本进行加密。
    - **解密**: 输入密文和密钥，通过移位密码对文本进行解密。
    - ![移位](img\shift.png)

    
2. **Playfair Cipher**
    - **加密**: 输入明文和密钥，通过Playfair密码对文本进行加密。
    - **解密**: 输入密文和密钥，通过Playfair密码对文本进行解密。
    - ![playfair](img\playfair.png)
    
3. **DES**
    - **加密**: 输入明文和8字节密钥，通过DES算法对文本进行加密。
    - **解密**: 输入密文和8字节密钥，通过DES算法对文本进行解密。
    - ![des](img\des.png)
    
4. **RSA**
    - **生成密钥**: 根据指定的密钥大小生成一对RSA公钥和私钥。
    - **加密**: 使用公钥对输入的明文进行加密。
    - **解密**: 使用私钥对输入的密文进行解密。
    - ![rsa](img\rsa.png)

### 界面布局
软件包含四个主要的标签页，每个标签页对应一种加密算法。每个标签页都有相应的输入框、密钥输入框、加密按钮、解密按钮和输出框。用户可以在不同的标签页之间切换，以使用不同的加密算法。

### 使用说明

#### 安装和运行
1. **环境要求**:

    - Python 3.x
    - PyQt5
    - pycryptodome

2. **安装依赖**:

    ```bash
    pip install pyqt5 pycryptodome
    
    ```
    或者使用镜像源安装
    ```bash
    pip install pyqt5 pycryptodome -i https://pypi.tuna.tsinghua.edu.cn/simple
    
    ```

3. **运行程序**:
    将程序文件保存为 `main.py`，然后在终端运行：

    ```bash
    python main.py
    ```

#### Shift Cipher
1. 输入待加密或解密的文本。
2. 输入密钥（0-25之间的整数）。
3. 点击“加密”按钮以加密文本。
4. 点击“解密”按钮以解密文本。
5. 结果会显示在输出框中。

#### Playfair Cipher
1. 输入待加密或解密的文本。
2. 输入密钥（字母串）。
3. 点击“加密”按钮以加密文本。
4. 点击“解密”按钮以解密文本。
5. 结果会显示在输出框中。

#### DES
1. 输入待加密或解密的文本。
2. 输入8字节的密钥。
3. 点击“加密”按钮以加密文本。
4. 点击“解密”按钮以解密文本。
5. 结果会显示在输出框中。如果密钥长度不是8字节，将显示错误信息。

#### RSA
1. 设置密钥大小（512到4096之间）。
2. 点击“生成密钥”按钮生成公钥和私钥。
3. 输入待加密的文本。
4. 输入公钥进行加密，结果会显示在输出框中。
5. 输入私钥进行解密，结果会显示在输出框中。

### 常见问题

1. **Q: 为什么我的DES加密无法成功？**
   - A: 确保输入的密钥长度为8字节。

2. **Q: 如何生成RSA密钥？**
   - A: 在RSA标签页中，设置密钥大小后点击“生成密钥”按钮即可生成公钥和私钥。

3. **Q: 为什么我的Shift Cipher解密结果不正确？**
   - A: 确保使用的密钥和加密时使用的密钥一致，并且密钥在0到25之间。

### 技术支持
如果在使用过程中遇到任何问题，请联系技术支持：harry.zlzhang@foxmail.com

### 版权信息
版权所有 © 2024 密码大师。保留所有权利。

---

此说明书旨在帮助用户快速上手密码大师的各项功能，并提供详细的使用指导和常见问题解答。希望用户在使用过程中能够体验到加密技术的乐趣和实用性。