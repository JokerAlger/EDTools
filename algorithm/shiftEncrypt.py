def shiftEncrypt(plaintext, key):
    ciphertext = ""
    for c in plaintext:
        if c.isalpha():
            if c.isupper():
                ciphertext += chr((ord(c) - 65 + key) % 26 + 65)
            else:
                ciphertext += chr((ord(c) - 97 + key) % 26 + 97)
        else:
            ciphertext += c
    return ciphertext


def shiftDecrypt(ciphertext, key):
    plaintext = ""
    for c in ciphertext:
        if c.isalpha():
            if c.isupper():
                plaintext += chr((ord(c) - 65 - key) % 26 + 65)
            else:
                plaintext += chr((ord(c) - 97 - key) % 26 + 97)
        else:
            plaintext += c
    return plaintext


def recoverPlaintext(ciphertext):
    for key in range(26):
        decrypted_text = shiftDecrypt(ciphertext, key)
        print(f"使用密钥{key}解密后的明文为：{decrypted_text}")


if __name__ == "__main__":
    plaintext = input("请输入明文：")
    key = int(input("请输入密钥："))
    print(shiftEncrypt(plaintext, key))
    ciphertext = input("请输入密文：")
    key = int(input("请输入偏移量："))
    print(shiftDecrypt(ciphertext, key))

