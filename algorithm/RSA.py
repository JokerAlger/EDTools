def ex_gcd(a,b):
    """扩展欧几里德算法"""
    if b == 0:
        return 1, 0
    else:
        q = a // b
        r = a % b
        s, t = ex_gcd(b, r)
        s, t = t, s-q*t
    return [s, t]


# 快速幂算法
def fast_expmod(a,e,n):
    """快速幂"""
    d = 1
    while e != 0:
        if(e & 1) == 1:
            d = (d * a) % n
        e >>= 1
        a = a * a % n
    return d


def make_key(p, q, e):
    """
    生成公私钥
    参数1：大素数p
    参数2：大素数q
    参数3：随机生成e，满足 gcd(e,fin)
    返回值：[公钥,私钥]-------[[n,e],[n,d]]
    """
    n = p * q
    fin = (p-1) * (q-1)
    d = ex_gcd(e, fin)[0]      # 辗转相除法求逆(广义欧几里得)
    while d < 0:
        d = (d+fin) % fin
    return [[n, e], [n, d]]


def encryption(key, data):
    """
    加密
    参数1：列表[n,e]----公钥
    参数2：待价密数据
    返回值：密文
    """
    n, e = key
    plaintext = list(data)
    ciphertext = []
    for item in plaintext:
        ciphertext.append(fast_expmod(ord(item), e, n))
    return ciphertext


def decrypt(key, ciphertext):
    """
    解密
    参数1：key为私钥
    参数2：密文数据
    返回值：明文
    """
    n, d = key
    plaintext = ''
    for item in ciphertext:
        plaintext += (chr(fast_expmod(item, d, n)))
    return plaintext


def make_p_q_e():
    """
    返回值：[p,q,e]
    """
    p = 11
    q = 13
    e = 7
    return [p, q, e]


def test():
    p, q, e = make_p_q_e()
    # 获取数据
    plaintext = input("待加密数据：")
    # 公钥、私钥
    public_key, private_key = make_key(p, q, e)
    # 加密
    ciphertext = encryption(public_key, plaintext)
    print("加密后的数据：", ciphertext)
    # 解密
    plaintext = decrypt(private_key, ciphertext)
    print("解密后的数据：", plaintext)


test()
