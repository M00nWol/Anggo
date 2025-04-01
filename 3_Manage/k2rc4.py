from arc4 import ARC4

#-------------------
# RC4 클래스
# rc4.set_key : 암호 문자열 정의
# rc4.crypt : 주어진 버퍼 암/복호화
#-------------------

class RC4:
    def __init__(self):
        self.arc4 = None
    
    def set_key(self, password):
        self.arc4 = ARC4(password)

    def crypt(self, data):
        cipher = self.arc4.encrypt(data)
        return cipher


