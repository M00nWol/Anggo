import hashlib
import os
import py_compile
import random
import shutil
import struct
import zlib
import k2rc4
import k2timelib


# rsa 개인키를 이용해서 주어진 파일을 암호화하여 KMD 파일 생성
def make(src_fname, debug=False):
    fname = src_fname

    if fname.split('.')[1] == 'py':
        py_compile.compile(fname, fname+'c', None, True)
        pyc_name = fname+'c'
    else:
        pyc_name = fname.split('.')[0]+'.pyc'
        shutil.copy(fname, pyc_name)
    

    # KMD 파일 생성
    # 헤더 : 시그니처(KAVM) + 예약영역
    kmd_data = b'KAVM'
    ret_date = k2timelib.get_now_date()
    ret_time = k2timelib.get_now_time()

    val_date = struct.pack('<H', ret_date)
    val_time = struct.pack('<H', ret_time)

    reserved_buf = val_date + val_time + (b'\x00'*28)

    kmd_data += reserved_buf

    # 본문 : 개인키로 암호화한 RC4 키 + RC4로 암호화한 파일
    random.seed()

    while 1:
        tmp_kmd_data = b''
        
        key = random.randbytes(16)
        tmp_kmd_data += key

        buf1 = open(pyc_name, 'rb').read()
        buf2 = zlib.compress(buf1)

        e_rc4 = k2rc4.RC4()
        e_rc4.set_key(key)

        buf3 = e_rc4.crypt(buf2)

        e_rc4 = k2rc4.RC4()
        e_rc4.set_key(key)

        if e_rc4.crypt(buf3) != buf2:
            continue

        tmp_kmd_data += buf3


        # 꼬리 : 개인키로 암호화한 MD5x3
        md5 = hashlib.md5()
        md5hash = kmd_data + tmp_kmd_data
        for i in range(3):
            md5.update(md5hash)
            md5hash = md5.hexdigest()

            md5hash = bytes(md5hash, 'utf-8')

        kmd_data += tmp_kmd_data + md5hash
        break
    
    # KMD 파일 생성
    ext = fname.find('.')
    kmd_name = fname[0:ext] + '.kmd'

    try:
        if kmd_data:
            open(kmd_name, 'wb').write(kmd_data)
            os.remove(pyc_name)

            if debug:
                print('Success : %-13s -> %s' % (fname, kmd_name))
            return True
        else:
            raise IOError   
    except IOError:
        if debug:
            print('Fail : %s' % (fname))
        return False
    
    
    
# ntimes_md5 : 주어진 버퍼에 대해 n회 반복해서 해시 결과를 리턴
def ntimes_md5(buf, ntimes):
    md5 = hashlib.md5()
    md5hash = buf
    for i in range(ntimes):
        md5.update(md5hash)
        md5hash = md5.hexdigest()
        md5hash = bytes(md5hash, 'utf-8')
    
    return md5hash

# KMD 오류 메시지 정의
class KMDFormatError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)
    
# KMD 관련 상수
class KMDConstants:
    KMD_SIGNATURE = b'KAVM'

    KMD_DATE_OFFSET = 4
    KMD_DATE_LENGTH = 2
    KMD_TIME_OFFSET = 6
    KMD_TIME_LENGTH = 2

    KMD_RESERVED_OFFSET = 8
    KMD_RESERVED_LENGTH = 28

    KMD_RC4_KEY_OFFSET = 36
    KMD_RC4_KEY_LENGTH = 16

    KMD_MD5_OFFSET = -32

# KMD 클래스
class KMD(KMDConstants):
    def __init__(self, fname):
        self.filename = fname           # KMD 파일 이름
        self.date = None                # KMD 파일 날짜
        self.time = None                # KMD 파일 시간
        self.body = None                # 복호화된 파일 내용

        self.__kmd_data = None          # KMD 암호화된 파일 내용
        self.__rc4_data = None          # RC4 키

        if self.filename:
            self.__decrypt(self.filename)       # 파일 복호화

    def __decrypt(self, fname, debug=False):
        # KMD 파일을 열고 시그니처 체크
        with open(fname, 'rb') as fp:
            if fp.read(4) == self.KMD_SIGNATURE:        # KMD 파일이 맞는지 체크
                self.__kmd_data = self.KMD_SIGNATURE + fp.read()        # 파일을 읽어들임
            else : 
                raise KMDFormatError('KMD Header magic not found.')
            
        # KMD 파일 날짜 읽기
        tmp = self.__kmd_data[self.KMD_DATE_OFFSET:self.KMD_DATE_OFFSET+self.KMD_DATE_LENGTH]
        self.date = k2timelib.convert_date(struct.unpack('<H', tmp)[0])

        # KMD 파일 시간 읽기
        tmp = self.__kmd_data[self.KMD_TIME_OFFSET:self.KMD_TIME_OFFSET+self.KMD_TIME_LENGTH]
        self.time = k2timelib.convert_time(struct.unpack('<H', tmp)[0])

        # KMD 파일에서 MD5 읽기
        e_md5hash = self.__get_md5()

        # 무결성 체크
        # 파이썬 3 사용하므로 교재랑 코드가 조금 다름름
        md5hash = ntimes_md5(self.__kmd_data[:self.KMD_MD5_OFFSET], 3)
        if e_md5hash != md5hash:
            raise KMDFormatError('Invalid KMD MD5 hash.')
        
        # KMD 파일에서 RC4 키 읽기
        self.__rc4_key = self.__get_rc4_key()

        # KMD 파일에서 본문 읽기
        e_kmd_data = self.__get_body()
        if debug:
            print(len(e_kmd_data))

        self.body = zlib.decompress(e_kmd_data)
        if debug:
            print(len(self.body))
        
    def __get_rc4_key(self):
        e_key = self.__kmd_data[self.KMD_RC4_KEY_OFFSET:self.KMD_RC4_KEY_OFFSET+self.KMD_RC4_KEY_LENGTH]
        return e_key
    
    def __get_body(self):
        e_kmd_data = self.__kmd_data[self.KMD_RC4_KEY_OFFSET+self.KMD_RC4_KEY_LENGTH:self.KMD_MD5_OFFSET]
        r = k2rc4.RC4()
        r.set_key(self.__rc4_key)
        return r.crypt(e_kmd_data)
    
    def __get_md5(self):
        e_md5 = self.__kmd_data[self.KMD_MD5_OFFSET:]
        return e_md5
