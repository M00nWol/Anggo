import sys
import zlib
import hashlib
import os

# 파일 암호화
def main():
    if len(sys.argv) != 2:
        print('Usage : kmake.py [file]')
        return

    fname = sys.argv[1]
    tname = fname
    
    fp = open(tname, 'rb')
    buf = fp.read()
    fp.close()

    buf2 = zlib.compress(buf)

    buf3 = b''
    for c in buf2 :
        buf3 += (c ^ 0xFF).to_bytes(1, byteorder="little")

    buf4 = b'KAVM' + buf3   # 헤더 생성

    f = buf4
    for i in range(3):
        md5 = hashlib.md5()
        md5.update(f)
        f = md5.hexdigest()
        f = bytes(f, 'utf-8')

    buf4 += f   # MD5를 암호화된 내용 뒤에 추가

    kmd_name = fname.split('.')[0] + '.kmd'
    fp = open(kmd_name, 'wb')
    fp.write(buf4)
    fp.close()

    print ('%s -> %s' % (fname, kmd_name))

if __name__ == '__main__':
    main()
    