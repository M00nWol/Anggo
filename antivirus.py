import sys
import os
import hashlib

VirusDB = []    # 악성코드 패턴은 모두 virus.db에 존재재
vdb = []    # 가공된 악성코드 DB가 저장됨
vsize = []  # 악성코드의 파일 크기만 저장됨

# virus.db 파일에서 악성코드 패턴 읽기
def LoadVirusDB():
    fp = open('virus.db', 'rb')

    while True:
        line = fp.readline()
        if not line : break

        line = line.strip()
        VirusDB.append(line)

    fp.close()

# VirusDB를 가공하여 vdb에 저장
def MakeVirusDB():
    for pattern in VirusDB:
        t = []
        v = pattern.split(b':')
        t.append(v[1])
        t.append(v[2])
        vdb.append(t)

        size = int(v[0])    # 악성코드 파일 크기
        if vsize.count(size) == 0 :
            vsize.append(size)

# 악성코드 검사
def SearchVDB(fmd5) :
    for t in vdb : 
        if t[0] == bytes(fmd5, 'utf-8') :
            return True, t[1]

    return False, ''

if __name__ == '__main__':
    LoadVirusDB()           # 악성코드 패턴을 파일에서 읽어옴
    MakeVirusDB()           # 악성코드 DB를 가공공

    if len(sys.argv) != 2 :
        print('Usage : antivirus.py [file]')
        exit(0)
    
    fname = sys.argv[1]

    size = os.path.getsize(fname)
    if vsize.count(size):
        fp = open(fname, 'rb')
        buf = fp.read()
        fp.close()

        m = hashlib.md5()
        m.update(buf)
        fmd5 = m.hexdigest()

        ret, vname = SearchVDB(fmd5)
        if ret == True:
            vname = str(vname, 'utf-8')
            print('%s : %s' % (fname, vname))
            os.remove(fname)

        else : 
            print('%s : ok' % (fname))
    else:
        print('%s : ok' % (fname))