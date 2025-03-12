import sys
import os
import hashlib

VirusDB = [
    '68:44d88612fea8a8f36de82e1278abb02f:EICAR Test',
    '64:253a394610d705549fc580934da4f114:Dummy Test'
]

vdb = []    # 가공된 악성코드 DB가 저장됨
vsize = []  # 악성코드의 파일 크기만 저장됨

# VirusDB를 가공하여 vdb에 저장
def MakeVirusDB():
    for pattern in VirusDB:
        t = []
        v = pattern.split(':')
        t.append(v[1])
        t.append(v[2])
        vdb.append(t)

        size = int(v[0])    # 악성코드 파일 크기
        if vsize.count(size) == 0 :
            vsize.append(size)

# 악성코드 검사
def SearchVDB(fmd5) :
    for t in vdb : 
        if t[0] == fmd5 :
            return True, t[1]

    return False, ''

if __name__ == '__main__':
    MakeVirusDB()   

    if len(sys.argv) != 2 :
        print('Usage : 5_checkDB.py [file]')
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
            print('%s : %s' % (fname, vname))
            os.remove(fname)

        else : 
            print('%s : ok' % (fname))
    else:
        print('%s : ok' % (fname))