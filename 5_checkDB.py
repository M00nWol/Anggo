import sys
import os
import hashlib

VirusDB = [
    '44d88612fea8a8f36de82e1278abb02f:EICAR Test',
    '253a394610d705549fc580934da4f114:Dummy Test'
]

vdb = []

# VirusDB를 가공하여 vdb에 저장
def MakeVirusDB() :
    for pattern in VirusDB : 
        t = []
        v = pattern.split(':')
        t.append(v[0])
        t.append(v[1])
        vdb.append(t)

# 악성코드 검사
def SearchVDB(fmd5):
    for t in vdb:
        if t[0] == fmd5 : 
            return True, t[1]
        
    return False, ''

if __name__ == '__main__' :
    MakeVirusDB()

    if len(sys.argv) != 2:
        print('Usage : antivirus.py [file]')
        exit(0)

    fname = sys.argv[1]

    fp = open(fname, 'rb')
    buf = fp.read()
    fp.close()

    m = hashlib.md5()
    m.update(buf)
    fmd5 = m.hexdigest()
    
    ret, vname = SearchVDB(fmd5)
    if ret == True:
        print('%s : %s' % ((fname, vname)))
        os.remove(fname)
    else : 
        print('%s : ok' % (fname))
    