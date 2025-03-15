import sys
import os
import hashlib
import zlib
import io
import scanmod
import curemod

VirusDB = []    # 악성코드 패턴은 모두 virus.db에 존재
vdb = []    # 가공된 악성코드 DB가 저장됨
vsize = []  # 악성코드의 파일 크기만 저장됨
sdb = [] # 가공된 악성코드 DB가 저장됨 (특정 위치 검색법용용)

# KMD 파일을 복호화
def DecodeKMD(fname):
    try:
        fp = open(fname, 'rb')
        buf = fp.read()
        fp.close()

        buf2 = buf[:-32]
        fmd5 = buf[-32:]

        f = buf2
        for i in range(3):
            md5 = hashlib.md5()
            md5.update(f)
            f = md5.hexdigest()
            f = bytes(f, 'utf-8')

        if f != fmd5:
            raise SystemError
        
        buf3 = b''
        for c in buf2[4:] : 
            buf3 += (c^0xFF).to_bytes(1, byteorder="little")

        buf4 = zlib.decompress(buf3)
        return buf4
    
    except Exception as e:
        print(f"DecodeKMD Error: {e}")
        pass

    return None

# virus.kmd 파일에서 악성코드 패턴 읽기
def LoadVirusDB():
    buf = DecodeKMD('virus.kmd')
    buf = str(buf, 'utf-8')
    fp = io.StringIO(buf)

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
        v = pattern.split(':')

        scan_func = v[0]
        cure_func = v[1]

        if scan_func == 'ScanMD5':
            t.append(v[3])
            t.append(v[4])
            vdb.append(t)

            size = int(v[2])    # 악성코드 파일 크기
            if vsize.count(size) == 0 :
                vsize.append(size)

        elif scan_func == 'ScanStr':
            t.append(int(v[2]))
            t.append(v[3])
            t.append(v[4])
            sdb.append(t)

if __name__ == '__main__':
    LoadVirusDB()           # 악성코드 패턴을 파일에서 읽어옴
    MakeVirusDB()           # 악성코드 DB를 가공공

    if len(sys.argv) != 2 :
        print('Usage : antivirus.py [file]')
        exit(0)
    
    fname = sys.argv[1]

    ret, vname = scanmod.ScanVirus(vdb, vsize, sdb, fname)
    if ret == True:
        print('%s : %s' % (fname, vname))
        curemod.CureDelete(fname)

    else : 
        print('%s : ok' % (fname))