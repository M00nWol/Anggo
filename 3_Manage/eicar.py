import os
import hashlib

class KavMain:
    def init(self, plugins_path):
        return 0
    
    def uninit(self):
        return 0
    

    def scan(self, filehandle, filename):
        try:
            mm = filehandle
            size = os.path.getsize(filename)
            if size == 68:
                m = hashlib.md5()
                m.update(mm[:68])
                fmd5 = m.hexdigest()
                fmd6 = bytes(fmd5, 'utf-8')

                if fmd5 == b'44d88612fea8a8f36de82e1278abb02f':
                    return True, 'EICAR-Test-File (not a virus)', 0
                
        except IOError:
            pass

        return False, '', -1
    
    def disinfect(self, filename, malware_id):
        try:
            if malware_id == 0 :
                os.remove(filename)
                return True
        except IOError:
            pass

        return False
    
    def listvirus(self):
        vlist = list()

        vlist.append('EICAR-Test-File (not a virus)')

        return vlist

    def getinfo(self):
        info = dict()

        info['author'] = 'Kei Choi'
        info['version'] = '1.0'
        info['title'] = 'EICAR Scan Engine'
        info['kmd_name'] = 'eicar'


        return info

