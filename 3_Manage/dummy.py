# dummy.py
import os

class KavMain:
    def init(self, plugins_path):
        self.virus_name = 'Dummy-Test-File (not a virus)'
        self.dummy_pattern = 'Dummy Engine test file - Anggo Anti-Virus Project'

        return 0

    def uninit(self):
        del self.virus_name
        del self.dummy_pattern

        return 0


    def scan(self, filehandle, filename):
        try:
            fp = open(filename, 'rb')
            buf = fp.read(len(self.dummy_pattern))
            fp.close()
            buf = str(buf, 'utf-8')

            if buf == self.dummy_pattern:
                return True, self.virus_name, 0
        except IOError:
            pass

        return False, '', -1

    def disinfect(self, filename, malware_id):
        try:
            if malware_id == 0:
                os.remove(filename)
                return True
        except IOError:
            pass

        return False


    def listvirus(self):
        vlist = list()

        vlist.append(self.virus_name)

        return vlist

    # 플러그인 엔진의 주요 정보를 알려줌
    def getinfo(self):
        info = dict()

        info['author'] = 'Kei Choi'
        info['version'] = '1.0'
        info['title'] = 'Dummy Scan Engine'
        info['kmd_name'] = 'dummy'

        return info
    