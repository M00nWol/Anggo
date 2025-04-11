import k2kmdfile
import dummy

k = k2kmdfile.KMD('dummy.kmd')

module = k2kmdfile.load('dummy', k.body)

kav2 = dummy.KavMain()
kav2.init('.')
print(kav2.listvirus())
kav2.uninit()

