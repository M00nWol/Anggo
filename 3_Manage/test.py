import k2kmdfile

# 특정 파일(readme.txt)를 kmd 파일로 만든다. 
ret = k2kmdfile.make('readme.txt')
if ret:
    k = k2kmdfile.KMD('readme.kmd')
    print(k.body.decode('utf-8'))