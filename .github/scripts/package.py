import hashlib,pefile

APP_ID='com.daxiaamu.muroot'

def sha(path):
    digest=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''):digest.update(chunk)
    return digest.hexdigest()

def identity(path):
    pe=pefile.PE(str(path),fast_load=False)
    info=pe.VS_FIXEDFILEINFO[0]
    version=(info.FileVersionMS>>16,info.FileVersionMS&65535,info.FileVersionLS>>16)
    product=None
    for group in pe.FileInfo:
        for entry in group:
            for table in getattr(entry,'StringTable',[]):
                product=table.entries.get(b'ProductName',product)
    if product!=b'MuRoot' or info.FileVersionLS&65535 or version[1]>99 or version[2]>99:
        raise ValueError('Unexpected executable product/version')
    pe.close()
    return '.'.join(map(str,version)),version[0]*10000+version[1]*100+version[2]
