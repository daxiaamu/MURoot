"""Prepare (never push) update metadata after a GitHub Release already exists.

Only byte-verified CDN endpoints enter the manifest. Failure leaves latest intact.
"""
import argparse,concurrent.futures,hashlib,json,os,re,ssl,tempfile,time,urllib.parse,urllib.request,zipfile
from pathlib import Path
from package import APP_ID,identity,sha
ROOT=Path(__file__).resolve().parents[2]
LIMIT=256*1024*1024
class HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        if urllib.parse.urlparse(newurl).scheme!='https':raise ValueError('HTTPS downgrade')
        redirected=super().redirect_request(req,fp,code,msg,headers,newurl)
        if redirected and urllib.parse.urlparse(newurl).hostname!='api.github.com':redirected.remove_header('Authorization')
        return redirected
def https(url):
    p=urllib.parse.urlparse(url)
    if p.scheme!='https' or not p.hostname or p.username or p.password:raise ValueError('Invalid HTTPS URL')
    return p
def get(url,path=None,limit=1024*1024):
    parsed=https(url);headers={'User-Agent':'MuRoot-release','Cache-Control':'no-cache','Accept':'application/vnd.github+json'}
    token=os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN')
    if parsed.hostname=='api.github.com' and token:headers['Authorization']='Bearer '+token
    request=urllib.request.Request(url,headers=headers)
    opener=urllib.request.build_opener(HttpsOnlyRedirect())
    started=time.monotonic();digest=hashlib.sha256();size=0;chunks=[]
    with opener.open(request,timeout=15) as response:
        https(response.url)
        if response.status!=200:raise ValueError('HTTP status')
        with (path.open('wb') if path else tempfile.TemporaryFile()) as stream:
            while True:
                chunk=response.read(1024*1024)
                if not chunk:break
                size+=len(chunk)
                if size>limit or time.monotonic()-started>90:raise ValueError('Response exceeded limits')
                digest.update(chunk);stream.write(chunk)
            if not path:stream.seek(0);chunks=stream.read()
    return (size,digest.hexdigest()) if path else chunks
def encode(data):return (json.dumps(data,ensure_ascii=False,sort_keys=True,separators=(',',':'))+'\n').encode()
def check_candidate(url,size,digest):
    try:
        with tempfile.TemporaryDirectory() as directory:
            got,hash_value=get(url,Path(directory)/'artifact.zip',size)
        if got!=size or hash_value!=digest:return None
        return url
    except Exception:return None
def sources(repo,path):
    return [f'https://raw.githubusercontent.com/{repo}/main/{path}',
        f'https://cdn.jsdelivr.net/gh/{repo}@main/{path}',f'https://fastly.jsdelivr.net/gh/{repo}@main/{path}',
        f'https://gcore.jsdelivr.net/gh/{repo}@main/{path}',f'https://testingcf.jsdelivr.net/gh/{repo}@main/{path}',
        f'https://cdn.statically.io/gh/{repo}/main/{path}']
def prepare(repo,release,archive,root=ROOT,verified_urls=None,policy_root=None):
    policy_root=policy_root or root
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',repo) or '..' in repo:raise ValueError('Invalid repository')
    if release.get('draft'):raise ValueError('Release is a draft')
    channel='beta' if release.get('prerelease') else 'stable'
    with zipfile.ZipFile(archive) as z:
        package=json.loads(z.read('package.json'))
        if z.getinfo('MuRoot.exe').file_size>5*1024*1024:raise ValueError('Executable exceeded identity limit')
        with tempfile.TemporaryDirectory() as directory:
            exe=Path(directory)/'MuRoot.exe';exe.write_bytes(z.read('MuRoot.exe'));name,code=identity(exe)
    if package.get('appId')!=APP_ID or package.get('versionCode')!=code or package.get('versionName')!=name:raise ValueError('Package/PE identity mismatch')
    tag=release['tag_name']
    expected=f'v{name}' if channel=='stable' else f'v{name}-beta'
    if tag!=expected:raise ValueError('Release tag must match executable version and channel: '+expected)
    asset_name=f'MuRoot-{name}-windows-x64.zip';assets=[a for a in release['assets'] if a['name']==asset_name]
    if len(assets)!=1:raise ValueError('Expected one uniquely named MuRoot ZIP asset')
    official=assets[0]['browser_download_url'];https(official)
    if not official.startswith(f'https://github.com/{repo}/releases/download/{tag}/'):raise ValueError('Asset belongs to another release')
    digest=sha(archive);size=archive.stat().st_size
    if not 0<size<=LIMIT or assets[0]['size']!=size:raise ValueError('Release size mismatch')
    api_digest=assets[0].get('digest')
    if api_digest and api_digest!='sha256:'+digest:raise ValueError('GitHub asset digest mismatch')
    policy=json.loads((policy_root/f'updates/policy-{channel}.json').read_text('utf-8'))
    revision=policy['policyRevision'];forced=policy['maxForcedVersionCode']
    if type(revision)!=int or revision<1 or type(forced)!=int or not 0<=forced<code:raise ValueError('Invalid explicit update policy')
    latest_path=root/f'updates/latest-{channel}.json'
    if latest_path.exists():
        previous=json.loads(latest_path.read_text('utf-8'))
        if revision<=previous['policyRevision']:raise ValueError('Increment policyRevision before every publication')
        previous_manifest=root/'updates/manifests'/previous['manifestUrl'].split('/')[-1]
        if previous_manifest.exists():
            old=json.loads(previous_manifest.read_text('utf-8'))
            if code<old['versionCode'] or forced<old['maxForcedVersionCode']:raise ValueError('Version/forced policy rollback')
    if verified_urls is None:
        templates=json.loads((policy_root/'updates/cdn-candidates.json').read_text('utf-8'))
        candidates=list(dict.fromkeys(t.format(officialUrl=official,repository=repo,tag=tag,asset=asset_name,sha256=digest) for t in templates))
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            verified_urls=list(filter(None,pool.map(lambda u:check_candidate(u,size,digest),candidates)))
    hosts={https(u).hostname.lower() for u in verified_urls if https(u).hostname.lower()!='github.com'}
    if len(hosts)<5:raise ValueError('Fewer than five fully SHA-256-verified CDN hosts; latest remains unchanged')
    manifest={'schemaVersion':1,'appId':APP_ID,'platform':'windows-x64','channel':channel,'versionCode':code,'versionName':name,
        'publishedAt':release.get('published_at',''),'changelog':release.get('body') or '',
        'maxForcedVersionCode':forced,'policyRevision':revision,'urls':list(dict.fromkeys(verified_urls))+[official],
        'size':size,'sha256':digest,'releaseUrl':release['html_url']}
    data=encode(manifest);hash_value=hashlib.sha256(data).hexdigest();relative=f'updates/manifests/{revision}-{hash_value}.json'
    immutable=root/relative;immutable.parent.mkdir(parents=True,exist_ok=True)
    if immutable.exists() and immutable.read_bytes()!=data:raise ValueError('Immutable manifest collision')
    immutable.write_bytes(data)
    urls=sources(repo,relative)
    pointer={'schemaVersion':1,'policyRevision':revision,'manifestUrl':urls[0],'manifestUrls':urls[1:],'manifestSha256':hash_value}
    temporary=latest_path.with_suffix('.json.tmp');temporary.write_bytes(encode(pointer));os.replace(temporary,latest_path)
    return manifest
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--repository',required=True);parser.add_argument('--tag',required=True)
    parser.add_argument('--output-root',type=Path,default=ROOT);parser.add_argument('--policy-root',type=Path,default=ROOT);args=parser.parse_args()
    # Read-only API call; neither the token nor local device information is sent to CDN hosts.
    release=json.loads(get(f'https://api.github.com/repos/{args.repository}/releases/tags/{urllib.parse.quote(args.tag,safe="")}'))
    matching=[a for a in release['assets'] if re.fullmatch(r'MuRoot-\d+\.\d+\.\d+-windows-x64\.zip',a['name'])]
    if len(matching)!=1:raise ValueError('Expected exactly one MuRoot portable asset')
    with tempfile.TemporaryDirectory() as directory:
        archive=Path(directory)/'release.zip';get(matching[0]['browser_download_url'],archive,LIMIT)
        result=prepare(args.repository,release,archive,root=args.output_root,policy_root=args.policy_root)
    print(json.dumps({k:result[k] for k in ['channel','versionCode','policyRevision','sha256']},indent=2))
if __name__=='__main__':main()
