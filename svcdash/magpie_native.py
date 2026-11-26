"""Read-only transport for the vendored Magpie web view.

No mutation endpoint is reachable. session-titles is upstream's POST-shaped
batch read; we expose it as a bounded GET query and reject all other writes.
"""
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from . import magpie

READS={
    'state','settings','providers','groups','caller-keys','model-loads','upstream','drift',
    'usage','usage/requests','usage/requests.csv','archive/file','sessions/markdown','usage/quotas','usage/quotas/history',
    'gateway/trace','gateway/history','gateway/route','gateway/call',
    'agents/cli','agents/install','plugins/agents','plugins/builtin',
    'plugin-panels','plugin-pages','plugins/updates','update','whatsnew',
    'context','context/session','context/text','context/reply','tune','model-price','sessions','sessions/active','sessions/recent',
    'sessions/stats','sessions/overview','sessions/progress','sessions/one','sessions/transcript',
    'usage/heatmap','usage/traffic','usage/requests/content','usage/deleted/into','speeds',
}
BATCH_READS={'gateway/session-titles'}
STUBS={'plugin-panels':{'panels':[]},'plugin-pages':{'pages':[]},
       'plugins/updates':{'updates':[]},'update':{},'whatsnew':{}}


def read(path, query=''):
    if path in STUBS:return 200,'application/json',json.dumps(STUBS[path]).encode()
    if path not in READS and path not in BATCH_READS and not re.fullmatch(r'(?:icons/[a-f0-9]+\.(?:png|svg|webp)|gateway/held/[A-Za-z0-9_-]+)',path):
        return 403,'application/json',b'{"error":"Read-only Magpie view"}'
    if len(query)>65536:return 400,'application/json',b'{"error":"Query too large"}'
    body=None
    qs=urllib.parse.parse_qs(query)
    if path in BATCH_READS:
        try:
            incoming=json.loads(qs.get('payload',['{}'])[0])
            body={k:incoming[k] for k in ('ids','routeIds','sessions','groups','day') if k in incoming} if path=='gateway/session-titles' else {}
            if any(isinstance(v,list) and len(v)>500 for v in body.values()):raise ValueError()
            body=json.dumps(body).encode()
        except (ValueError,TypeError):return 400,'application/json',b'{"error":"Invalid title query"}'
        qs.pop('payload',None)
        query=urllib.parse.urlencode(qs,doseq=True)
    headers={'Cookie':f'magpie_web_{magpie.MAGPIE_PORT}={magpie._discover_magpie_key()}', 'Accept':'application/json'}
    if body is not None:headers['Content-Type']='application/json'
    url=magpie.MAGPIE_URL+'/api/'+path+('?' + query if query else '')
    req=urllib.request.Request(url,data=body,headers=headers)
    try:
        with urllib.request.urlopen(req,timeout=60 if path in {'context','tune','sessions','sessions/stats','sessions/overview'} else 30) as response:
            raw=response.read(32*1024*1024)
            return 200,response.headers.get('Content-Type','application/json'),raw
    except urllib.error.HTTPError as error:
        return error.code,'application/json',json.dumps({'error':f'Magpie HTTP {error.code}'}).encode()
    except (OSError,ValueError) as error:
        return 502,'application/json',json.dumps({'error':'Magpie temporarily unavailable'}).encode()


def _json(path):
    name,_,query=path.partition('?')
    status,_,raw=read(name,query)
    if status!=200:return None
    try:return json.loads(raw)
    except (ValueError,TypeError):return None


def public_snapshot():
    """Public display data: retain metrics; never publish requests or conversations."""
    import hashlib
    from .privacy import sanitize_text
    marker='[内容已脱敏]'
    previous=magpie.read_public_cache('native')
    private_fields={'title','transcript','prompts','messages','message','prompt','prompttext',
                    'firsttext','inputtext','outputtext','requesttext','responsetext',
                    'body','text','content','summary','excerpt','reply','conversation',
                    'command','cmd','description','intent','error','systemprompt'}
    def remove_private(value):
        if isinstance(value,dict):
            return {key:(marker if str(key).lower() in private_fields and not isinstance(item,(int,float,bool))
                         else remove_private(item)) for key,item in value.items()}
        if isinstance(value,list):return [remove_private(item) for item in value]
        return value
    def opaque(value):return 'item-'+hashlib.sha256(str(value).encode()).hexdigest()[:12]
    sensitive={'sessionTitle','conversationTitle','folder','cwd','path','body','text','content','messages','systemPrompt','promptText','description','error','intent','author','username','email','user','who','resume','command','cmd','firstPrompt','promptText'}
    def clean(value,key=''):
        if isinstance(value,dict):
            return {opaque(k) if ('@' in str(k) or str(k).startswith(('/','~/'))) else k:clean(v,k) for k,v in value.items() if k.lower() not in {'apikey','authorization','password','headers','secret','access_token','refresh_token'}}
        if isinstance(value,list):return [clean(v,key) for v in value]
        if isinstance(value,str):
            if key=='cwd':return 'project-'+opaque(value)
            if key=='keys' and ':' in value:
                agent,ident=value.split(':',1)
                return agent+':'+opaque(ident)
            if key in sensitive:return marker
            if key in {'session','conv','callerKeyId','account','id','key','fingerprint'}:return opaque(value)
            return sanitize_text(value,mask_ips=True,mask_paths=True)
        return value
    def route(route):
        value=clean(route)
        # A route's prompt/first-text fields can contain conversation content.
        for field in ('prompt','firstText','titleLink','folder','flow'):
            value.pop(field,None)
        return value
    trace=_json('gateway/trace?after=0')
    if trace is None:
        if previous:
            sanitized=remove_private(previous)
            if sanitized != previous:
                magpie.write_public_cache('native',sanitized)
            return sanitized
        routing=magpie.read_public_cache('routing') or {}
        usages={period:magpie.read_public_cache('usage-'+period) or {}
                for period in ('today','7d','30d','all')}
        return {'trace':{'mine':True,'seq':routing.get('seq',0),'routes':routing.get('routes',[]),
                         'totals':routing.get('totals',{})},'days':routing.get('days',[]),
                'groups':{field:routing.get(field,[]) for field in ('groups','pools','models','deciders')},
                'providers':magpie.read_public_cache('providers') or {'providers':[]},
                'usage':usages,'ledgers':{},'state':{'agents':[],'clients':[],'settings':{}},
                'settings':{},'quotas':[],'ranges':{}}
    trace['routes']=[route(r) for r in trace.get('routes') or []]
    def read_or_saved(path,fallback):
        value=_json(path)
        return fallback if value is None else value
    history=read_or_saved('gateway/history',{'days':(previous or {}).get('days',[])})
    data={'trace':trace,'days':clean(history.get('days',[]))}
    groups=read_or_saved('groups',(previous or {}).get('groups') or {'groups':[],'pools':[],'models':[],'deciders':[]})
    data['groups']=clean(groups)
    # Model and group ids are public model references, not account identities.
    for field in ('groups','models','deciders'):
        for raw,masked in zip(groups.get(field) or [],data['groups'].get(field) or []):
            if 'id' in raw:masked['id']=sanitize_text(str(raw['id']))
    state=read_or_saved('state',(previous or {}).get('state') or {})
    clients=[{k:a[k] for k in ('id','name','icon','installed') if k in a} | {'fields':[]} for a in state.get('clients') or state.get('agents') or []]
    settings={k:state.get('settings',{}).get(k) for k in ('theme','lang','currency','textSize','builtins','quotaLeft') if k in state.get('settings',{})}
    data['settings']=settings
    data['state']={'agents':clients,'clients':clients,'profiles':[],'catalog':'','settings':settings,'fx':state.get('fx',{}),'served':[]}
    provs=read_or_saved('providers',(previous or {}).get('providers') or {'providers':[]})
    public_providers=[]
    for p in provs.get('providers') or []:
        public={k:p[k] for k in ('id','name','icon','preset','off','unlisted','ready','exposed','models','routing','affinity') if k in p}
        public['account']={'user':marker,'plan':(p.get('account') or {}).get('plan','')} if p.get('account') else None
        public['key']={'masked':'••••••','set':bool((p.get('key') or {}).get('set'))}
        public['agents']=[];public['keyList']=[]
        public_providers.append(public)
    data['providers']={'providers':public_providers,'presets':provs.get('presets',{}),'gateway':clean(provs.get('gateway',{}))}
    data['quotas']=clean(read_or_saved('usage/quotas',(previous or {}).get('quotas') or []))
    data['quotasHistory']=clean(read_or_saved('usage/quotas/history?days=45',(previous or {}).get('quotasHistory') or {}))
    data['usage']={}
    data['ledgers']={}
    for period in ('today','last:24h','7d','30d','all'):
        usage=_json('usage?period='+period)
        if usage is None:
            usage=(previous or {}).get('usage',{}).get(period) or magpie.read_public_cache('usage-'+period) or {}
        usage=magpie.sanitize_magpie_usage_for_public(usage)
        for k in ('callerKeys','providerKeys','sessions'):
            if k in usage:
                usage[k]=clean(usage[k])
                for item in usage[k]:
                    if isinstance(item,dict):item['name']=marker
        data['usage'][period]=clean(usage)
        ledger=clean(read_or_saved('usage/requests?period='+period,(previous or {}).get('ledgers',{}).get(period) or {'rows':[],'total':0}))
        for row in ledger.get('rows') or []:
            for key in ('sessionTitle','folder','account','callerKeyName','clientName'):
                if key in row:row[key]=marker
        data['ledgers'][period]=ledger
    # Context/session aggregate views retain numbers, titles and paths are removed.
    for key,path in [('context','context?days=7'),('tune','tune?days=7'),('sessions','sessions'),('sessionStats','sessions/stats?days=7'),('sessionOverview','sessions/overview'),('traffic','usage/traffic'),('heatmap','usage/heatmap?period=30d')]:
        data[key]=clean(read_or_saved(path,(previous or {}).get(key) or {}))
    # Capture each advertised range; offline tabs must not silently reuse 7-day numbers.
    from concurrent.futures import ThreadPoolExecutor
    ranges={}
    for endpoint in ('context','tune'):
        for days in (1,7,30):ranges[f'{endpoint}?days={days}']=(endpoint,days)
    for endpoint in ('sessions/stats','sessions/overview'):
        for days in (0,1,7,30,90):ranges[f'{endpoint}?days={days}']=(endpoint,days)
    with ThreadPoolExecutor(max_workers=3) as pool:
        captured=list(pool.map(_json,ranges))
    data['ranges']={key:clean(value if value is not None else (previous or {}).get('ranges',{}).get(key) or {}) for key,value in zip(ranges,captured)}
    def remove_titles(value):
        if isinstance(value,dict):
            for k,v in value.items():
                if k in {'title','name'} and isinstance(v,str):value[k]=marker
                else:remove_titles(v)
        elif isinstance(value,list):
            for v in value:remove_titles(v)
    for key in ('context','tune','sessions','sessionStats','sessionOverview','ranges'):remove_titles(data[key])
    def final_clean(value):
        if isinstance(value,dict):
            return {opaque(k) if sanitize_text(str(k))!=str(k) else k:final_clean(v) for k,v in value.items()}
        if isinstance(value,list):return [final_clean(v) for v in value]
        return sanitize_text(value,mask_ips=True,mask_paths=True) if isinstance(value,str) else value
    result=final_clean(remove_private(data))
    if any((row or {}).get('calls') or (row or {}).get('agents') or (row or {}).get('models')
           for row in result['usage'].values()) or result['trace'].get('routes'):
        magpie.write_public_cache('native',result)
    return result
