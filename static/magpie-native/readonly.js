// svc adapter: upstream display code, server-enforced read-only transport.
(() => {
  const query=new URLSearchParams(location.search);
  window.bootPrefs={web:true,lang:query.get('locale')||'zh',theme:query.get('theme')||'system',featuresOff:[],pluginConfig:{gateway:{callsPage:20}}};
  try { localStorage.setItem('magpie.navLayout','top'); } catch {}
  const nativeFetch=window.fetch.bind(window);
  const waiters=[];
  let active=true;
  const browserHidden=()=>document.visibilityState==='hidden';
  Object.defineProperty(document,'hidden',{configurable:true,get:()=>browserHidden() || !active});
  const allowedViews=new Set(['routing','groups','usage','providers']);
  const blockedWords=['Use a reset','Undo','Clear all usage…','Clear usage…','Clear','Set price…','Review and import…','Edit','New group','Save','Add','Remove','Delete','Import','Bring it back','Settings',"It's verified — try it again",'Refresh model lists','New provider','Add provider','Sign in','Sign out','Switch off','Switch on'];
  function response(data,status=200){return new Response(JSON.stringify(data),{status,headers:{'Content-Type':'application/json'}});}
  window.fetch=async(input,options={})=>{
    const url=new URL(typeof input==='string'?input:input.url,location.href);
    const method=(options.method || (typeof input!=='string'?input.method:'GET') || 'GET').toUpperCase();
    if(url.origin!==location.origin)return response({error:'Read-only view: external request blocked'},403);
    if(!url.pathname.startsWith('/api/'))return nativeFetch(input,options);
    const endpoint=url.pathname.slice(5);
    if(method!=='GET' && !(method==='POST' && ['gateway/session-titles'].includes(endpoint)))return response({error:'Read-only Magpie view'},403);
    if(!active)await new Promise(resolve=>waiters.push(resolve));
    if(window.SVC_MAGPIE_SNAPSHOT)return offline(endpoint,url.searchParams);
    const qs=new URLSearchParams(url.search);
    if(method==='POST')qs.set('payload',options.body || '{}');
    const result=await nativeFetch('/api/magpie/native/'+endpoint+(qs.size?'?'+qs:''),{cache:'no-store',signal:options.signal});
    if(result.ok && endpoint==='state'){
      const data=await result.json();
      if(data.settings){data.settings.lang=query.get('locale')||'zh';data.settings.theme=query.get('theme')||'system';data.settings.navSide=false;}
      return response(data);
    }
    return result;
  };
  let traceDelivered=false;
  async function offline(endpoint,params){
    const map=window.SVC_MAGPIE_SNAPSHOT;
    if(endpoint==='gateway/trace'){
      if(traceDelivered)return new Promise(()=>{});
      traceDelivered=true;
      return response(map.trace || {mine:true,now:new Date().toISOString(),seq:0,routes:[],totals:{requests:0,rerouted:0,errors:0}});
    }
    if(endpoint==='gateway/history')return response(params.get('day') ? {days:map.days||[],routes:map.history?.[params.get('day')]||[]} : {days:map.days||[],routes:[]});
    if(endpoint==='gateway/session-titles')return response({titles:[],sessions:[]});
    if(endpoint==='context/text' || endpoint==='context/reply')return response({archive:'off'},404);
    if(endpoint==='gateway/call' || endpoint==='usage/requests/content')return response({found:false,why:'read',error:'Content hidden in public snapshot'});
    if(endpoint==='usage')return response(map.usage?.[params.get('period')||'30d'] || {});
    if(endpoint==='usage/requests'){
      const ledger=map.ledgers?.[params.get('period')||'30d'] || {rows:[],total:0,agents:[]};
      const offset=Number(params.get('offset')||0);
      return response({...ledger,rows:offset ? [] : (ledger.rows || [])});
    }
    if(endpoint==='usage/heatmap')return response(map.heatmap || {});
    if(endpoint==='usage/traffic')return response(map.traffic || {});
    const days=params.get('days') || (endpoint==='sessions/overview'?'0':'7');
    if(map.ranges?.[endpoint+'?days='+days])return response(map.ranges[endpoint+'?days='+days]);
    if(endpoint==='context')return response(map.context || {});
    if(endpoint==='tune')return response(map.tune || {});
    if(endpoint==='sessions')return response(map.sessions || {});
    if(endpoint==='sessions/stats')return response(map.sessionStats || {});
    if(endpoint==='sessions/overview')return response(map.sessionOverview || {});
    if(endpoint==='usage/quotas')return response(map.quotas || []);
    if(endpoint==='usage/quotas/history')return response(map.quotasHistory || {});
    const key={state:'state',settings:'settings',providers:'providers',groups:'groups','caller-keys':'callerKeys'}[endpoint];
    if(key){
      const value=map[key] || {};
      if(key==='state')return response({...value,settings:{...(value.settings||{}),lang:query.get('locale')||'zh',theme:query.get('theme')||'system'}});
      return response(value);
    }
    return response({});
  }
  // Match the dashboard's static placeholder treatment inside the component.
  // Only already-redacted markers are blurred; private source text is absent.
  function staticRedaction(){
    if(!window.SVC_MAGPIE_SNAPSHOT)return;
    const marker=/\[[^\[\]\n]{0,60}(?:已脱敏|已隐藏|已屏蔽|非公開|redacted|hidden)[^\[\]\n]{0,60}\]|\*{3,}/gi;
    const walker=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT,{acceptNode(node){
      const parent=node.parentElement;
      if(!parent || parent.closest('.redact-mosaic,.svc-static-note,script,style,textarea'))return NodeFilter.FILTER_REJECT;
      marker.lastIndex=0;return marker.test(node.nodeValue)?NodeFilter.FILTER_ACCEPT:NodeFilter.FILTER_REJECT;
    }});
    const nodes=[];while(walker.nextNode())nodes.push(walker.currentNode);
    for(const node of nodes){
      const fragment=document.createDocumentFragment();let last=0;marker.lastIndex=0;
      for(const match of node.nodeValue.matchAll(marker)){
        fragment.append(document.createTextNode(node.nodeValue.slice(last,match.index)));
        const span=document.createElement('span');span.className='redact-mosaic';span.textContent=match[0];
        fragment.append(span);last=match.index+match[0].length;
      }
      fragment.append(document.createTextNode(node.nodeValue.slice(last)));node.replaceWith(fragment);
    }
  }
  function readonlyUI(){
    if(typeof t!=='function')return;
    const words=new Set(blockedWords.flatMap(s=>[s,t(s)]));
    if(window.SVC_MAGPIE_SNAPSHOT)for(const word of ['Export CSV','Download','Download original','Export Markdown']){words.add(word);words.add(t(word));}
    if(window.SVC_MAGPIE_SNAPSHOT && !document.querySelector('.svc-static-note')){
      const note=document.createElement('div');note.className='svc-static-note';
      note.textContent=(query.get('locale')==='zh'?'只读静态快照 · 账号、会话和正文已脱敏 · 历史请求仅保留最近采样':'Read-only snapshot · identities and conversations redacted · recent requests only');
      document.body.prepend(note);
    }
    document.querySelectorAll('button').forEach(button=>{
      if(words.has(button.textContent.replace(/[›↗]/g,'').trim()))button.hidden=true;
    });
    document.querySelectorAll('.quota-autoreset button.lib-switch,.quota-credits button.lib-switch').forEach(control=>{
      const state=document.createElement('span');state.className='svc-setting-state';state.textContent=t(control.classList.contains('on')?'On':'Off');control.replaceWith(state);
    });
    document.querySelectorAll('.rt-group,.rt-pool,.row.provider').forEach(row=>{
      row.onclick=null;row.oncontextmenu=null;row.draggable=false;
      row.querySelectorAll('button,input,select').forEach(control=>{
        const span=document.createElement('span');span.className=control.className;
        if(control.querySelector('.ic'))span.append(...[...control.childNodes].map(n=>n.cloneNode(true)));
        if(!span.childNodes.length)span.textContent=control.getAttribute('role')==='switch' ? (control.getAttribute('aria-checked')==='true'?t('On'):t('Off')) : control.textContent || control.value || '';
        span.title=control.title;control.replaceWith(span);
      });
    });
    document.querySelectorAll('.rt-gedit,.rt-gon,.provider-switch,.provider-add').forEach(e=>e.hidden=true);
    staticRedaction();
  }
  document.addEventListener('contextmenu',event=>{event.preventDefault();event.stopImmediatePropagation();},true);
  document.addEventListener('pointerdown',event=>{if(event.target.closest('.ag-handle,.rt-ghandle,.rt-group .ics'))event.stopImmediatePropagation();},true);
  document.addEventListener('click',event=>{
    const target=event.target.closest('.rt-group,.rt-pool,.row.provider,.rt-gedit,[data-view="settings"],[data-view="plugins"],[data-view="agents"]');
    if(target){event.preventDefault();event.stopImmediatePropagation();}
  },true);
  const observer=new MutationObserver(()=>{observer.disconnect();readonlyUI();observer.observe(document.body,{childList:true,subtree:true});});
  document.addEventListener('DOMContentLoaded',()=>{
    observer.observe(document.body,{childList:true,subtree:true});
    readonlyUI();
    if(typeof window.show==='function'){
      const show=window.show;
      window.show=function(view,...args){if(!allowedViews.has(view))return Promise.resolve(false);return show(view,...args);};
    }
    // Never load third-party scripts, icons or plugins outside the vendored display.
    document.querySelectorAll('img[src^="/api/icons/"]').forEach(img=>img.src='/api/magpie/native/'+new URL(img.src).pathname.slice(5));
  });
  window.addEventListener('message',event=>{
    if(event.source!==parent || event.origin!==location.origin)return;
    if(event.data?.type==='svc-magpie-active'){
      active=!!event.data.active;
      document.dispatchEvent(new Event('visibilitychange'));
      if(active)while(waiters.length)waiters.shift()();
    }
    if(event.data?.type==='svc-magpie-theme'){query.set('theme',event.data.theme);document.documentElement.dataset.theme=event.data.theme;}
    if(event.data?.type==='svc-magpie-refresh')location.reload();
  });
})();
