/* Magpie display component: actual page DOM, scoped styles, no browsing context.
 * Upstream's renderer runs with a component-local document and view state. Its
 * only data transport is readonly.js → the server's allowlisted read bridge.
 */
(() => {
  const sourceCache=new Map();
  const rawFetch=window.fetch.bind(window);
  const text=url=>{
    if(!sourceCache.has(url))sourceCache.set(url,rawFetch(url,{cache:'no-cache'}).then(r=>{if(!r.ok)throw new Error('Magpie asset unavailable: '+new URL(url).pathname);return r.text();}).catch(error=>{sourceCache.delete(url);throw error;}));
    return sourceCache.get(url);
  };
  const runtimeCSS=`
    :host { display:block; min-width:0; color:var(--text-title); font-family:inherit; }
    .mp-native-html { --bg:var(--svc-bg); --card:var(--svc-card); --card-2:var(--svc-hover); --fg:var(--svc-fg); --fg-2:var(--svc-text); --muted:var(--svc-muted); --faint:var(--svc-muted); --line:var(--svc-line); --line-2:var(--svc-line); --accent:var(--svc-accent); --font:var(--svc-font); --font-choice:var(--svc-font); --font-ui:var(--svc-font); color:var(--fg); font:13px/1.5 var(--svc-font); height:auto; min-width:0; }
    .mp-native-body { display:block !important; height:auto !important; min-height:0 !important; min-width:0 !important; width:100%; margin:0 !important; padding:0 !important; overflow:visible !important; background:transparent !important; font-family:var(--svc-font) !important; }
    .mp-native-body > .view { position:relative !important; inset:auto !important; width:100%; height:auto !important; min-height:0 !important; max-height:none !important; overflow:visible !important; margin:0 !important; padding:0 !important; }
    .mp-native-body > .view[hidden] { display:none !important; }
    .rt,.quota,.ctx-card,.usage-box,.sess-kpi,.us-kpi { border-radius:var(--svc-radius) !important; border-color:var(--svc-line); }
    .row-head .label { font-size:14px; font-weight:650; }
    .rt-mode,.rt-what,.ctx-head { line-height:1.55; }
    .row-head .note,.rt-mode,.rt-node small,.rt-accts em { font-size:11.5px; }
    .rt-accts li,.rt-req,.rt-act { font-size:13px; }
    .top,.side,.foot,#sideToggle,#prefs,#sync { display:none !important; }
    .modal { z-index:100; }
    /* Style bridge only: match svc surfaces even when native theme rules apply.
       Outer app.css cannot select elements inside this ShadowRoot. */
    .mp-native-html,.mp-native-html[data-theme] {
      --bg:var(--svc-bg); --card:var(--svc-card); --card-2:var(--bg-elev);
      --fg:var(--svc-fg); --fg-2:var(--svc-text);
      --muted:var(--svc-muted); --faint:var(--text-faint); --ctl-fg:var(--text-soft);
      --line:var(--svc-line); --line-2:var(--border-soft);
      --pill:var(--chip-bg); --pill-hover:var(--svc-hover); --pill-line:var(--svc-line);
      --pill-shadow:none; --card-edge:none;
      --seg-track:var(--svc-hover); --seg-thumb:var(--bg-elev);
      --seg-edge:inset 0 0 0 1px var(--svc-line);
      --accent:var(--svc-accent); --accent-soft:var(--accent-blue-bg); --accent-fg:#fff;
      --sel:var(--accent-blue-bg);
      --green:var(--c-green); --green-soft:var(--c-green-bg);
      --red:var(--c-red); --red-soft:var(--c-red-bg);
      --amber:var(--c-warn); --amber-soft:var(--c-warn-bg);
      --drift:var(--c-red); --drift-soft:var(--c-red-bg);
      --pop-bg:var(--bg-elev); --shadow:var(--glass-shadow);
      --font:var(--svc-font); --skel:var(--bg-hover);
    }
    .mp-native-html :is(.rt,.ctx-card,.usage-box,.subscription-card,.pq-card,.ctx-agent,.ctx-tune,.ctx-sess-list) {
      border-color:var(--svc-line); border-radius:var(--svc-radius);
      background:var(--svc-card); box-shadow:none;
    }
    .mp-native-html :is(.rt,.ctx-card,.usage-box) {
      padding:var(--card-pad-y) var(--card-pad-x); margin-bottom:var(--page-gap);
    }
    .mp-native-html :is(.rt-node,.rt-accts li) { border-radius:8px; }
    .mp-native-html .rt-hub { border-color:var(--svc-accent); box-shadow:none; }
    .mp-native-html .rt-hub i { background:var(--accent-soft); color:var(--accent-blue-tx); }
    .mp-native-html :is(.row-head .label,.subscription-head b,.ctx-head) {
      color:var(--svc-fg); font-size:14px; font-weight:600;
    }
    .mp-native-html :is(.row-head .note,.rt-mode,.rt-node small,.rt-accts em,.quota-reset) {
      color:var(--svc-muted); font-size:11.5px; line-height:1.5;
    }
    .mp-native-html :is(.seg,.sess-pick) { border-radius:8px; }
    .mp-native-html .seg button { font-size:12px; }
    .mp-native-html :is(.sess-kpi,.us-kpi) { font-variant-numeric:tabular-nums; }
    .mp-native-html :is(button,input,select,textarea):focus-visible {
      outline:2px solid var(--focus); outline-offset:2px;
    }
  `;
  function cssScope(css,base){
    return css.replace(/:root/g,'.mp-native-html')
      .replace(/(^|[\s,>+~(])html(?=[\s.#:[>,+~{)])/gm,'$1.mp-native-html')
      .replace(/(^|[\s,>+~(])body(?=[\s.#:[>,+~{)])/gm,'$1.mp-native-body')
      .replace(/url\((['"]?)(?!data:|https?:|blob:|#)([^)'"\s]+)\1\)/g,(_,quote,path)=>`url("${new URL(path,base).href}")`);
  }
  function tokens(host){
    const s=getComputedStyle(document.documentElement);
    const map={'--svc-bg':'--bg','--svc-card':'--bg-panel','--svc-hover':'--bg-hover','--svc-fg':'--text-title','--svc-text':'--text','--svc-muted':'--text-dim','--svc-line':'--border','--svc-accent':'--accent','--svc-radius':'--card-radius'};
    for(const [to,from] of Object.entries(map))host.style.setProperty(to,s.getPropertyValue(from).trim() || (to==='--svc-radius'?'12px':'#888'));
    host.style.setProperty('--svc-font',getComputedStyle(document.body).fontFamily);
  }
  window.mountSvcMagpie=async(host,options)=>{
    host.magpieDispose?.();
    const base=new URL('static/magpie-native/',location.href).href;
    const version=window.__BOOT__?.magpieNativeVersion;
    const markup=await text(base+'index.html'+(version?'?v='+encodeURIComponent(version):''));
    const parsed=new DOMParser().parseFromString(markup,'text/html');
    const scripts=[...parsed.querySelectorAll('script[src]')].map(s=>s.getAttribute('src'));
    const css=[...parsed.querySelectorAll('link[rel="stylesheet"]')].map(s=>s.getAttribute('href'));
    const [code,styles]=await Promise.all([Promise.all(scripts.map(src=>text(new URL(src,base).href))),Promise.all(css.map(src=>text(new URL(src,base).href)))]);
    const root=host.shadowRoot || host.attachShadow({mode:'open'});root.replaceChildren();tokens(host);
    const html=document.createElement('div');html.className='mp-native-html';
    const head=document.createElement('div');head.hidden=true;
    const body=document.createElement('div');body.className='mp-native-body';
    for(const script of parsed.querySelectorAll('script'))script.remove();
    body.append(...parsed.body.childNodes);html.append(head,body);
    const sheet=document.createElement('style');sheet.textContent=styles.map(s=>cssScope(s,base)).join('\n')+'\n'+runtimeCSS;root.append(sheet,html);
    let ready='loading',disposed=false;
    const timers=new Set(),intervals=new Set(),rafs=new Set(),requests=new Set(),listeners=[];
    const eventWindow=new EventTarget();
    const own={};
    const url=new URL('index.html',base);url.searchParams.set('view',options.view);url.searchParams.set('locale',options.lang);url.searchParams.set('theme',options.theme);
    if(options.view==='usage')url.searchParams.set('tab','usage');
    const locationProxy=new Proxy(url,{get(target,key){if(key==='reload')return ()=>host.magpieReload();const value=Reflect.get(target,key,target);return typeof value==='function'?value.bind(target):value;},set(target,key,value){return Reflect.set(target,key,value,target);}});
    const attrs=(element,property)=>{
      const descriptor=Object.getOwnPropertyDescriptor(Object.getPrototypeOf(element),property);
      if(!descriptor?.set || !descriptor.get)return element;
      Object.defineProperty(element,property,{configurable:true,get:()=>descriptor.get.call(element),set:value=>descriptor.set.call(element,new URL(String(value),base).href)});
      return element;
    };
    const makeElement=(tag,...args)=>{
      const node=document.createElement(tag,...args);
      if(tag.toLowerCase()==='img' || tag.toLowerCase()==='script')attrs(node,'src');
      if(tag.toLowerCase()==='link')attrs(node,'href');
      if(tag.toLowerCase()==='a'){
        const descriptor=Object.getOwnPropertyDescriptor(HTMLAnchorElement.prototype,'href');
        Object.defineProperty(node,'href',{get:()=>descriptor.get.call(node),set:value=>{const target=new URL(String(value),base);if(target.origin===location.origin && target.pathname.startsWith('/api/'))target.pathname='/api/magpie/native/'+target.pathname.slice(5);descriptor.set.call(node,target.href);}});
        const click=node.click.bind(node);node.click=()=>{if(own.SVC_MAGPIE_SNAPSHOT && node.href.includes('/api/'))return;click();};
      }
      return node;
    };
    const docProps={};
    const doc=new Proxy(docProps,{get(target,key){
      if(Object.prototype.hasOwnProperty.call(target,key))return Reflect.get(target,key);
      if(key==='body')return body;if(key==='head')return head;if(key==='documentElement')return html;
      if(key==='baseURI'||key==='URL')return url.href;if(key==='readyState')return ready;
      if(key==='currentScript')return {src:base+'start.js'};
      if(key==='activeElement')return root.activeElement || body;
      if(key==='styleSheets')return [sheet.sheet].filter(Boolean);
      if(key==='scripts')return [];
      if(key==='hidden')return document.hidden;
      if(key==='querySelector')return selector=>root.querySelector(selector==='body'?'.mp-native-body':selector==='html'||selector===':root'?'.mp-native-html':selector);
      if(key==='querySelectorAll')return selector=>root.querySelectorAll(selector);
      if(key==='getElementById')return id=>root.querySelector('#'+CSS.escape(id));
      if(key==='createElement')return makeElement;
      if(key==='addEventListener')return (...args)=>root.addEventListener(...args);
      if(key==='removeEventListener')return (...args)=>root.removeEventListener(...args);
      if(key==='dispatchEvent')return e=>root.dispatchEvent(e);
      const value=Reflect.get(document,key,document);return typeof value==='function'?value.bind(document):value;
    }});
    const local=new Proxy(localStorage,{get(target,key){if(['getItem','setItem','removeItem'].includes(key))return (name,...args)=>target[key]('svc-native:'+name,...args);const value=Reflect.get(target,key,target);return typeof value==='function'?value.bind(target):value;},set(target,key,value){target.setItem('svc-native:'+String(key),value);return true;}});
    const scopedHistory={state:null,replaceState(state,_,next){this.state=state;if(next)url.href=new URL(next,url).href;},pushState(state,_,next){this.replaceState(state,_,next);}};
    const scope=new Proxy(own,{has(target,key){return key!=='scope' && (key in target || key in window);},get(target,key){if(key===Symbol.unscopables)return undefined;if(key in target)return target[key];return Reflect.get(window,key,window);},set(target,key,value){target[key]=value;return true;}});
    Object.assign(own,{window:scope,self:scope,globalThis:scope,parent:window,top:scope,document:doc,location:locationProxy,history:scopedHistory,localStorage:local,fetch:(input,options={})=>{const controller=new AbortController();requests.add(controller);return rawFetch(input,{...options,signal:options.signal?AbortSignal.any([options.signal,controller.signal]):controller.signal}).finally(()=>requests.delete(controller));},
      SVC_ASSET_BASE:base,
      Image:function(...args){return attrs(new window.Image(...args),'src');},
      queueMicrotask:window.queueMicrotask.bind(window),scrollTo:window.scrollTo.bind(window),scrollBy:window.scrollBy.bind(window),
      getComputedStyle:window.getComputedStyle.bind(window),matchMedia:window.matchMedia.bind(window),getSelection:window.getSelection.bind(window),
      addEventListener(type,fn,opt){eventWindow.addEventListener(type,fn,opt);if(!['message','load'].includes(type)){const relay=()=>eventWindow.dispatchEvent(new Event(type));window.addEventListener(type,relay,opt);listeners.push(()=>window.removeEventListener(type,relay,opt));}},
      removeEventListener:(...args)=>eventWindow.removeEventListener(...args),dispatchEvent:e=>eventWindow.dispatchEvent(e),
      setTimeout(fn,ms,...args){const id=window.setTimeout(()=>{timers.delete(id);if(!disposed)fn(...args);},ms);timers.add(id);return id;},clearTimeout(id){timers.delete(id);window.clearTimeout(id);},
      setInterval(fn,ms,...args){const id=window.setInterval(()=>{if(!disposed)fn(...args);},ms);intervals.add(id);return id;},clearInterval(id){intervals.delete(id);window.clearInterval(id);},
      requestAnimationFrame(fn){const id=window.requestAnimationFrame(time=>{rafs.delete(id);if(!disposed)fn(time);});rafs.add(id);return id;},cancelAnimationFrame(id){rafs.delete(id);window.cancelAnimationFrame(id);},
    });
    const visible=()=>root.dispatchEvent(new Event('visibilitychange'));
    document.addEventListener('visibilitychange',visible);listeners.push(()=>document.removeEventListener('visibilitychange',visible));
    host.magpieControl=message=>{
      if(message.type==='svc-magpie-theme'){options.theme=message.theme;html.dataset.theme=message.theme;tokens(host);}
      eventWindow.dispatchEvent(new MessageEvent('message',{origin:location.origin,source:window,data:message}));
    };
    host.magpieDispose=()=>{disposed=true;requests.forEach(controller=>controller.abort());timers.forEach(clearTimeout);intervals.forEach(clearInterval);rafs.forEach(cancelAnimationFrame);listeners.forEach(off=>off());};
    host.magpieReload=()=>window.mountSvcMagpie(host,options);
    // Lazy helpers execute in the same component lexical environment as app.js,
    // just as their free identifiers resolve to the upstream window's globals.
    own.__svcModuleText=async name=>{
      const path=new URL(name,base);if(path.origin!==location.origin || !path.href.startsWith(base))throw new Error('Unsupported Magpie module');
      let source=(await text(path.href)).replace(/\bimport\s*\(/g,'__svcImport(').replace(/import\.meta\.url/g,JSON.stringify(path.href)).replaceAll('url(icons/','url('+base+'icons/');
      const exports=[...source.matchAll(/\bexport\s+(?:async\s+)?function\s+([\w$]+)/g)].map(m=>m[1]);
      source=source.replace(/\bexport\s+(?=(?:async\s+)?function\s)/g,'');
      return '(()=>{'+source+'\n;return {'+exports.join(',')+'};})()';
    };
    let bridge='';
    const chunks=code.map((source,index)=>{
      const name=scripts[index].split('?')[0];
      const declared=[...source.matchAll(/^(?:async )?function ([A-Za-z_$][\w$]*)\s*\(/gm)].map(m=>m[1]);
      bridge+=declared.map(name=>`window.${name}=${name};`).join('\n')+'\n';
      const transformed=source.replace(/\bimport\s*\(/g,'__svcImport(').replaceAll('url(icons/','url('+base+'icons/');
      return name==='start.js'?bridge+'\n'+transformed:transformed;
    });
    const modules=new Map();own.__svcModules=modules;
    const program=`with(scope){return (async function(){
      async function __svcImport(name){if(!window.__svcModules.has(name))window.__svcModules.set(name,window.__svcModuleText(name).then(source=>eval(source)));return window.__svcModules.get(name);}
      ${chunks.join('\n;\n')}
      window.__svcReady=true;
    }).call(scope);}`;
    try {
      await new Function('scope',program)(scope);
      ready='interactive';root.dispatchEvent(new Event('DOMContentLoaded'));ready='complete';eventWindow.dispatchEvent(new Event('load'));
      await Promise.resolve();host.dispatchEvent(new Event('magpie-ready'));
      return host;
    } catch(error){host.magpieDispose();throw error;}
  };
})();
