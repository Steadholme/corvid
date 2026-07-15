// GENERATED FROM odyssey — DO NOT EDIT
/*! odyssey-wire v1 — HTML-over-the-wire, Steadholme internal line */
(function(d,w){
  'use strict';
  if(window.OdysseyWire)return;
  var version='1',inFlight=new WeakMap(),links=new WeakMap(),popCtl=null,wireIndex=0,scrolls={};
  var bootWire=history.state&&history.state.odysseyWire;
  if(bootWire&&typeof bootWire.index==='number')wireIndex=bootWire.index;
  scrolls[wireIndex]=history.state&&typeof history.state.owy==='number'?history.state.owy:(w.pageYOffset||0);
  function fire(el,n,detail,cancel){return el.dispatchEvent(new CustomEvent(n,{bubbles:true,cancelable:!!cancel,detail:detail}));}
  function warn(s){if(w.console&&console.warn)console.warn('odyssey-wire: '+s);}
  function cookie(n){var p=d.cookie?d.cookie.split('; '):[];for(var i=0;i<p.length;i++){var e=p[i].indexOf('=');if(e>-1&&p[i].slice(0,e)===n)return decodeURIComponent(p[i].slice(e+1));}return '';}
  function urlOf(u){try{var x=new URL(u,w.location.href);return x.origin===w.location.origin?x:null;}catch(e){return null;}}
  // boost: mark a shell scope `[data-wire-nav="#region"]`; same-origin GET links inside then
  // navigate by swapping #region (View-Transition-animated) + pushState + aria-current — instant,
  // no full reload, ZERO per-link wiring. Opt a link out with `data-wire-off`.
  function boostRegion(a){var s=a.closest&&a.closest('[data-wire-nav]');return s?(s.getAttribute('data-wire-nav')||'').trim():'';}
  function boostable(a){
    if(!a||a.hasAttribute('data-wire')||a.hasAttribute('data-wire-off')||a.target||a.hasAttribute('download')||!a.getAttribute('href'))return null;
    if(/(^|\s)external(\s|$)/.test(a.getAttribute('rel')||''))return null;
    var region=boostRegion(a);if(!region)return null;
    var u=urlOf(a.getAttribute('href'));if(!u||u.href===w.location.href)return null;
    // Gateway control endpoints (/_gw/theme, /_gw/lang, /_gw/auth/*) set a cookie + redirect; they
    // repaint <html>/<head> which a region inner-swap never touches. Never boost them — full nav.
    if(u.pathname.indexOf('/_gw/')===0)return null;
    if(u.pathname===w.location.pathname&&u.search===w.location.search&&u.hash)return null;
    return{u:u,region:region};
  }
  function reduced(){return w.matchMedia&&w.matchMedia('(prefers-reduced-motion:reduce)').matches;}
  // Run the DOM mutation inside a View Transition when boost-navigating: prefer OdysseyMotion
  // (shared timing) but fall back to a direct startViewTransition so boost animates even if the
  // motion module was not loaded; plain call when VT is unsupported or motion is reduced.
  function vtCommit(commit,vt){
    if(vt&&!reduced()){
      if(w.OdysseyMotion&&w.OdysseyMotion.swap){w.OdysseyMotion.swap(commit);return;}
      if(d.startViewTransition){d.startViewTransition(commit);return;}
    }
    commit();
  }
  // Scroll: forward boost nav lands at the top (like a normal link); back/forward restores the
  // saved position. history.scrollRestoration=manual so the browser does not fight us.
  try{if('scrollRestoration' in history)history.scrollRestoration='manual';}catch(e){}
  function wireState(c){return{t:c.t,s:c.s,m:c.m,vt:c.vt};}
  function historyEntry(raw){
    if(raw&&typeof raw.index==='number')return{index:raw.index,incoming:raw.incoming||null,outgoing:raw.outgoing||null};
    if(raw&&raw.t)return{index:wireIndex,incoming:raw,outgoing:raw};
    return{index:wireIndex,incoming:null,outgoing:null};
  }
  function historyWire(raw,from){
    if(!raw)return null;
    if(raw.t)return raw;
    if(typeof raw.index!=='number')return null;
    if(raw.index<from)return raw.outgoing||raw.incoming;
    if(raw.index>from)return raw.incoming||raw.outgoing;
    return raw.incoming||raw.outgoing;
  }
  function saveScroll(c,y){try{
    var s=Object.assign({},history.state||{}),entry=historyEntry(s.odysseyWire);
    y=y==null?(w.pageYOffset||0):y;entry.index=wireIndex;if(c)entry.outgoing=wireState(c);
    s.odysseyWire=entry;s.owy=y;scrolls[wireIndex]=y;history.replaceState(s,'');
  }catch(e){}}
  function trackScroll(){saveScroll(null,w.pageYOffset||0);}
  function flushScroll(){saveScroll(null,Object.prototype.hasOwnProperty.call(scrolls,wireIndex)?scrolls[wireIndex]:(w.pageYOffset||0));}
  function markCurrent(){
    var links=d.querySelectorAll('[data-wire-nav] a[href]'),i,a,lu,current;
    for(i=0;i<links.length;i++){a=links[i];if(a.hasAttribute('data-wire-off')){a.removeAttribute('aria-current');a.classList.remove('is-active');continue;}
      lu=urlOf(a.getAttribute('href'));current=!!(lu&&lu.pathname===w.location.pathname&&(!lu.search||lu.search===w.location.search));
      if(current)a.setAttribute('aria-current','page');else a.removeAttribute('aria-current');a.classList.toggle('is-active',current);}
  }
  function toast(msg,ok){
    if(!msg)return;
    if(w.OdysseySpark&&w.OdysseySpark.toast){w.OdysseySpark.toast(msg,ok);return;}
    var h=d.querySelector('[data-toast-host]');
    if(!h){h=d.createElement('div');h.className='toast-host';h.setAttribute('data-toast-host','');h.setAttribute('aria-live','polite');d.body.appendChild(h);}
    var t=d.createElement('div');t.className='toast '+(ok?'toast--ok':'toast--err');t.setAttribute('role','status');t.textContent=msg;h.appendChild(t);
    w.requestAnimationFrame(function(){t.classList.add('is-in');});
    w.setTimeout(function(){t.classList.remove('is-in');t.classList.add('is-leaving');w.setTimeout(function(){if(t.parentNode)t.parentNode.removeChild(t);},220);},ok?2400:4200);
  }
  function split(v){return(v||'').split(',').map(function(s){return s.trim();}).filter(Boolean);}
  function defTarget(el){var n=el.closest('[id]');return n?'#'+CSS.escape(n.id):'';}
  function cfg(el){
    var v=el.getAttribute('data-wire')||'',tag=el.tagName,targets,selects,mode;
    if(tag==='FORM'){if(el.target)return null;if(v&&v!=='submit'&&v!=='get'){warn('bad form value');return null;}}
    else if(tag==='A'){if(el.target||!el.href)return null;if(v&&v!=='get'){warn('bad link value');return null;}}
    else return null;
    targets=split(el.getAttribute('data-wire-target')||defTarget(el));selects=split(el.getAttribute('data-wire-select')||targets.join(','));
    if(!targets.length||targets.length!==selects.length){warn('target/select mismatch');return null;}
    mode=el.getAttribute('data-wire-swap')||'outer';
    if(['outer','inner','append','prepend','delete'].indexOf(mode)<0){warn('bad swap mode');return null;}
    if(el.hasAttribute('data-wire-optimistic')&&mode!=='delete'){warn('optimistic requires delete');return null;}
    return{t:targets,s:selects,m:mode};
  }
  function csrf(fd){return fd.has('csrf')||fd.has('csrf_token');}
  function addCookieCsrf(fd){var c=cookie('__Host-csrf');if(c&&!csrf(fd))fd.append('csrf_token',c);return !!c||csrf(fd);}
  function formReq(form,submitter){
    var method=(form.getAttribute('method')||'get').toUpperCase(),u=urlOf(form.getAttribute('action')||w.location.pathname),fd,body=null,headers={'Accept':'text/html','X-Wire':'1'};
    if(!u)return null;
    fd=new FormData(form);
    if(submitter&&submitter.name)fd.append(submitter.name,submitter.value);
    if(method==='GET'){u.search=new URLSearchParams(fd).toString();}
    else{
      if(!addCookieCsrf(fd))return null;
      if((form.enctype||'').toLowerCase()==='multipart/form-data')body=fd;
      else{body=new URLSearchParams(fd);headers['Content-Type']='application/x-www-form-urlencoded';}
    }
    return{url:u,method:method,body:body,headers:headers};
  }
  function busy(trigger,targets,on,submitter){
    var label=trigger.getAttribute('data-wire-busy'),el=submitter||trigger,old;
    if(on){
      if(label&&el){old=el.textContent;el.__odyWireText=old;el.textContent=label;}
      if(el)el.setAttribute('aria-busy','true');
      targets.forEach(function(s){var n=q(d,s);if(n)n.classList.add('is-busy');});
    }else{
      if(el){el.removeAttribute('aria-busy');if(el.__odyWireText!=null){el.textContent=el.__odyWireText;delete el.__odyWireText;}}
      targets.forEach(function(s){var n=q(d,s);if(n)n.classList.remove('is-busy');});
    }
  }
  function q(root,sel){try{return root.querySelector(sel);}catch(e){return null;}}
  function focusedIn(nodes){var a=d.activeElement;if(!a)return null;for(var i=0;i<nodes.length;i++)if(nodes[i].contains(a))return a;return null;}
  function formSig(f){try{return(f.getAttribute('action')||'')+'?'+new URLSearchParams(new FormData(f)).toString();}catch(e){return'';}}
  function restoreFocus(old,nodes){
    if(!old)return;
    var id=old.id,found=null,sig='';
    if(id)found=d.getElementById(id);
    if(!found&&old.form){sig=formSig(old.form);nodes.some(function(n){return Array.prototype.some.call(n.querySelectorAll('form'),function(f){if(formSig(f)===sig){found=f.querySelector('button,input[type=submit],input:not([type=hidden]),select,textarea');return true;}return false;});});}
    if(!found)found=nodes[0];
    if(found){if(!found.hasAttribute('tabindex')&&!/^(A|BUTTON|INPUT|SELECT|TEXTAREA)$/.test(found.tagName))found.setAttribute('tabindex','-1');try{found.focus({preventScroll:true});}catch(e){found.focus();}}
  }
  function apply(mode,cur,fresh){
    var n=d.importNode(fresh,true);
    if(mode==='inner'){cur.replaceChildren.apply(cur,Array.prototype.slice.call(n.childNodes));return cur;}
    if(mode==='append'){cur.appendChild(n);return n;}
    if(mode==='prepend'){cur.insertBefore(n,cur.firstChild);return n;}
    cur.replaceWith(n);return n;
  }
  function delTargets(targets){
    var snaps=[];
    targets.forEach(function(s){var n=q(d,s);if(n){snaps.push({p:n.parentNode,next:n.nextSibling,n:n});n.classList.add('is-removing');w.setTimeout(function(){if(n.parentNode)n.parentNode.removeChild(n);},160);}});
    return snaps;
  }
  function rollback(snaps){snaps.forEach(function(x){x.n.classList.remove('is-removing');if(!x.n.parentNode&&x.p)x.p.insertBefore(x.n,x.next);});}
  function finish(trigger,evt,detail,inserted){fire(trigger.isConnected?trigger:(inserted&&inserted[0])||d,evt,detail);}
  function run(trigger,req,c,submitter,push){
    var before={url:req.url.href,method:req.method,targets:c.t,submitter:submitter||null},originY=push?(w.pageYOffset||0):0;
    if(!fire(trigger,'wire:before',before,true))return false;
    var ctl=new AbortController(),snaps=null;
    if(trigger.tagName==='A'){var old=links.get(trigger);if(old)old.abort();links.set(trigger,ctl);}
    if(c.m==='delete'&&trigger.hasAttribute('data-wire-optimistic'))snaps=delTargets(c.t);
    busy(trigger,c.t,true,submitter);
    fetch(req.url.href,{method:req.method,credentials:'same-origin',redirect:'follow',headers:req.headers,body:req.body,signal:ctl.signal}).then(function(res){
      var ru=urlOf(res.url),ct=res.headers.get('Content-Type')||'';
      if(!ru||!res.ok||ct.toLowerCase().indexOf('text/html')<0)throw{status:res.status};
      if(c.m==='delete'){if(!snaps)delTargets(c.t);return{res:res,nodes:[]};}
      return res.text().then(function(text){
        var doc=new DOMParser().parseFromString(text,'text/html'),pairs=[],cur,fresh;
        for(var i=0;i<c.t.length;i++){cur=q(d,c.t[i]);fresh=q(doc,c.s[i]);if(!cur||!fresh){w.location.assign(ru.href);return null;}pairs.push([cur,fresh,c.t[i]]);}
        var active=focusedIn(pairs.map(function(p){return p[0];})),ins=[];
        function commit(){pairs.forEach(function(p){var n=apply(c.m,p[0],p[1]);ins.push(n);fire(n,'odyssey:swap',{url:res.url,mode:c.m,selector:p[2]});});restoreFocus(active,ins);}
        vtCommit(commit,c.vt);
        return{res:res,nodes:ins};
      });
    }).then(function(out){
      if(!out)return;
      if(push){
        var incoming=wireState(c),next=wireIndex+1,destY=c.vt?0:(w.pageYOffset||0);
        saveScroll(c,originY);
        history.pushState({odysseyWire:{index:next,incoming:incoming,outgoing:null},owy:destY},'',out.res.url);
        wireIndex=next;scrolls[wireIndex]=destY;if(c.vt)w.scrollTo(0,0);
      }
      finish(trigger,'wire:after',{url:out.res.url,status:out.res.status,redirected:out.res.redirected,targets:c.t},out.nodes);
      toast(trigger.getAttribute('data-wire-ok'),true);
    }).catch(function(err){
      if(snaps)rollback(snaps);
      if(err&&err.name==='AbortError')return;
      fire(trigger,'wire:error',{status:err&&err.status||0,error:err});
      toast(trigger.getAttribute('data-wire-err')||'Could not save — try again',false);
    }).finally(function(){busy(trigger,c.t,false,submitter);if(trigger.tagName==='FORM')inFlight.delete(trigger);});
    return true;
  }
  d.addEventListener('submit',function(e){
    var f=e.target,c,req,push;
    if(!(f instanceof HTMLFormElement)||!f.hasAttribute('data-wire'))return;
    c=cfg(f);req=c&&formReq(f,e.submitter);
    if(!c||!req)return;
    if(inFlight.has(f)){e.preventDefault();return;}
    push=req.method==='GET'&&f.hasAttribute('data-wire-push');
    if(run(f,req,c,e.submitter,push)){e.preventDefault();inFlight.set(f,1);}
  });
  d.addEventListener('click',function(e){
    if(e.defaultPrevented||e.button||e.metaKey||e.ctrlKey||e.shiftKey||e.altKey)return;
    var link=e.target.closest&&e.target.closest('a'),c,u,b,H={'Accept':'text/html','X-Wire':'1'};
    if(!link)return;
    if(link.hasAttribute('data-wire')){
      c=cfg(link);u=c&&urlOf(link.getAttribute('href'));if(!c||!u)return;
      if(run(link,{url:u,method:'GET',body:null,headers:H},c,null,link.hasAttribute('data-wire-push')))e.preventDefault();
      return;
    }
    b=boostable(link);if(!b)return;
    if(run(link,{url:b.u,method:'GET',body:null,headers:H},{t:[b.region],s:[b.region],m:'inner',vt:true},null,true))e.preventDefault();
  });
  w.addEventListener('popstate',function(e){
    var from=wireIndex,raw=e.state&&e.state.odysseyWire,s=historyWire(raw,from),ctl,restoreY;
    if(!s)return;
    // Append/prepend/delete do not have a reversible DOM operation. Preserve native History
    // correctness by reloading the destination instead of trying to replay a lossy mutation.
    if(s.m!=='outer'&&s.m!=='inner'){w.location.reload();return;}
    if(popCtl)popCtl.abort();ctl=new AbortController();popCtl=ctl;
    if(raw&&typeof raw.index==='number')wireIndex=raw.index;
    restoreY=Object.prototype.hasOwnProperty.call(scrolls,wireIndex)?scrolls[wireIndex]:(e.state&&typeof e.state.owy==='number'?e.state.owy:0);
    fetch(w.location.href,{credentials:'same-origin',headers:{'Accept':'text/html','X-Wire':'1'},signal:ctl.signal}).then(function(r){
      var ru=urlOf(r.url),ct=r.headers.get('Content-Type')||'';
      if(!ru||!r.ok||ct.toLowerCase().indexOf('text/html')<0)throw{status:r.status};
      return r.text();
    }).then(function(text){
      var doc=new DOMParser().parseFromString(text,'text/html'),ok=true,nodes=[];
      s.t.forEach(function(t,i){var cur=q(d,t),fresh=q(doc,s.s[i]);if(!cur||!fresh)ok=false;else nodes.push([cur,fresh,t]);});
      if(!ok){w.location.reload();return;}
      function commit(){nodes.forEach(function(p){var n=apply(s.m,p[0],p[1]);fire(n,'odyssey:swap',{url:w.location.href,mode:s.m,selector:p[2]});});markCurrent();w.scrollTo(0,restoreY);}
      vtCommit(commit,s.vt);
    }).catch(function(err){if(err&&err.name==='AbortError')return;w.location.reload();}).finally(function(){if(popCtl===ctl)popCtl=null;});
  });
  d.addEventListener('wire:after',function(){markCurrent();});
  w.addEventListener('scroll',trackScroll,{passive:true});
  w.addEventListener('pagehide',flushScroll);
  if(d.readyState!=='loading')markCurrent();else d.addEventListener('DOMContentLoaded',markCurrent);
  window.OdysseyWire={version:version,toast:toast,post:function(url,data,csrfField){
    var u=urlOf(url),fd=new URLSearchParams(data||{}),c=cookie('__Host-csrf'),field=csrfField||'csrf_token';
    if(!u)return Promise.reject(new Error('cross-origin'));
    if(c&&!fd.has(field))fd.append(field,c);
    return fetch(u.href,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/x-www-form-urlencoded','Accept':'application/json'},body:fd});
  }};
})(document,window);
