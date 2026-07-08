// GENERATED FROM odyssey — DO NOT EDIT
/*! odyssey-spark v1 */
(function(d,w){
  'use strict';
  if(window.OdysseySpark)return;
  var version='1',states=new WeakMap(),persist=new WeakMap(),roots=[];
  var tok=/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/,store=/^[A-Za-z0-9:_-]{1,64}$/,attr=/^(aria-[a-z-]+|disabled|data-[a-z0-9-]+)$/;
  function ok(v){return tok.test(String(v));}
  function val(v){v=String(v);if(v==='true')return true;if(v==='false')return false;if(/^-?\d+$/.test(v))return parseInt(v,10);return v;}
  function truth(v){return !(v===false||v===0||v==='');}
  function split(v){return(v||'').split(/\s+/).filter(Boolean);}
  function own(el,root){return el.closest('[data-spark]')===root;}
  function clean(){roots=roots.filter(function(r){return r.isConnected;});}
  function storageKey(root,k,name){return name||('spark:'+(root.id||'island')+':'+k);}
  function parseRoot(root){
    var m=new Map(),p=new Map();
    split(root.getAttribute('data-spark')).forEach(function(part){var i=part.indexOf(':'),k=part.slice(0,i),v=part.slice(i+1);if(i>0&&ok(k)&&ok(v))m.set(k,val(v));});
    split(root.getAttribute('data-spark-persist')).forEach(function(part){var x=part.split('='),k=x[0],name=x[1]||'';if(ok(k)&&(!name||store.test(name))){p.set(k,name);try{var got=w.localStorage.getItem(storageKey(root,k,name));if(got!==null&&ok(got))m.set(k,val(got));}catch(e){}}});
    states.set(root,m);persist.set(root,p);if(roots.indexOf(root)<0)roots.push(root);
  }
  function state(root){if(!states.has(root))parseRoot(root);return states.get(root);}
  function match(root,s){
    var neg=false,k,v,i,m=state(root);
    if(!s)return false;
    i=s.indexOf('!=');
    if(i>-1){k=s.slice(0,i);v=s.slice(i+2);return ok(k)&&ok(v)&&m.get(k)!==val(v);}
    i=s.indexOf('=');
    if(i>-1){k=s.slice(0,i);v=s.slice(i+1);return ok(k)&&ok(v)&&m.get(k)===val(v);}
    if(s[0]==='!'){neg=true;s=s.slice(1);}
    return ok(s)&&(neg?!truth(m.get(s)):truth(m.get(s)));
  }
  function writePersist(root,k,v){
    var p=persist.get(root),name=p&&p.get(k);
    if(p&&p.has(k)){try{w.localStorage.setItem(storageKey(root,k,name),String(v));}catch(e){}}
  }
  function set(root,k,v){if(!root||!ok(k)||!ok(v))return;v=val(v);state(root).set(k,v);writePersist(root,k,v);render(root);}
  function toggle(root,k){if(!ok(k))return;var m=state(root),v=!truth(m.get(k));m.set(k,v);writePersist(root,k,v);render(root);}
  function act(root,el,actions){
    actions.split(',').forEach(function(a){a=a.trim();var k,i;
      if(a.indexOf('toggle:')===0)toggle(root,a.slice(7));
      else if(a.indexOf('set:')===0){i=a.indexOf('=');if(i>4)set(root,a.slice(4,i),a.slice(i+1));}
      else if(a.indexOf('setfrom:')===0){k=a.slice(8);if(ok(k)&&ok(el.value))set(root,k,el.value);}
    });
  }
  function render(root){
    state(root);
    Array.prototype.forEach.call(root.querySelectorAll('[data-spark-show]'),function(el){if(own(el,root))el.hidden=!match(root,el.getAttribute('data-spark-show'));});
    Array.prototype.forEach.call(root.querySelectorAll('[data-spark-class]'),function(el){if(!own(el,root))return;split(el.getAttribute('data-spark-class')).forEach(function(x){var i=x.indexOf(':'),c=x.slice(0,i),m=x.slice(i+1);if(i>0)el.classList.toggle(c,match(root,m));});});
    Array.prototype.forEach.call(root.querySelectorAll('[data-spark-text]'),function(el){var k=el.getAttribute('data-spark-text');if(own(el,root)&&ok(k)){var v=state(root).get(k);el.textContent=v==null?'':String(v);}});
    Array.prototype.forEach.call(root.querySelectorAll('[data-spark-attr]'),function(el){if(!own(el,root))return;split(el.getAttribute('data-spark-attr')).forEach(function(x){var i=x.indexOf(':'),a=x.slice(0,i),m=x.slice(i+1),on;if(i<1||!attr.test(a))return;on=match(root,m);if(a==='disabled'){if(on)el.setAttribute(a,'');else el.removeAttribute(a);}else el.setAttribute(a,on?'true':'false');});});
  }
  function charcount(root){
    Array.prototype.forEach.call(root.querySelectorAll('[data-spark-charcount]'),function(el){
      if(el.getAttribute('data-spark-charcount-ready'))return;
      var max=parseInt(el.getAttribute('maxlength'),10);if(!max)return;
      var c=d.createElement('div');c.className='char-counter';el.setAttribute('data-spark-charcount-ready','1');
      function upd(){var n=el.value.length;c.textContent=n+'/'+max;c.classList.toggle('is-max',n>=max);}
      if(el.parentNode)el.parentNode.appendChild(c);upd();el.addEventListener('input',upd);
    });
  }
  function reltime(root){
    var now=Math.floor(Date.now()/1000);
    Array.prototype.forEach.call(root.querySelectorAll('[data-spark-reltime][data-ts]'),function(el){
      var ts=parseInt(el.getAttribute('data-ts'),10),dlt=now-ts,txt='';
      if(isNaN(dlt)||dlt<0)return;
      if(dlt<60)txt='just now';else if(dlt<3600)txt=Math.floor(dlt/60)+'m ago';else if(dlt<86400)txt=Math.floor(dlt/3600)+'h ago';else if(dlt<2592000)txt=Math.floor(dlt/86400)+'d ago';
      if(txt)el.textContent=txt;
    });
  }
  function init(root){
    root=root||d;
    Array.prototype.forEach.call((root.matches&&root.matches('[data-spark]'))?[root]:root.querySelectorAll('[data-spark]'),function(r){if(!states.has(r))parseRoot(r);render(r);r.removeAttribute('data-spark-cloak');Array.prototype.forEach.call(r.querySelectorAll('[data-spark-cloak]'),function(e){if(own(e,r))e.removeAttribute('data-spark-cloak');});Array.prototype.forEach.call(r.querySelectorAll('[data-spark-uncloak]'),function(e){if(own(e,r))e.hidden=false;});});
    charcount(root);reltime(root);clean();
  }
  function rootFor(el){return el&&el.closest&&el.closest('[data-spark]');}
  function delegated(name,e){var el=e.target.closest&&e.target.closest('['+name+']'),r;if(!el)return;r=rootFor(el);if(r)act(r,el,el.getAttribute(name));}
  d.addEventListener('click',function(e){delegated('data-spark-click',e);clean();roots.forEach(function(r){if(!r.hidden&&r.hasAttribute('data-spark-outside')&&!r.contains(e.target))act(r,r,r.getAttribute('data-spark-outside'));});});
  d.addEventListener('input',function(e){delegated('data-spark-input',e);});
  d.addEventListener('change',function(e){delegated('data-spark-change',e);});
  d.addEventListener('keydown',function(e){if(e.key!=='Escape')return;clean();roots.forEach(function(r){if(!r.hidden&&r.hasAttribute('data-spark-esc'))act(r,r,r.getAttribute('data-spark-esc'));});});
  d.addEventListener('odyssey:swap',function(e){init(e.target);});
  function toast(msg,ok){
    var h=d.querySelector('[data-toast-host]');
    if(!h){h=d.createElement('div');h.className='toast-host';h.setAttribute('data-toast-host','');h.setAttribute('aria-live','polite');d.body.appendChild(h);}
    var t=d.createElement('div');t.className='toast '+(ok?'toast--ok':'toast--err');t.setAttribute('role','status');t.textContent=msg;h.appendChild(t);
    w.requestAnimationFrame(function(){t.classList.add('is-in');});
    w.setTimeout(function(){t.classList.remove('is-in');t.classList.add('is-leaving');w.setTimeout(function(){if(t.parentNode)t.parentNode.removeChild(t);},220);},ok?2400:4200);
  }
  window.OdysseySpark={version:version,init:init,toast:toast,get:function(root,k){return state(root).get(k);},set:set};
  if(d.readyState==='loading')d.addEventListener('DOMContentLoaded',function(){init(d);});else init(d);
})(document,window);
