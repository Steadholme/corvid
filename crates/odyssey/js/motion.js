// GENERATED FROM odyssey — DO NOT EDIT
/*! odyssey-motion v1 — sovereign motion helpers, Steadholme internal line.
   The headline (cross-document View Transitions, held chrome, sliding indicators) is 100% CSS in
   motion.css and works with THIS FILE ABSENT. This is optional polish for same-document motion:
   a startViewTransition() wrapper + a FLIP list animator. Zero eval / zero network / audited IIFE,
   same locked test loop as wire.js/spark.js. Every path early-returns under reduced-motion or when
   the native API is missing, so it is a strict superset of a working no-JS floor. */
(function(d, w){
  'use strict';
  if(w.OdysseyMotion)return;
  var REDUCE = !!(w.matchMedia && w.matchMedia('(prefers-reduced-motion: reduce)').matches);
  if(w.matchMedia){
    try{ w.matchMedia('(prefers-reduced-motion: reduce)').addEventListener('change', function(e){ REDUCE = e.matches; }); }catch(e){}
  }
  var canAnimate = typeof Element !== 'undefined' && !!Element.prototype.animate;
  var DUR = 180, ENTER_DUR = 200, EASE = 'cubic-bezier(.2,.6,.25,1)';
  var seen = new WeakSet();          // containers already wired
  var rects = new WeakMap();         // child element -> last-known {top,left}

  /* Wrap a synchronous DOM update in a same-document View Transition when the browser supports it
     and motion is allowed; otherwise run it straight (the optimistic write still lands). Returns a
     transition-like object so callers can await .finished uniformly. */
  function swap(update){
    if(REDUCE || typeof d.startViewTransition !== 'function'){
      try{ update(); }catch(e){}
      return { finished:Promise.resolve(), ready:Promise.resolve(), updateCallbackDone:Promise.resolve() };
    }
    return d.startViewTransition(update);
  }

  function snapshot(container){
    var kids = container.children, i, el, r;
    for(i=0;i<kids.length;i++){
      el = kids[i];
      r = el.getBoundingClientRect();
      rects.set(el, { top:r.top, left:r.left });
    }
  }

  function play(container){
    if(!canAnimate || REDUCE){ snapshot(container); return; }
    var kids = container.children, i, el, prev, now, dx, dy;
    for(i=0;i<kids.length;i++){
      el = kids[i];
      now = el.getBoundingClientRect();
      prev = rects.get(el);
      if(prev){
        dx = prev.left - now.left;
        dy = prev.top - now.top;
        if(dx || dy){
          try{
            el.animate([{ transform:'translate(' + dx + 'px,' + dy + 'px)' }, { transform:'none' }],
              { duration:DUR, easing:EASE });
          }catch(e){}
        }
      } else {
        // newly inserted child rises in
        try{
          el.animate([{ opacity:0, transform:'translateY(6px)' }, { opacity:1, transform:'none' }],
            { duration:ENTER_DUR, easing:EASE });
        }catch(e){}
      }
      rects.set(el, { top:now.top, left:now.left });
    }
  }

  function wireList(container){
    if(seen.has(container))return;
    seen.add(container);
    snapshot(container);
    if(typeof MutationObserver !== 'function')return;
    var scheduled = false;
    var mo = new MutationObserver(function(){
      if(scheduled)return;
      scheduled = true;
      // run after the mutation settles so getBoundingClientRect reflects the new layout
      (w.requestAnimationFrame || w.setTimeout)(function(){ scheduled = false; play(container); });
    });
    mo.observe(container, { childList:true });
  }

  function enter(el){
    if(!canAnimate || REDUCE || el.__odyEntered)return;
    el.__odyEntered = 1;
    try{
      el.animate([{ opacity:0, transform:'translateY(6px)' }, { opacity:1, transform:'none' }],
        { duration:ENTER_DUR, easing:EASE });
    }catch(e){}
  }

  function scan(root){
    var r = root || d, lists, ents, i;
    lists = r.querySelectorAll ? r.querySelectorAll('[data-motion-list]') : [];
    for(i=0;i<lists.length;i++)wireList(lists[i]);
    ents = r.querySelectorAll ? r.querySelectorAll('[data-motion-enter]') : [];
    for(i=0;i<ents.length;i++)enter(ents[i]);
  }

  // Re-scan after HTML-over-the-wire swaps (odyssey-wire dispatches this on every swapped node).
  d.addEventListener('odyssey:swap', function(e){ scan(e.target || d); });

  window.OdysseyMotion = { version:'1', swap:swap, scan:scan };

  if(d.readyState === 'loading') d.addEventListener('DOMContentLoaded', function(){ scan(d); });
  else scan(d);
})(document, window);
