(function () {
  function token() {
    var m=document.cookie.match(/(?:^|;\s*)inventory_csrf=([^;]+)/);
    return m ? decodeURIComponent(m[1]) : '';
  }
  function sameOrigin(url) {
    try { return new URL(url, location.href).origin === location.origin; }
    catch (_) { return true; }
  }
  var origFetch=window.fetch && window.fetch.bind(window);
  if (origFetch) {
    window.fetch=function(input, init) {
      var opts=Object.assign({}, init || {});
      var method=(opts.method || (input && input.method) || 'GET').toUpperCase();
      var url=(typeof input === 'string') ? input : ((input && input.url) || location.href);
      if (!['GET','HEAD','OPTIONS','TRACE'].includes(method) && sameOrigin(url)) {
        var h=new Headers((input && input.headers) || opts.headers || {});
        var t=token(); if (t) h.set('X-CSRF-Token', t);
        opts.headers=h;
      }
      return origFetch(input, opts);
    };
  }
  var open=XMLHttpRequest.prototype.open, send=XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open=function(method,url) {
    this.__invMethod=String(method||'GET').toUpperCase();
    this.__invUrl=url; return open.apply(this,arguments);
  };
  XMLHttpRequest.prototype.send=function(body) {
    if (!['GET','HEAD','OPTIONS','TRACE'].includes(this.__invMethod) && sameOrigin(this.__invUrl)) {
      var t=token(); if (t) this.setRequestHeader('X-CSRF-Token',t);
    }
    return send.apply(this,arguments);
  };
  document.addEventListener('submit',function(e) {
    var f=e.target;if(!f || String(f.method||'GET').toUpperCase()==='GET') return;
    if(!f.querySelector('input[name="_csrf_token"]')) {
      var i=document.createElement('input');i.type='hidden';i.name='_csrf_token';i.value=token();f.appendChild(i);
    }
  },true);
})();