/* Sentry first-party browser collector. Reads device traits, posts them once
   per session to the collect endpoint next to this script. No third-party
   code, no storage beyond a sessionStorage flag. */
(function () {
  "use strict";
  var script = document.currentScript;
  if (!script || !window.fetch) return;
  var endpoint;
  try {
    endpoint = new URL("collect", script.src).href;
    if (sessionStorage.getItem("sentry_fp")) return;
  } catch (e) {}

  function hash(str) {
    var h1 = 0xdeadbeef, h2 = 0x41c6ce57;
    for (var i = 0; i < str.length; i++) {
      var c = str.charCodeAt(i);
      h1 = Math.imul(h1 ^ c, 2654435761);
      h2 = Math.imul(h2 ^ c, 1597334677);
    }
    h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
    h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
    return (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(16);
  }

  var out = { v: 1 };
  var errors = [];
  function probe(name, fn) {
    try { fn(); } catch (e) { errors.push(name); }
  }

  probe("nav", function () {
    var n = navigator;
    out.ua = n.userAgent;
    out.platform = n.platform;
    out.langs = Array.prototype.slice.call(n.languages || [n.language]).slice(0, 8);
    out.hw = n.hardwareConcurrency;
    out.mem = n.deviceMemory;
    out.touch = n.maxTouchPoints;
    out.plugins = n.plugins ? n.plugins.length : undefined;
    out.mimes = n.mimeTypes ? n.mimeTypes.length : undefined;
    out.webdriver = !!n.webdriver;
    out.chrome = typeof window.chrome === "object" && window.chrome !== null;
  });
  probe("tz", function () {
    out.tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
  });
  probe("screen", function () {
    out.screen = [screen.width, screen.height, screen.colorDepth];
    out.dpr = window.devicePixelRatio;
  });
  probe("canvas", function () {
    var c = document.createElement("canvas");
    c.width = 220; c.height = 40;
    var x = c.getContext("2d");
    x.textBaseline = "alphabetic";
    x.fillStyle = "#f60"; x.fillRect(100, 1, 62, 20);
    x.fillStyle = "#069"; x.font = "15px 'Arial'";
    x.fillText("Sentry, ☃ 😃 cwm fjordbank", 2, 15);
    x.fillStyle = "rgba(102,204,0,0.7)"; x.font = "18px serif";
    x.fillText("Sentry, ☃ 😃 cwm fjordbank", 4, 30);
    out.canvas = hash(c.toDataURL());
  });
  probe("webgl", function () {
    var c = document.createElement("canvas");
    var gl = c.getContext("webgl") || c.getContext("experimental-webgl");
    if (!gl) return;
    var info = gl.getExtension("WEBGL_debug_renderer_info");
    if (info) {
      out.webgl_vendor = gl.getParameter(info.UNMASKED_VENDOR_WEBGL);
      out.webgl_renderer = gl.getParameter(info.UNMASKED_RENDERER_WEBGL);
    }
    var p = [
      gl.getParameter(gl.MAX_TEXTURE_SIZE),
      gl.getParameter(gl.MAX_VERTEX_ATTRIBS),
      gl.getParameter(gl.MAX_VIEWPORT_DIMS),
      gl.getParameter(gl.ALIASED_LINE_WIDTH_RANGE),
      gl.getParameter(gl.ALIASED_POINT_SIZE_RANGE),
      gl.getParameter(gl.VERSION),
      (gl.getSupportedExtensions() || []).join(",")
    ];
    out.webgl = hash(JSON.stringify(p));
  });
  probe("fonts", function () {
    var base = ["monospace", "sans-serif", "serif"];
    var test = ["Arial", "Verdana", "Times New Roman", "Courier New", "Georgia", "Tahoma",
      "Trebuchet MS", "Impact", "Comic Sans MS", "Segoe UI", "Calibri", "Cambria",
      "Consolas", "Helvetica", "Menlo", "Monaco", "SF Pro Text", "Ubuntu", "DejaVu Sans",
      "Liberation Sans", "Noto Sans", "Roboto", "Open Sans", "Lucida Console",
      "Palatino Linotype", "Garamond", "Futura", "Gill Sans", "Optima", "Apple Color Emoji"];
    var s = document.createElement("span");
    s.style.cssText = "position:absolute;left:-9999px;font-size:72px;visibility:hidden";
    s.textContent = "mmmmmmmmmmlli";
    document.body.appendChild(s);
    var w0 = {};
    base.forEach(function (b) { s.style.fontFamily = b; w0[b] = s.offsetWidth; });
    var mask = test.map(function (f) {
      return base.some(function (b) {
        s.style.fontFamily = "'" + f + "'," + b;
        return s.offsetWidth !== w0[b];
      }) ? "1" : "0";
    }).join("");
    document.body.removeChild(s);
    out.fonts = hash(mask);
  });

  function audio(done) {
    var finished = false;
    function end(v) { if (!finished) { finished = true; if (v) out.audio = v; done(); } }
    try {
      var Ctx = window.OfflineAudioContext || window.webkitOfflineAudioContext;
      if (!Ctx) return end();
      var ctx = new Ctx(1, 5000, 44100);
      var osc = ctx.createOscillator();
      osc.type = "triangle"; osc.frequency.value = 10000;
      var comp = ctx.createDynamicsCompressor();
      comp.threshold.value = -50; comp.knee.value = 40; comp.ratio.value = 12;
      comp.attack.value = 0; comp.release.value = 0.25;
      osc.connect(comp); comp.connect(ctx.destination);
      osc.start(0);
      ctx.oncomplete = function (ev) {
        try {
          var d = ev.renderedBuffer.getChannelData(0), sum = 0;
          for (var i = 4500; i < 5000; i++) sum += Math.abs(d[i]);
          end(hash(sum.toString()));
        } catch (e) { errors.push("audio"); end(); }
      };
      ctx.startRendering();
      setTimeout(function () { errors.push("audio"); end(); }, 1500);
    } catch (e) { errors.push("audio"); end(); }
  }

  function send() {
    if (errors.length) out.errors = errors.slice(0, 8);
    try {
      fetch(endpoint, {
        method: "POST",
        credentials: "same-origin",
        keepalive: true,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(out)
      }).then(function (r) {
        if (r.ok) { try { sessionStorage.setItem("sentry_fp", "1"); } catch (e) {} }
      }, function () {});
    } catch (e) {}
  }

  function run() { audio(send); }
  if (document.readyState === "complete") setTimeout(run, 0);
  else window.addEventListener("load", function () { setTimeout(run, 0); });
})();
