(function () {
  var toast = document.getElementById('toast');
  var timer;
  function say(text) {
    toast.textContent = text;
    toast.classList.add('show');
    clearTimeout(timer);
    timer = setTimeout(function () { toast.classList.remove('show'); }, 2200);
  }
  function fallbackCopy(text) {
    var t = document.createElement('textarea');
    t.value = text; t.style.position = 'fixed'; t.style.opacity = '0';
    document.body.appendChild(t); t.select();
    try { document.execCommand('copy'); } catch (e) {}
    document.body.removeChild(t);
  }
  document.querySelectorAll('.copy').forEach(function (b) {
    b.addEventListener('click', function () {
      var text = b.dataset.copy;
      if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(text).catch(function () { fallbackCopy(text); });
      else fallbackCopy(text);
      say('Copied. Paste it to your agent.');
    });
  });

  var shoe = document.getElementById('heroShoe');
  if (shoe && !window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    window.addEventListener('mousemove', function (e) {
      var x = (e.clientX / window.innerWidth - .5) * 2, y = (e.clientY / window.innerHeight - .5) * 2;
      shoe.style.transform = 'rotate(' + (-9 + x * 4) + 'deg) translate(' + x * 10 + 'px,' + y * 8 + 'px)';
    });
  }
}());
