/* Clipper S1 — Studio Edition (v2) main.js */
(function () {
  'use strict';

  var reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var hasHover = window.matchMedia('(hover: hover) and (pointer: fine)').matches;

  document.addEventListener('DOMContentLoaded', init);

  function init() {
    initPreloader();
    initScrollProgress();
    initOverlayMenu();
    initReveal();
    initStory();
    initTilt();
    initRings();
    initFlipCards();
    initMagnetic();
    initCursorRing();
    initBookingForm();
    initMobileCta();
    setYear();
  }

  /* ---------------- Preloader ---------------- */
  function initPreloader() {
    var pre = document.getElementById('preloader');
    if (!pre) return;
    var hidden = false;
    function reveal() {
      if (hidden) return;
      hidden = true;
      setTimeout(function () { pre.classList.add('hide'); }, 500);
    }
    window.addEventListener('load', reveal);
    // Safety net: never let a slow/blocked resource strand users behind the preloader.
    setTimeout(reveal, 2600);
  }

  /* ---------------- Scroll progress bar ---------------- */
  function initScrollProgress() {
    var bar = document.getElementById('scrollProgress');
    if (!bar) return;
    function update() {
      var h = document.documentElement;
      var scrolled = h.scrollTop;
      var max = h.scrollHeight - h.clientHeight;
      var pct = max > 0 ? (scrolled / max) * 100 : 0;
      bar.style.width = pct + '%';
    }
    update();
    window.addEventListener('scroll', update, { passive: true });
    window.addEventListener('resize', update);
  }

  /* ---------------- Overlay fullscreen menu ---------------- */
  function initOverlayMenu() {
    var btn = document.getElementById('menuBtn');
    var overlay = document.getElementById('overlayMenu');
    if (!btn || !overlay) return;

    function close() {
      btn.setAttribute('aria-expanded', 'false');
      overlay.classList.remove('open');
      document.body.style.overflow = '';
    }
    function open() {
      btn.setAttribute('aria-expanded', 'true');
      overlay.classList.add('open');
      document.body.style.overflow = 'hidden';
    }

    btn.addEventListener('click', function () {
      var expanded = btn.getAttribute('aria-expanded') === 'true';
      if (expanded) close(); else open();
    });

    overlay.querySelectorAll('a[data-nav]').forEach(function (a) {
      a.addEventListener('click', close);
    });
  }

  /* ---------------- Generic scroll reveal ---------------- */
  function initReveal() {
    var items = document.querySelectorAll('.reveal2, .bento-card, .hcard, .story-step, .flip-card, .section-head2');
    if (!items.length) return;
    items.forEach(function (el) { el.classList.add('reveal2'); });

    var observer = new IntersectionObserver(function (entries, obs) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add('visible2');
          obs.unobserve(entry.target);
        }
      });
    }, { threshold: 0.12, rootMargin: '0px 0px -40px 0px' });

    items.forEach(function (el) { observer.observe(el); });
  }

  /* ---------------- Story pinned scrollytelling ---------------- */
  function initStory() {
    var steps = document.querySelectorAll('.story-step');
    var img = document.getElementById('storyImg');
    if (!steps.length) return;

    var images = [
      'https://images.unsplash.com/photo-1585747860715-2ba37e788b70?auto=format&fit=crop&w=1200&q=80',
      'https://images.unsplash.com/photo-1599351431202-1e0f0137899a?auto=format&fit=crop&w=1200&q=80',
      'https://images.unsplash.com/photo-1512690459411-b9245aed614b?auto=format&fit=crop&w=1200&q=80',
      'https://images.unsplash.com/photo-1622287162716-f311baa1a2b8?auto=format&fit=crop&w=1200&q=80'
    ];

    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        var step = entry.target;
        if (entry.isIntersecting) {
          steps.forEach(function (s) { s.classList.remove('active-step'); });
          step.classList.add('active-step');
          var idx = parseInt(step.getAttribute('data-step'), 10) || 0;
          if (img && images[idx]) img.src = images[idx];
        }
      });
    }, { threshold: 0.6, rootMargin: '-20% 0px -20% 0px' });

    steps.forEach(function (s) { observer.observe(s); });
  }

  /* ---------------- Tilt on bento cards ---------------- */
  function initTilt() {
    if (!hasHover || reduceMotion) return;
    var cards = document.querySelectorAll('[data-tilt]');
    cards.forEach(function (card) {
      card.addEventListener('mousemove', function (e) {
        var r = card.getBoundingClientRect();
        var x = (e.clientX - r.left) / r.width - 0.5;
        var y = (e.clientY - r.top) / r.height - 0.5;
        card.style.transform = 'perspective(800px) rotateY(' + (x * 8) + 'deg) rotateX(' + (y * -8) + 'deg) translateY(-4px)';
      });
      card.addEventListener('mouseleave', function () {
        card.style.transform = '';
      });
    });
  }

  /* ---------------- Animated stat rings ---------------- */
  function initRings() {
    var rings = document.querySelectorAll('.ring-stat');
    if (!rings.length) return;
    var CIRC = 2 * Math.PI * 52;

    var animated = new WeakSet();
    function animate(el) {
      var target = parseInt(el.getAttribute('data-value'), 10) || 0;
      var fg = el.querySelector('.ring-fg');
      var countEl = el.querySelector('.count');
      var max = 100;
      var offset = CIRC - (Math.min(target, max) / max) * CIRC;
      if (fg) fg.style.strokeDashoffset = offset;

      var duration = 1400;
      var start = null;
      function step(ts) {
        if (!start) start = ts;
        var progress = Math.min((ts - start) / duration, 1);
        var eased = 1 - Math.pow(1 - progress, 3);
        if (countEl) countEl.textContent = Math.floor(eased * target);
        if (progress < 1) requestAnimationFrame(step);
        else if (countEl) countEl.textContent = target;
      }
      requestAnimationFrame(step);
    }

    var observer = new IntersectionObserver(function (entries, obs) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting && !animated.has(entry.target)) {
          animated.add(entry.target);
          animate(entry.target);
          obs.unobserve(entry.target);
        }
      });
    }, { threshold: 0.5 });

    rings.forEach(function (r) { observer.observe(r); });
  }

  /* ---------------- Flip pricing cards ---------------- */
  function initFlipCards() {
    var cards = document.querySelectorAll('.flip-card');
    cards.forEach(function (card) {
      card.addEventListener('click', function (e) {
        if (e.target.closest('a')) return;
        card.classList.toggle('flipped');
      });
    });
  }

  /* ---------------- Magnetic buttons (desktop) ---------------- */
  function initMagnetic() {
    if (!hasHover || reduceMotion) return;
    var btns = document.querySelectorAll('[data-magnetic]');
    btns.forEach(function (btn) {
      btn.addEventListener('mousemove', function (e) {
        var r = btn.getBoundingClientRect();
        var x = e.clientX - r.left - r.width / 2;
        var y = e.clientY - r.top - r.height / 2;
        btn.style.transform = 'translate(' + (x * 0.25) + 'px,' + (y * 0.35) + 'px)';
      });
      btn.addEventListener('mouseleave', function () {
        btn.style.transform = '';
      });
    });
  }

  /* ---------------- Custom cursor ring (desktop) ---------------- */
  function initCursorRing() {
    if (!hasHover || reduceMotion) return;
    var ring = document.getElementById('cursorRing');
    if (!ring) return;
    var x = 0, y = 0;
    window.addEventListener('mousemove', function (e) {
      x = e.clientX; y = e.clientY;
      ring.style.opacity = '1';
      ring.style.left = x + 'px';
      ring.style.top = y + 'px';
    });
    document.addEventListener('mouseleave', function () { ring.style.opacity = '0'; });

    document.querySelectorAll('a, button, [data-tilt]').forEach(function (el) {
      el.addEventListener('mouseenter', function () {
        ring.style.width = '54px'; ring.style.height = '54px';
        ring.style.background = 'rgba(214,255,63,0.15)';
      });
      el.addEventListener('mouseleave', function () {
        ring.style.width = '34px'; ring.style.height = '34px';
        ring.style.background = 'transparent';
      });
    });
  }

  /* ---------------- Booking form ---------------- */
  function initBookingForm() {
    var form = document.getElementById('bookingForm2');
    var fields = document.getElementById('formFields2');
    var success = document.getElementById('formSuccess2');
    var dateInput = document.getElementById('d2');
    if (!form || !fields || !success) return;

    if (dateInput) {
      var today = new Date().toISOString().split('T')[0];
      dateInput.setAttribute('min', today);
    }

    form.addEventListener('submit', function (e) {
      e.preventDefault();
      if (!form.checkValidity()) {
        form.reportValidity();
        return;
      }
      fields.style.display = 'none';
      success.classList.add('show2');
      setTimeout(function () {
        success.classList.remove('show2');
        fields.style.display = '';
        form.reset();
      }, 4200);
    });
  }

  /* ---------------- Sticky mobile CTA ---------------- */
  function initMobileCta() {
    var bar = document.getElementById('mobileCta');
    if (!bar) return;
    window.addEventListener('scroll', function () {
      if (window.scrollY > 500) bar.classList.add('show-cta');
      else bar.classList.remove('show-cta');
    }, { passive: true });
  }

  /* ---------------- Footer year ---------------- */
  function setYear() {
    var y = document.getElementById('year2');
    if (y) y.textContent = new Date().getFullYear();
  }

})();
