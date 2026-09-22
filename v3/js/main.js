/* Clipper S1 — Prestige Suite (v3) main.js */
(function () {
  'use strict';

  var reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var hasHover = window.matchMedia('(hover: hover) and (pointer: fine)').matches;

  document.addEventListener('DOMContentLoaded', init);

  function init() {
    initPreloader();
    initTheme();
    initSpotlight();
    initNav();
    initMobileMenu();
    initReveal();
    initHours();
    initBeforeAfter();
    initCalculator();
    initMembershipCarousel();
    initAvailability();
    initGalleryLightbox();
    initFollowCounter();
    initReviews();
    initFaq();
    initWizard();
    initNewsletter();
    initFab();
    initCookieBar();
    setYear();
  }

  /* ---------------- Preloader with % counter ---------------- */
  function initPreloader() {
    var pre = document.getElementById('preloader');
    var pct = document.getElementById('preloadPct');
    if (!pre) return;
    var n = 0;
    var timer = setInterval(function () {
      n += Math.floor(Math.random() * 18) + 6;
      if (n >= 100) { n = 100; clearInterval(timer); }
      if (pct) pct.textContent = n + '%';
    }, 120);

    var hidden = false;
    function reveal() {
      if (hidden) return;
      hidden = true;
      clearInterval(timer);
      if (pct) pct.textContent = '100%';
      setTimeout(function () { pre.classList.add('hide'); }, 300);
    }
    window.addEventListener('load', function () { setTimeout(reveal, 400); });
    // Safety net: never let a slow/blocked resource strand users behind the preloader.
    setTimeout(reveal, 2600);
  }

  /* ---------------- Theme toggle ---------------- */
  function initTheme() {
    var toggle = document.getElementById('themeToggle');
    var root = document.documentElement;
    var saved = null;
    try { saved = localStorage.getItem('clipperS1PrestigeTheme'); } catch (e) {}
    if (saved === 'light') root.setAttribute('data-theme', 'light');

    if (!toggle) return;
    toggle.addEventListener('click', function () {
      var isLight = root.getAttribute('data-theme') === 'light';
      if (isLight) root.removeAttribute('data-theme');
      else root.setAttribute('data-theme', 'light');
      try { localStorage.setItem('clipperS1PrestigeTheme', isLight ? 'dark' : 'light'); } catch (e) {}
    });
  }

  /* ---------------- Cursor spotlight ---------------- */
  function initSpotlight() {
    if (!hasHover || reduceMotion) return;
    var spot = document.getElementById('spotlight');
    if (!spot) return;
    var raf = null;
    window.addEventListener('mousemove', function (e) {
      if (raf) return;
      raf = requestAnimationFrame(function () {
        spot.style.setProperty('--sx', e.clientX + 'px');
        spot.style.setProperty('--sy', e.clientY + 'px');
        raf = null;
      });
    });
  }

  /* ---------------- Nav: sliding pill + scrollspy ---------------- */
  function initNav() {
    var links = document.querySelectorAll('.p-nav-link[data-pnav]');
    var pill = document.getElementById('pPill');
    var navLinksWrap = document.getElementById('pNavLinks');
    if (!links.length || !pill || !navLinksWrap) return;

    function movePill(el) {
      if (!el || navLinksWrap.offsetWidth === 0) return;
      pill.style.left = el.offsetLeft + 'px';
      pill.style.width = el.offsetWidth + 'px';
    }

    var activeLink = document.querySelector('.p-nav-link.active') || links[0];
    setTimeout(function () { movePill(activeLink); }, 60);
    window.addEventListener('resize', function () { movePill(document.querySelector('.p-nav-link.active')); });

    links.forEach(function (l) {
      l.addEventListener('mouseenter', function () { movePill(l); });
    });
    navLinksWrap.addEventListener('mouseleave', function () { movePill(document.querySelector('.p-nav-link.active')); });

    var sections = document.querySelectorAll('section[id]');
    var map = {};
    links.forEach(function (l) { map[l.getAttribute('href').slice(1)] = l; });

    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          links.forEach(function (l) { l.classList.remove('active'); });
          var link = map[entry.target.id];
          if (link) { link.classList.add('active'); movePill(link); }
        }
      });
    }, { rootMargin: '-45% 0px -50% 0px' });
    sections.forEach(function (s) { observer.observe(s); });
  }

  /* ---------------- Mobile menu ---------------- */
  function initMobileMenu() {
    var btn = document.getElementById('pHamburger');
    var menu = document.getElementById('pMobileMenu');
    var overlay = document.getElementById('pMobileOverlay');
    if (!btn || !menu) return;

    function close() {
      btn.setAttribute('aria-expanded', 'false');
      menu.classList.remove('open');
      if (overlay) overlay.classList.remove('open');
      document.body.style.overflow = '';
    }
    function open() {
      btn.setAttribute('aria-expanded', 'true');
      menu.classList.add('open');
      if (overlay) overlay.classList.add('open');
      document.body.style.overflow = 'hidden';
    }

    btn.addEventListener('click', function () {
      var expanded = btn.getAttribute('aria-expanded') === 'true';
      if (expanded) close(); else open();
    });
    if (overlay) overlay.addEventListener('click', close);
    menu.querySelectorAll('a').forEach(function (a) { a.addEventListener('click', close); });
    window.addEventListener('resize', function () { if (window.innerWidth >= 992) close(); });
  }

  /* ---------------- Reveal on scroll ---------------- */
  function initReveal() {
    var targets = document.querySelectorAll('.p-section-head, .p-calc, .p-mem-carousel, .p-slots, .p-grid-item, .p-award, .p-faq-item, .p-ba-frame, .p-wizard');
    targets.forEach(function (el) { el.classList.add('p-reveal'); });
    var observer = new IntersectionObserver(function (entries, obs) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) { entry.target.classList.add('p-visible'); obs.unobserve(entry.target); }
      });
    }, { threshold: 0.1, rootMargin: '0px 0px -40px 0px' });
    targets.forEach(function (el) { observer.observe(el); });
  }

  /* ---------------- Live open/closed hours ---------------- */
  function initHours() {
    var badgeDot = document.querySelector('#statusBadge .p-status-dot');
    var text = document.getElementById('statusText');
    var footerDot = document.querySelector('#hoursLive .p-status-dot');
    var footerText = document.getElementById('hoursLiveText');
    if (!text) return;

    function hoursFor(day) {
      if (day === 0) return [10, 18];
      if (day === 6) return [9, 21];
      return [9, 20];
    }

    function update() {
      var now = new Date();
      var day = now.getDay();
      var hour = now.getHours() + now.getMinutes() / 60;
      var range = hoursFor(day);
      var open = hour >= range[0] && hour < range[1];
      var msg = open
        ? 'Open now — until ' + formatHour(range[1])
        : 'Closed — opens ' + (hour < range[0] ? 'today' : 'tomorrow') + ' at ' + formatHour(range[0]);

      [text, footerText].forEach(function (el) { if (el) el.textContent = msg; });
      [badgeDot, footerDot].forEach(function (el) { if (el) el.classList.toggle('closed', !open); });
    }

    function formatHour(h) {
      var hh = h % 12 === 0 ? 12 : h % 12;
      return hh + (h >= 12 ? 'PM' : 'AM');
    }

    update();
    setInterval(update, 60000);
  }

  /* ---------------- Before / After slider ---------------- */
  function initBeforeAfter() {
    var range = document.getElementById('baRange');
    var afterWrap = document.getElementById('baAfterWrap');
    var line = document.getElementById('baLine');
    if (!range || !afterWrap || !line) return;

    function update() {
      var v = range.value;
      afterWrap.style.clipPath = 'inset(0 ' + (100 - v) + '% 0 0)';
      line.style.left = v + '%';
    }
    range.addEventListener('input', update);
    update();
  }

  /* ---------------- Price calculator ---------------- */
  function initCalculator() {
    var items = document.querySelectorAll('.p-calc-item input');
    var totalEl = document.getElementById('calcTotal');
    var countEl = document.getElementById('calcCount');
    var totalWrap = totalEl ? totalEl.closest('.p-calc-total') : null;
    if (!items.length || !totalEl) return;

    function update() {
      var total = 0, count = 0;
      items.forEach(function (i) {
        if (i.checked) { total += parseInt(i.getAttribute('data-price'), 10) || 0; count++; }
      });
      totalEl.textContent = total;
      if (countEl) countEl.textContent = count;
      if (totalWrap) {
        totalWrap.classList.add('p-pulse');
        setTimeout(function () { totalWrap.classList.remove('p-pulse'); }, 200);
      }
    }
    items.forEach(function (i) { i.addEventListener('change', update); });
    update();
  }

  /* ---------------- Membership carousel ---------------- */
  function initMembershipCarousel() {
    var track = document.getElementById('memTrack');
    var prev = document.getElementById('memPrev');
    var next = document.getElementById('memNext');
    var dotsWrap = document.getElementById('memDots');
    if (!track || !dotsWrap) return;

    var cards = track.children;
    for (var i = 0; i < cards.length; i++) {
      var dot = document.createElement('span');
      if (i === 0) dot.classList.add('active');
      dot.addEventListener('click', (function (idx) {
        return function () { scrollToCard(idx); };
      })(i));
      dotsWrap.appendChild(dot);
    }
    var dots = dotsWrap.querySelectorAll('span');

    function scrollToCard(idx) {
      var card = cards[idx];
      if (!card) return;
      track.scrollTo({ left: card.offsetLeft - (track.offsetWidth - card.offsetWidth) / 2, behavior: 'smooth' });
    }

    function currentIndex() {
      var center = track.scrollLeft + track.offsetWidth / 2;
      var closest = 0, min = Infinity;
      for (var i = 0; i < cards.length; i++) {
        var cCenter = cards[i].offsetLeft + cards[i].offsetWidth / 2;
        var d = Math.abs(cCenter - center);
        if (d < min) { min = d; closest = i; }
      }
      return closest;
    }

    function syncDots() {
      var idx = currentIndex();
      dots.forEach(function (d, di) { d.classList.toggle('active', di === idx); });
    }

    var scrollTimer;
    track.addEventListener('scroll', function () {
      clearTimeout(scrollTimer);
      scrollTimer = setTimeout(syncDots, 100);
    }, { passive: true });

    if (prev) prev.addEventListener('click', function () { scrollToCard(Math.max(0, currentIndex() - 1)); });
    if (next) next.addEventListener('click', function () { scrollToCard(Math.min(cards.length - 1, currentIndex() + 1)); });
  }

  /* ---------------- Availability slots ---------------- */
  function initAvailability() {
    var slots = document.querySelectorAll('.p-slot:not(:disabled)');
    if (!slots.length) return;
    slots.forEach(function (slot) {
      slot.addEventListener('click', function () {
        slots.forEach(function (s) { s.classList.remove('selected'); });
        slot.classList.add('selected');
        var time = slot.getAttribute('data-time');
        var wTime = document.getElementById('wTime');
        if (wTime) wTime.value = time;
        var book = document.getElementById('book');
        if (book) book.scrollIntoView({ behavior: 'smooth', block: 'start' });
      });
    });
  }

  /* ---------------- Gallery lightbox ---------------- */
  function initGalleryLightbox() {
    var items = document.querySelectorAll('.p-grid-item');
    var lightbox = document.getElementById('pLightbox');
    var img = document.getElementById('pLightboxImg');
    var closeBtn = document.getElementById('pLightboxClose');
    if (!items.length || !lightbox || !img || !closeBtn) return;

    function open(src, alt) {
      img.src = src; img.alt = alt || '';
      lightbox.classList.add('open');
      document.body.style.overflow = 'hidden';
    }
    function close() { lightbox.classList.remove('open'); document.body.style.overflow = ''; }

    items.forEach(function (item) {
      item.addEventListener('click', function () {
        var full = item.getAttribute('data-full');
        var thumb = item.querySelector('img');
        open(full || (thumb && thumb.src), thumb && thumb.alt);
      });
    });
    closeBtn.addEventListener('click', close);
    lightbox.addEventListener('click', function (e) { if (e.target === lightbox) close(); });
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape') close(); });
  }

  /* ---------------- Follower counter ---------------- */
  function initFollowCounter() {
    var el = document.querySelector('.p-count[data-count]');
    if (!el) return;
    var animated = false;
    var observer = new IntersectionObserver(function (entries, obs) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting && !animated) {
          animated = true;
          var target = parseInt(el.getAttribute('data-count'), 10) || 0;
          var start = null, duration = 1600;
          function step(ts) {
            if (!start) start = ts;
            var progress = Math.min((ts - start) / duration, 1);
            var eased = 1 - Math.pow(1 - progress, 3);
            el.textContent = Math.floor(eased * target).toLocaleString();
            if (progress < 1) requestAnimationFrame(step);
            else el.textContent = target.toLocaleString();
          }
          requestAnimationFrame(step);
          obs.unobserve(el);
        }
      });
    }, { threshold: 0.6 });
    observer.observe(el);
  }

  /* ---------------- Reviews carousel with star fill ---------------- */
  function initReviews() {
    var track = document.getElementById('reviewTrack');
    var dotsWrap = document.getElementById('reviewDots');
    if (!track || !dotsWrap) return;

    var cards = track.querySelectorAll('.p-review-card');
    var index = 0;
    var timer;

    cards.forEach(function (card, i) {
      var dot = document.createElement('span');
      if (i === 0) dot.classList.add('active');
      dot.addEventListener('click', function () { goTo(i); });
      dotsWrap.appendChild(dot);

      var starsWrap = card.querySelector('.p-review-stars');
      if (starsWrap) {
        var fill = document.createElement('span');
        fill.className = 'p-review-stars-fill';
        fill.textContent = '★★★★★';
        var starCount = parseInt(starsWrap.getAttribute('data-stars'), 10) || 5;
        fill.style.width = (starCount / 5 * 100) + '%';
        starsWrap.appendChild(fill);
      }
    });
    var dots = dotsWrap.querySelectorAll('span');

    function goTo(i) {
      index = (i + cards.length) % cards.length;
      track.style.transition = 'transform .6s cubic-bezier(.19,1,.22,1)';
      track.style.transform = 'translateX(-' + (index * 100) + '%)';
      dots.forEach(function (d, di) { d.classList.toggle('active', di === index); });
      resetTimer();
    }
    function resetTimer() { clearInterval(timer); timer = setInterval(function () { goTo(index + 1); }, 6500); }
    goTo(0);
  }

  /* ---------------- FAQ accordion ---------------- */
  function initFaq() {
    var items = document.querySelectorAll('.p-faq-item');
    items.forEach(function (item) {
      var q = item.querySelector('.p-faq-q');
      if (!q) return;
      q.addEventListener('click', function () { item.classList.toggle('open'); });
    });
  }

  /* ---------------- Booking wizard ---------------- */
  function initWizard() {
    var form = document.getElementById('wizardForm');
    if (!form) return;
    var panes = form.querySelectorAll('.p-wpane');
    var steps = document.querySelectorAll('.p-wstep');
    var barFill = document.getElementById('wizardBarFill');
    var chips = document.querySelectorAll('#serviceChips .p-chip');
    var success = document.getElementById('wSuccess');
    var summary = document.getElementById('wSummary');
    var wDate = document.getElementById('wDate');

    if (wDate) wDate.setAttribute('min', new Date().toISOString().split('T')[0]);

    var state = { service: null, date: '', time: '', name: '', phone: '' };
    var current = 1;

    chips.forEach(function (chip) {
      chip.addEventListener('click', function () {
        chips.forEach(function (c) { c.classList.remove('selected'); });
        chip.classList.add('selected');
        state.service = chip.getAttribute('data-value');
      });
    });

    function showPane(n) {
      panes.forEach(function (p) { p.classList.toggle('active', parseInt(p.getAttribute('data-wpane'), 10) === n); });
      steps.forEach(function (s) {
        var sn = parseInt(s.getAttribute('data-wstep'), 10);
        s.classList.toggle('active', sn === n);
        s.classList.toggle('done', sn < n);
      });
      if (barFill) barFill.style.width = (n / 3 * 100) + '%';
      current = n;
    }

    function validateStep(n) {
      if (n === 1) return !!state.service;
      if (n === 2) {
        state.date = document.getElementById('wDate').value;
        state.time = document.getElementById('wTime').value;
        return !!state.date && !!state.time;
      }
      return true;
    }

    form.querySelectorAll('[data-wnext]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        if (!validateStep(current)) {
          btn.closest('.p-wpane').style.animation = 'none';
          void btn.offsetWidth;
          btn.closest('.p-wpane').style.animation = 'pShake .4s';
          return;
        }
        if (current === 2) {
          state.name = document.getElementById('wName').value;
          state.phone = document.getElementById('wPhone').value;
          if (summary) {
            summary.innerHTML = '<strong>' + escapeHtml(state.service) + '</strong> on <strong>' + escapeHtml(state.date) + '</strong> at <strong>' + escapeHtml(state.time) + '</strong>';
          }
        }
        showPane(current + 1);
      });
    });
    form.querySelectorAll('[data-wback]').forEach(function (btn) {
      btn.addEventListener('click', function () { showPane(current - 1); });
    });

    form.addEventListener('submit', function (e) {
      e.preventDefault();
      state.name = document.getElementById('wName').value;
      state.phone = document.getElementById('wPhone').value;
      if (!state.name || !state.phone) return;

      panes.forEach(function (p) { p.classList.remove('active'); });
      document.querySelector('.p-wizard-progress').style.display = 'none';
      if (success) {
        success.classList.add('show');
        var successText = document.getElementById('wSuccessText');
        if (successText) successText.textContent = state.service + ' confirmed for ' + state.date + ' at ' + state.time + '. Confirmation is on its way to ' + state.phone + '.';
      }
      fireConfetti();
    });

    var resetBtn = document.getElementById('wReset');
    if (resetBtn) {
      resetBtn.addEventListener('click', function () {
        form.reset();
        state = { service: null, date: '', time: '', name: '', phone: '' };
        chips.forEach(function (c) { c.classList.remove('selected'); });
        if (success) success.classList.remove('show');
        document.querySelector('.p-wizard-progress').style.display = '';
        showPane(1);
      });
    }

    // Prefill service from calculator "Book This Combo"
    var calcBtn = document.getElementById('calcBookBtn');
    if (calcBtn) {
      calcBtn.addEventListener('click', function (e) {
        var checked = document.querySelectorAll('.p-calc-item input:checked');
        if (checked.length) {
          var name = checked[0].getAttribute('data-name');
          chips.forEach(function (c) {
            c.classList.toggle('selected', c.getAttribute('data-value') === name);
          });
          state.service = name;
        }
      });
    }

    showPane(1);
  }

  function escapeHtml(str) {
    var div = document.createElement('div');
    div.textContent = str || '';
    return div.innerHTML;
  }

  /* shake keyframes injected once */
  var styleTag = document.createElement('style');
  styleTag.textContent = '@keyframes pShake { 0%,100%{transform:translateX(0);} 25%{transform:translateX(-6px);} 75%{transform:translateX(6px);} }';
  document.head.appendChild(styleTag);

  /* ---------------- Confetti ---------------- */
  function fireConfetti() {
    if (reduceMotion) return;
    var layer = document.getElementById('confettiLayer');
    if (!layer) return;
    var colors = ['#d9b96a', '#f5e2b8', '#b98f3e', '#ffffff'];
    for (var i = 0; i < 46; i++) {
      var piece = document.createElement('span');
      piece.className = 'p-confetti-piece';
      var size = 5 + Math.random() * 6;
      piece.style.width = size + 'px';
      piece.style.height = (size * 0.4) + 'px';
      piece.style.left = Math.random() * 100 + 'vw';
      piece.style.background = colors[Math.floor(Math.random() * colors.length)];
      piece.style.animationDuration = (2.2 + Math.random() * 1.6) + 's';
      piece.style.animationDelay = (Math.random() * 0.4) + 's';
      layer.appendChild(piece);
      (function (p) { setTimeout(function () { p.remove(); }, 4500); })(piece);
    }
  }

  /* ---------------- Newsletter ---------------- */
  function initNewsletter() {
    var form = document.getElementById('newsletterForm');
    var msg = document.getElementById('newsletterMsg');
    if (!form) return;
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      var input = form.querySelector('input[type="email"]');
      if (!input || !input.value) return;
      if (msg) msg.textContent = 'Welcome to the list — check your inbox!';
      form.reset();
      fireConfetti();
      setTimeout(function () { if (msg) msg.textContent = ''; }, 5000);
    });
  }

  /* ---------------- Speed dial FAB ---------------- */
  function initFab() {
    var wrap = document.getElementById('fabWrap');
    var main = document.getElementById('fabMain');
    if (!wrap || !main) return;
    main.addEventListener('click', function () {
      var open = wrap.classList.toggle('open');
      main.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
    wrap.querySelectorAll('.p-fab-item').forEach(function (item) {
      item.addEventListener('click', function () {
        wrap.classList.remove('open');
        main.setAttribute('aria-expanded', 'false');
      });
    });
  }

  /* ---------------- Cookie consent ---------------- */
  function initCookieBar() {
    var bar = document.getElementById('cookieBar');
    if (!bar) return;
    var accepted = null;
    try { accepted = localStorage.getItem('clipperS1CookieChoice'); } catch (e) {}
    if (accepted) return;

    setTimeout(function () { bar.classList.add('show'); }, 1400);

    var acceptBtn = document.getElementById('cookieAccept');
    var declineBtn = document.getElementById('cookieDecline');
    function dismiss(choice) {
      bar.classList.remove('show');
      try { localStorage.setItem('clipperS1CookieChoice', choice); } catch (e) {}
    }
    if (acceptBtn) acceptBtn.addEventListener('click', function () { dismiss('accepted'); });
    if (declineBtn) declineBtn.addEventListener('click', function () { dismiss('declined'); });
  }

  /* ---------------- Footer year ---------------- */
  function setYear() {
    var y = document.getElementById('pYear');
    if (y) y.textContent = new Date().getFullYear();
  }

})();
