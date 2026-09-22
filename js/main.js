/* Clipper S1 Hair Saloon — main.js */
(function () {
  'use strict';

  document.addEventListener('DOMContentLoaded', init);

  function init() {
    initPreloader();
    initNavbar();
    initMobileMenu();
    initScrollSpy();
    initRevealAnimations();
    initCounters();
    initGalleryLightbox();
    initTestimonialSlider();
    initBookingForm();
    initNewsletterForm();
    initBackToTop();
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
      setTimeout(function () { pre.classList.add('hide'); }, 350);
    }
    window.addEventListener('load', reveal);
    // Safety net: never let a slow/blocked resource strand users behind the preloader.
    setTimeout(reveal, 2600);
  }

  /* ---------------- Navbar shrink on scroll ---------------- */
  function initNavbar() {
    var navbar = document.getElementById('navbar');
    if (!navbar) return;
    function onScroll() {
      if (window.scrollY > 40) navbar.classList.add('scrolled');
      else navbar.classList.remove('scrolled');
    }
    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
  }

  /* ---------------- Mobile menu ---------------- */
  function initMobileMenu() {
    var hamburger = document.getElementById('hamburger');
    var navLinks = document.getElementById('navLinks');
    var overlay = document.getElementById('navOverlay');
    if (!hamburger || !navLinks || !overlay) return;

    function closeMenu() {
      hamburger.setAttribute('aria-expanded', 'false');
      navLinks.classList.remove('open');
      overlay.classList.remove('open');
      document.body.style.overflow = '';
    }
    function openMenu() {
      hamburger.setAttribute('aria-expanded', 'true');
      navLinks.classList.add('open');
      overlay.classList.add('open');
      document.body.style.overflow = 'hidden';
    }

    hamburger.addEventListener('click', function () {
      var expanded = hamburger.getAttribute('aria-expanded') === 'true';
      if (expanded) closeMenu(); else openMenu();
    });
    overlay.addEventListener('click', closeMenu);
    navLinks.querySelectorAll('a').forEach(function (link) {
      link.addEventListener('click', closeMenu);
    });
    window.addEventListener('resize', function () {
      if (window.innerWidth >= 992) closeMenu();
    });
  }

  /* ---------------- Scrollspy: highlight active nav link ---------------- */
  function initScrollSpy() {
    var sections = document.querySelectorAll('section[id]');
    var navLinks = document.querySelectorAll('.nav-link[data-nav]');
    if (!sections.length || !navLinks.length) return;

    var map = {};
    navLinks.forEach(function (l) { map[l.getAttribute('href').slice(1)] = l; });

    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          navLinks.forEach(function (l) { l.classList.remove('active'); });
          var link = map[entry.target.id];
          if (link) link.classList.add('active');
        }
      });
    }, { rootMargin: '-45% 0px -50% 0px', threshold: 0 });

    sections.forEach(function (s) { observer.observe(s); });
  }

  /* ---------------- Scroll reveal ---------------- */
  function initRevealAnimations() {
    var items = document.querySelectorAll('.reveal-up, .reveal-fade, .reveal-left, .reveal-right');
    if (!items.length) return;

    items.forEach(function (el) {
      var delay = el.getAttribute('data-delay');
      if (delay !== null) el.style.setProperty('--d', delay);
    });

    var observer = new IntersectionObserver(function (entries, obs) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add('visible');
          obs.unobserve(entry.target);
        }
      });
    }, { threshold: 0.15, rootMargin: '0px 0px -60px 0px' });

    items.forEach(function (el) { observer.observe(el); });
  }

  /* ---------------- Animated counters ---------------- */
  function initCounters() {
    var counters = document.querySelectorAll('.num[data-count]');
    if (!counters.length) return;

    var animated = new WeakSet();

    function animate(el) {
      var target = parseInt(el.getAttribute('data-count'), 10) || 0;
      var duration = 1600;
      var start = null;

      function step(ts) {
        if (!start) start = ts;
        var progress = Math.min((ts - start) / duration, 1);
        var eased = 1 - Math.pow(1 - progress, 3);
        el.textContent = Math.floor(eased * target).toLocaleString();
        if (progress < 1) requestAnimationFrame(step);
        else el.textContent = target.toLocaleString();
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
    }, { threshold: 0.6 });

    counters.forEach(function (c) { observer.observe(c); });
  }

  /* ---------------- Gallery lightbox ---------------- */
  function initGalleryLightbox() {
    var items = document.querySelectorAll('.gallery-item');
    var lightbox = document.getElementById('lightbox');
    var lightboxImg = document.getElementById('lightboxImg');
    var closeBtn = document.getElementById('lightboxClose');
    if (!items.length || !lightbox || !lightboxImg || !closeBtn) return;

    function open(src, alt) {
      lightboxImg.src = src;
      lightboxImg.alt = alt || '';
      lightbox.classList.add('open');
      document.body.style.overflow = 'hidden';
    }
    function close() {
      lightbox.classList.remove('open');
      document.body.style.overflow = '';
    }

    items.forEach(function (item) {
      item.addEventListener('click', function () {
        var full = item.getAttribute('data-full');
        var img = item.querySelector('img');
        open(full || (img && img.src), img && img.alt);
      });
    });

    closeBtn.addEventListener('click', close);
    lightbox.addEventListener('click', function (e) {
      if (e.target === lightbox) close();
    });
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') close();
    });
  }

  /* ---------------- Testimonial slider ---------------- */
  function initTestimonialSlider() {
    var track = document.getElementById('testiTrack');
    var dotsWrap = document.getElementById('testiDots');
    var prevBtn = document.getElementById('testiPrev');
    var nextBtn = document.getElementById('testiNext');
    if (!track || !dotsWrap || !prevBtn || !nextBtn) return;

    var slides = track.children.length;
    var index = 0;
    var autoplayTimer;

    for (var i = 0; i < slides; i++) {
      var dot = document.createElement('span');
      if (i === 0) dot.classList.add('active');
      dot.addEventListener('click', function (idx) {
        return function () { goTo(idx); };
      }(i));
      dotsWrap.appendChild(dot);
    }
    var dots = dotsWrap.querySelectorAll('span');

    function goTo(i) {
      index = (i + slides) % slides;
      track.style.transform = 'translateX(-' + (index * 100) + '%)';
      dots.forEach(function (d, di) { d.classList.toggle('active', di === index); });
      resetAutoplay();
    }

    function next() { goTo(index + 1); }
    function prev() { goTo(index - 1); }

    nextBtn.addEventListener('click', next);
    prevBtn.addEventListener('click', prev);

    function resetAutoplay() {
      clearInterval(autoplayTimer);
      autoplayTimer = setInterval(next, 6000);
    }
    resetAutoplay();

    /* Touch swipe */
    var startX = 0, isDragging = false;
    track.addEventListener('touchstart', function (e) {
      startX = e.touches[0].clientX;
      isDragging = true;
      clearInterval(autoplayTimer);
    }, { passive: true });

    track.addEventListener('touchmove', function (e) {
      if (!isDragging) return;
    }, { passive: true });

    track.addEventListener('touchend', function (e) {
      if (!isDragging) return;
      isDragging = false;
      var endX = e.changedTouches[0].clientX;
      var diff = startX - endX;
      if (Math.abs(diff) > 40) {
        if (diff > 0) next(); else prev();
      } else {
        resetAutoplay();
      }
    });
  }

  /* ---------------- Booking form ---------------- */
  function initBookingForm() {
    var form = document.getElementById('bookingForm');
    var fields = document.getElementById('formFields');
    var success = document.getElementById('formSuccess');
    var dateInput = document.getElementById('fdate');
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
      success.classList.add('show');
      setTimeout(function () {
        success.classList.remove('show');
        fields.style.display = '';
        form.reset();
      }, 4200);
    });
  }

  /* ---------------- Newsletter form ---------------- */
  function initNewsletterForm() {
    var form = document.getElementById('newsletterForm');
    var msg = document.getElementById('newsletterMsg');
    if (!form || !msg) return;

    form.addEventListener('submit', function (e) {
      e.preventDefault();
      var input = form.querySelector('input[type="email"]');
      if (!input || !input.value) return;
      msg.textContent = 'Thanks for subscribing! Check your inbox soon.';
      form.reset();
      setTimeout(function () { msg.textContent = ''; }, 5000);
    });
  }

  /* ---------------- Back to top ---------------- */
  function initBackToTop() {
    var btn = document.getElementById('backToTop');
    if (!btn) return;
    window.addEventListener('scroll', function () {
      if (window.scrollY > 500) btn.classList.add('show');
      else btn.classList.remove('show');
    }, { passive: true });

    btn.addEventListener('click', function () {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    });
  }

  /* ---------------- Footer year ---------------- */
  function setYear() {
    var y = document.getElementById('year');
    if (y) y.textContent = new Date().getFullYear();
  }

})();
