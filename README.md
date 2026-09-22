# Clipper S1 Hair Saloon

A professional, mobile-first, animated website for Clipper S1 Hair Saloon — a men's grooming/barbershop brand.

## Structure

```
index.html      Single-page site (hero, about, services, gallery, pricing, team, testimonials, booking, contact, footer)
css/style.css   Mobile-first responsive styles, animations & transitions
js/main.js      Navigation, scroll reveal, counters, gallery lightbox, testimonial slider, booking form
```

## Running locally

No build step required — pure HTML/CSS/JS.

```bash
python3 -m http.server 8080
# then open http://localhost:8080
```

## Notes

- Images sourced from Unsplash (hotlinked) and pravatar.cc (testimonial avatars) as placeholders — swap for real photography before launch.
- Booking and newsletter forms are front-end only (no backend); wire them to a real API or service before production use.
- Icons via Font Awesome (CDN), fonts via Google Fonts (Playfair Display + Poppins).
