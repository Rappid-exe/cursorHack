import { existsSync } from "node:fs";
import { join } from "node:path";
import Link from "next/link";

/**
 * The hero.
 *
 * One deep blue field, one illustration, one sentence, one button. The
 * illustration is entirely inline SVG — gradients, layered silhouettes and an
 * SVG-turbulence grain — so there is no image to load, nothing to go missing
 * offline, and it stays sharp on whatever projector it lands on.
 *
 * The concentric arcs are the product's name drawn literally: a blast radius
 * sweeping out from a single point on the horizon. They sit *behind* the ridge
 * lines, so the landscape occludes them and they read as light rather than as
 * a diagram pasted over a picture.
 */

/**
 * The viewBox is 1440×760 rather than a rounder 1440×900 because the hero is
 * roughly 1.9:1 on a laptop. `slice` scales to cover and crops the overflow, so
 * a viewBox far from the rendered aspect throws away most of the composition —
 * at 1.6:1 the entire upper sky was being cropped away on a wide screen.
 */
const VB_H = 760;

/**
 * Where the ground meets the sky.
 *
 * Deliberately low: the composition wants a tall sky with an incandescent band
 * just above the ridge line, and the ground as a thin anchoring strip rather
 * than half the picture.
 */
const HORIZON = 672;

/**
 * Ridge silhouettes, back to front.
 *
 * Smooth cubics rather than polylines: straight segments between peaks read as
 * a line chart, which is exactly the wrong association for a page about attack
 * surface. Real ranges curve.
 *
 * Every crest sits *below* the brightest sky stop at 66%, so the ranges are
 * silhouetted against the glow instead of covering it. That relationship is
 * the whole illustration — get it wrong and this is a blue rectangle.
 */
const RIDGES = [
  {
    // Far range — lowest contrast, sitting in the brightest part of the band.
    d: `M0,548 C 150,512 268,542 396,504 S 616,458 744,498 S 968,454 1098,492 S 1320,452 1440,488 L1440,${HORIZON} L0,${HORIZON} Z`,
    fill: "url(#ridgeFar)",
    opacity: 0.68,
  },
  {
    d: `M0,596 C 168,564 296,592 432,552 S 654,514 790,552 S 1024,510 1164,548 S 1360,522 1440,542 L1440,${HORIZON} L0,${HORIZON} Z`,
    fill: "url(#ridgeMid)",
    opacity: 0.92,
  },
  {
    // Near ridge — carries the rim light on its lit crest.
    d: `M0,634 C 186,604 306,628 464,592 S 700,556 852,590 S 1092,552 1244,586 S 1396,574 1440,580 L1440,${HORIZON} L0,${HORIZON} Z`,
    fill: "url(#ridgeNear)",
    opacity: 1,
  },
];

/** The near ridge's crest alone, for the rim light to trace. */
const NEAR_CREST =
  "M0,634 C 186,604 306,628 464,592 S 700,556 852,590 S 1092,552 1244,586 S 1396,574 1440,580";

export function HeroArt() {
  return (
    <svg
      className="absolute inset-0 h-full w-full"
      viewBox={`0 0 1440 ${VB_H}`}
      preserveAspectRatio="xMidYMax slice"
      aria-hidden="true"
    >
      <defs>
        {/*
          Sky: deep at the zenith, collapsing into an incandescent band that
          peaks just above the ridge line. Every warm stop sits above HORIZON —
          putting them below it hides the band under the ground plane, which is
          the difference between a landscape and a blue rectangle.
        */}
        <linearGradient id="sky" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#04113f" />
          <stop offset="20%" stopColor="#0a2280" />
          <stop offset="40%" stopColor="#10309e" />
          <stop offset="52%" stopColor="#2148c0" />
          <stop offset="58%" stopColor="#5b83df" />
          <stop offset="62%" stopColor="#a8c0ea" />
          <stop offset="66%" stopColor="#f0e0bc" />
          <stop offset="70%" stopColor="#f2a355" />
          <stop offset="74%" stopColor="#cf5928" />
          <stop offset="80%" stopColor="#5e2014" />
          <stop offset="90%" stopColor="#160809" />
          <stop offset="100%" stopColor="#0a0406" />
        </linearGradient>

        {/* Ridges. Cool and dark, lifting slightly toward the light source. */}
        <linearGradient id="ridgeFar" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%" stopColor="#20418f" />
          <stop offset="55%" stopColor="#2a4c99" />
          <stop offset="100%" stopColor="#1a3479" />
        </linearGradient>
        <linearGradient id="ridgeMid" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%" stopColor="#0e2258" />
          <stop offset="58%" stopColor="#132c68" />
          <stop offset="100%" stopColor="#0b1b46" />
        </linearGradient>
        <linearGradient id="ridgeNear" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#0a1430" />
          <stop offset="60%" stopColor="#060c1c" />
          <stop offset="100%" stopColor="#04070f" />
        </linearGradient>

        <linearGradient id="ground" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#080f22" />
          <stop offset="100%" stopColor="#03060d" />
        </linearGradient>

        {/* The glow the rings emanate from, sitting on the horizon. */}
        <radialGradient id="source" cx="0.66" cy="0.855" r="0.4">
          <stop offset="0%" stopColor="#fff2d8" stopOpacity="0.9" />
          <stop offset="24%" stopColor="#f9a24e" stopOpacity="0.4" />
          <stop offset="58%" stopColor="#e8452a" stopOpacity="0.11" />
          <stop offset="100%" stopColor="#e8452a" stopOpacity="0" />
        </radialGradient>

        {/* Rim light picking out the near ridge's lit crest. */}
        <linearGradient id="rim" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%" stopColor="#ff8a4c" stopOpacity="0.05" />
          <stop offset="34%" stopColor="#ffb066" stopOpacity="0.28" />
          <stop offset="63%" stopColor="#ffe6bc" stopOpacity="0.85" />
          <stop offset="84%" stopColor="#ffb066" stopOpacity="0.3" />
          <stop offset="100%" stopColor="#e8452a" stopOpacity="0.05" />
        </linearGradient>

        {/* Keeps the rings in the sky — they must not paint over the ground. */}
        <clipPath id="skyOnly">
          <rect x="0" y="0" width="1440" height={HORIZON} />
        </clipPath>

        {/*
          Roughened edges.
          A cubic bezier is perfectly smooth, and perfectly smooth is what makes
          vector landscape art look like clip art. Displacing the ridge outlines
          by a low-frequency noise field breaks the mathematical regularity so
          the crests read as terrain rather than as curves.
        */}
        <filter id="rough" x="-5%" y="-15%" width="110%" height="140%">
          <feTurbulence
            type="fractalNoise"
            baseFrequency="0.006 0.022"
            numOctaves="4"
            seed="11"
            result="warp"
          />
          <feDisplacementMap
            in="SourceGraphic"
            in2="warp"
            scale="26"
            xChannelSelector="R"
            yChannelSelector="G"
          />
        </filter>

        <filter id="roughSoft" x="-5%" y="-15%" width="110%" height="140%">
          <feTurbulence
            type="fractalNoise"
            baseFrequency="0.005 0.017"
            numOctaves="3"
            seed="4"
            result="warp"
          />
          <feDisplacementMap
            in="SourceGraphic"
            in2="warp"
            scale="34"
            xChannelSelector="R"
            yChannelSelector="G"
          />
          {/* Distance haze on the far range. */}
          <feGaussianBlur stdDeviation="1.4" />
        </filter>

        {/*
          Print grain.
          Rendered inside the SVG rather than only as a CSS overlay so it sits
          in the same colour space as the artwork and survives scaling. This is
          the single biggest reason the reference illustrations read as printed
          — a flat saturated field with no grain reads as a gradient tool.
        */}
        <filter id="filmGrain" x="0" y="0" width="100%" height="100%">
          <feTurbulence type="fractalNoise" baseFrequency="0.68" numOctaves="4" seed="19" />
          <feColorMatrix type="saturate" values="0" />
          <feComponentTransfer>
            <feFuncA type="linear" slope="0.9" intercept="-0.28" />
          </feComponentTransfer>
        </filter>

        {/* Coarser, directional speckle for the foreground. */}
        <filter id="coarseGrain" x="0" y="0" width="100%" height="100%">
          <feTurbulence type="fractalNoise" baseFrequency="0.28 0.42" numOctaves="3" seed="5" />
          <feColorMatrix type="saturate" values="0" />
          <feComponentTransfer>
            <feFuncA type="linear" slope="0.7" intercept="-0.3" />
          </feComponentTransfer>
        </filter>
      </defs>

      <rect width="1440" height={VB_H} fill="url(#sky)" />

      {/* Blast radius. Behind the ridges, clipped to the sky. */}
      <g clipPath="url(#skyOnly)">
        {[130, 246, 372, 508, 654, 810, 976].map((r, i) => (
          <circle
            key={r}
            className="ring"
            style={{
              // Outer rings are fainter and breathe later, so the sweep reads
              // as travelling outward rather than throbbing as one object.
              ["--ring-min" as string]: `${0.18 - i * 0.019}`,
              ["--ring-max" as string]: `${0.4 - i * 0.042}`,
              animationDelay: `${i * 0.5}s`,
            }}
            cx="950"
            cy={HORIZON}
            r={r}
            fill="none"
            stroke="#ffe3b8"
            strokeWidth={1.5}
          />
        ))}
      </g>

      {/* A high, thin cloud bank catching the last light. */}
      <g className="drift" opacity="0.5">
        <ellipse cx="1010" cy="286" rx="440" ry="12" fill="#e8a06a" opacity="0.18" />
        <ellipse cx="860" cy="262" rx="300" ry="7" fill="#ffcf9a" opacity="0.15" />
        <ellipse cx="380" cy="336" rx="260" ry="7" fill="#e8a06a" opacity="0.12" />
      </g>

      {/* The light source itself, over the rings so it anchors them. */}
      <rect width="1440" height={VB_H} fill="url(#source)" />

      {/* Sky grain, over the gradient but under the terrain. */}
      <rect
        width="1440"
        height={VB_H}
        filter="url(#filmGrain)"
        opacity="0.5"
        style={{ mixBlendMode: "overlay" }}
      />

      {RIDGES.map((ridge, i) => (
        <path
          key={i}
          d={ridge.d}
          fill={ridge.fill}
          opacity={ridge.opacity}
          // The far range gets the softer, hazier displacement; the nearer two
          // get the tighter one, so the roughness has depth rather than being
          // one uniform wobble applied to everything.
          filter={i === 0 ? "url(#roughSoft)" : "url(#rough)"}
        />
      ))}

      {/* Rim light traced along the near ridge's crest, roughened to match. */}
      <path
        d={NEAR_CREST}
        fill="none"
        stroke="url(#rim)"
        strokeWidth="2.4"
        filter="url(#rough)"
      />

      <rect x="0" y={HORIZON - 1} width="1440" height={VB_H - HORIZON + 1} fill="url(#ground)" />

      {/* Foreground speckle. Coarser than the sky grain because it is nearer. */}
      <rect
        x="0"
        y={HORIZON - 120}
        width="1440"
        height={VB_H - HORIZON + 120}
        filter="url(#coarseGrain)"
        opacity="0.5"
        style={{ mixBlendMode: "overlay" }}
      />

      {/* A second, finer pass over the whole frame ties sky and ground into one
          surface — without it the terrain reads as pasted onto the sky. */}
      <rect
        width="1440"
        height={VB_H}
        filter="url(#filmGrain)"
        opacity="0.32"
        style={{ mixBlendMode: "soft-light" }}
      />
    </svg>
  );
}

/**
 * Uses a real illustration if one has been dropped into `public/`, otherwise
 * falls back to the drawn one.
 *
 * A generated SVG landscape has a ceiling — displacement and grain get it a
 * long way from clip art, but it will not match a piece of art somebody painted.
 * So this looks for `public/hero.{jpg,png,webp,avif}` at render time and prefers
 * it when present. Drop a file in, reload, done — no code change.
 *
 * Deliberately not committed: whatever lands there is likely someone else's
 * artwork, and a public repo is the wrong place for it. `public/hero.*` is
 * gitignored for that reason.
 */
function findHeroImage(): string | null {
  // Checked per render rather than once at module scope: at module scope the
  // answer is cached for the life of the dev server, so dropping a file in and
  // reloading would appear to do nothing. Five existsSync calls per request is
  // not worth optimising against that confusion.
  for (const name of ["hero.jpg", "hero.jpeg", "hero.png", "hero.webp", "hero.avif"]) {
    if (existsSync(join(process.cwd(), "public", name))) return `/${name}`;
  }
  return null;
}

export function Hero() {
  const heroImage = findHeroImage();

  return (
    <section className="grain relative isolate flex min-h-[94vh] flex-col overflow-hidden bg-hero-deep">
      {heroImage ? (
        <div
          aria-hidden="true"
          className="absolute inset-0 bg-cover bg-center bg-no-repeat"
          style={{ backgroundImage: `url(${heroImage})` }}
        />
      ) : (
        <HeroArt />
      )}

      {/*
        Scrim.
        Type has to survive sitting over the brightest part of the sky. Dimming
        the whole illustration to achieve that would throw away the dusk band,
        so this darkens only the upper 62% — above where the band begins — and
        fades out before reaching it.
      */}
      <div
        aria-hidden="true"
        className="absolute inset-x-0 top-0 h-[70%] bg-gradient-to-b from-hero-deep/88 via-hero-deep/55 to-transparent"
      />

      <div className="relative z-10 flex flex-1 flex-col">
        <HeroNav />

        <div className="mx-auto w-full max-w-6xl px-6 pt-10 pb-24 sm:pt-14">
          <h1 className="max-w-3xl text-[36px] leading-[1.08] font-semibold tracking-[-0.025em] text-on-hero sm:text-[56px]">
            A server that reads files is not a vulnerability.
          </h1>
          <p className="mt-5 max-w-2xl text-[17px] leading-relaxed text-on-hero-muted sm:text-[19px]">
            Neither is one that makes HTTP requests. Installed together, they are an
            exfiltration primitive — and your agent sees one flat list of tools, not two
            servers with two trust boundaries.
          </p>

          <div className="mt-8 flex flex-wrap items-center gap-5">
            <a
              href="#scan"
              className="group inline-flex items-center gap-2.5 rounded bg-accent px-5 py-3 text-[14px] font-medium text-white transition-colors hover:bg-accent-hover"
            >
              Scan a configuration
              <span
                aria-hidden="true"
                className="transition-transform group-hover:translate-x-0.5"
              >
                →
              </span>
            </a>
            <a
              href="#census"
              className="text-[14px] font-medium text-on-hero underline decoration-white/40 underline-offset-4 transition-colors hover:decoration-white"
            >
              19,513 servers, measured
            </a>
          </div>
        </div>
      </div>
    </section>
  );
}

function HeroNav() {
  const links = [
    { label: "How it works", href: "#how" },
    { label: "Attack paths", href: "#scan" },
    { label: "Census", href: "#census" },
    { label: "Provenance", href: "#provenance" },
  ];

  return (
    <nav className="mx-auto flex w-full max-w-6xl items-center justify-between px-6 py-5">
      <Link href="/" className="wordmark text-[22px] text-on-hero">
        Blast Radius
      </Link>

      <div className="hidden items-center gap-7 md:flex">
        {links.map((l) => (
          <a
            key={l.href}
            href={l.href}
            className="text-[14px] text-on-hero-muted transition-colors hover:text-on-hero"
          >
            {l.label}
          </a>
        ))}
      </div>

      <a
        href="https://github.com/Rappid-exe/cursorHack"
        target="_blank"
        rel="noreferrer"
        className="text-[14px] text-on-hero-muted transition-colors hover:text-on-hero"
      >
        Source
      </a>
    </nav>
  );
}
