import Link from "next/link";
import { PROVENANCE } from "@/lib/engine/provenance";
import { SEVERITY_STYLE } from "@/lib/present";
import type { Severity } from "@/lib/engine/types";

export function SiteHeader() {
  return (
    <header className="border-b border-border">
      <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
        <Link href="/" className="flex items-center gap-2.5">
          <RadiusMark />
          <span className="text-[15px] font-semibold tracking-tight">Blast Radius</span>
        </Link>
        <span className="notation text-[11px] uppercase tracking-[0.14em] text-faint">
          MCP attack surface analysis
        </span>
      </div>
    </header>
  );
}

/** Concentric arcs from a single point — the product's one piece of iconography. */
function RadiusMark({ className = "" }: { className?: string }) {
  return (
    <svg viewBox="0 0 20 20" className={`h-5 w-5 ${className}`} aria-hidden="true">
      <circle cx="5" cy="15" r="2" fill="var(--accent)" />
      {[5.5, 10, 14.5].map((r, i) => (
        <path
          key={r}
          d={`M ${5 + r} 15 A ${r} ${r} 0 0 0 5 ${15 - r}`}
          fill="none"
          stroke="var(--accent)"
          strokeWidth="1.1"
          opacity={0.75 - i * 0.2}
        />
      ))}
    </svg>
  );
}

export function SeverityChip({ severity }: { severity: Severity }) {
  return (
    <span
      className={`notation inline-flex shrink-0 items-center rounded border px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-[0.1em] ${SEVERITY_STYLE[severity].chip}`}
    >
      {severity}
    </span>
  );
}

export function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <h2 className="notation mb-3 text-[11px] font-medium uppercase tracking-[0.14em] text-faint">
      {children}
    </h2>
  );
}

/**
 * Where every number on the page came from.
 *
 * Present on both the dashboard and the brief because the product's entire
 * claim is that nothing here is invented — a reader who wants to check a
 * severity band should be able to find the table it came from.
 */
export function ProvenanceFooter() {
  const { registry, threat, supply } = PROVENANCE;
  const kevSource = threat.sources.find((s) => s.catalogVersion);

  const rows = [
    {
      name: "CISA Known Exploited Vulnerabilities",
      detail: kevSource?.catalogVersion
        ? `catalogue ${kevSource.catalogVersion} · ${threat.counts.kevEntries.toLocaleString()} CVEs`
        : `${threat.counts.kevEntries.toLocaleString()} CVEs`,
      href: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    },
    {
      name: "MITRE ATT&CK for Enterprise",
      detail: `${threat.counts.attackTechniques} techniques cited`,
      href: "https://attack.mitre.org",
    },
    {
      name: "OSV.dev",
      detail: `${supply.counts.advisories.toLocaleString()} advisories over ${supply.counts.packages.toLocaleString()} packages`,
      href: "https://osv.dev",
    },
    {
      name: "Official MCP registry",
      detail: `${registry.counts.servers.toLocaleString()} published servers`,
      href: "https://registry.modelcontextprotocol.io",
    },
  ];

  return (
    <footer className="mt-16 border-t border-border">
      <div className="mx-auto max-w-6xl px-6 py-8">
        <p className="notation mb-4 text-[11px] uppercase tracking-[0.14em] text-faint">
          Every claim on this page traces to one of these
        </p>
        <div className="grid gap-x-8 gap-y-3 sm:grid-cols-2 lg:grid-cols-4">
          {rows.map((r) => (
            <div key={r.name}>
              <a
                href={r.href}
                target="_blank"
                rel="noreferrer"
                className="text-[13px] text-foreground underline decoration-border underline-offset-4 transition-colors hover:decoration-accent"
              >
                {r.name}
              </a>
              <p className="notation mt-0.5 text-[11px] text-faint">{r.detail}</p>
            </div>
          ))}
        </div>
        <p className="mt-6 max-w-3xl text-[12px] leading-relaxed text-faint">
          Datasets are pulled at build time and committed, so the scanner makes no outbound
          request while it runs. Severity is computed by rules in{" "}
          <span className="notation">src/lib/engine</span>, not by a model. Blast Radius is a
          demonstration prototype, not a security product, and the sample configuration it ships
          with is synthetic.
        </p>
      </div>
    </footer>
  );
}
