import Link from "next/link";
import { PROVENANCE } from "@/lib/engine/provenance";
import { SEVERITY_STYLE } from "@/lib/present";
import type { Severity } from "@/lib/engine/types";

/**
 * Header for the interior routes.
 *
 * The landing page carries its own nav inside the hero, over the illustration.
 * This is the plain version for pages that have no hero — currently the brief.
 */
export function SiteHeader() {
  return (
    <header className="border-b border-border bg-surface">
      <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
        <Link href="/" className="wordmark text-[19px] text-foreground">
          Blast Radius
        </Link>
        <span className="notation text-[11px] uppercase tracking-[0.14em] text-faint">
          MCP attack surface analysis
        </span>
      </div>
    </header>
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
 * The product's entire claim is that nothing here is invented, so a reader who
 * wants to check a severity band should be able to find the table it came from
 * without leaving the page.
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
    <footer id="provenance" className="border-t border-border bg-surface">
      <div className="mx-auto max-w-6xl px-6 py-14">
        <p className="notation mb-6 text-[11px] uppercase tracking-[0.16em] text-accent">
          Every claim on this page traces to one of these
        </p>
        <div className="grid gap-x-8 gap-y-5 sm:grid-cols-2 lg:grid-cols-4">
          {rows.map((r) => (
            <div key={r.name} className="border-t border-border-strong pt-3">
              <a
                href={r.href}
                target="_blank"
                rel="noreferrer"
                className="text-[14px] font-medium text-foreground underline decoration-border-strong underline-offset-4 transition-colors hover:decoration-accent"
              >
                {r.name}
              </a>
              <p className="notation mt-1 text-[11px] text-faint">{r.detail}</p>
            </div>
          ))}
        </div>

        <div className="mt-10 flex flex-col gap-4 border-t border-border pt-6 sm:flex-row sm:items-start sm:justify-between">
          <p className="max-w-3xl text-[12.5px] leading-relaxed text-muted">
            Datasets are pulled at build time and committed, so the scanner makes no outbound
            request while it runs. Severity is computed by rules in{" "}
            <span className="notation">src/lib/engine</span>, not by a model. Blast Radius is a
            demonstration prototype, not a security product, and the sample configuration it ships
            with is synthetic.
          </p>
          <a
            href="https://github.com/Rappid-exe/cursorHack"
            target="_blank"
            rel="noreferrer"
            className="notation shrink-0 text-[12px] text-faint underline decoration-border-strong underline-offset-4 transition-colors hover:text-foreground"
          >
            github.com/Rappid-exe/cursorHack
          </a>
        </div>
      </div>
    </footer>
  );
}
