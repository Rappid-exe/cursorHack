import { Hero } from "@/components/Hero";
import { ProvenanceFooter } from "@/components/Chrome";
import { ScanFlow } from "@/components/ScanFlow";
import { PROVENANCE } from "@/lib/engine/provenance";
import corpus from "@/data/corpus/summary.json";

interface Corpus {
  census: {
    servers: number;
    delivery: { local: number; remote: number; both: number };
    withoutRepository: number;
    percentWithoutRepository: number;
    medianDaysSincePublish: number;
    publishedLast30Days: number;
    serversWithAdvisories: number;
    serversWithKevCve: number;
    soloMaintainerPackages: number;
    maintainerDataAvailable: number;
    percentSoloMaintainer: number;
  };
  sample: {
    size: number;
    completePathAlone: number;
    percentCompletePathAlone: number;
    withAnyIngress: number;
    medianCapabilities: number;
  } | null;
}

export default function Home() {
  const { registry, threat } = PROVENANCE;
  const { census, sample } = corpus as Corpus;

  return (
    <>
      <Hero />

      {/* --- The claim ------------------------------------------------------ */}
      <section id="how" className="border-b border-border bg-surface">
        <div className="mx-auto max-w-6xl px-6 py-16 sm:py-20">
          <p className="notation text-[11px] uppercase tracking-[0.16em] text-accent">
            The architecture
          </p>
          <h2 className="mt-3 max-w-3xl text-[26px] leading-[1.2] font-semibold tracking-[-0.015em] sm:text-[34px]">
            The model reads English. It never decides what is dangerous.
          </h2>
          <p className="mt-4 max-w-2xl text-[15px] leading-relaxed text-muted">
            Ask any AI-security demo how you know the model did not invent a finding, and the
            answer is usually a shrug. Here it cannot — it is never asked to produce one.
          </p>

          <div className="mt-10 grid gap-8 md:grid-cols-3">
            {[
              {
                n: "01",
                t: "Classify",
                d: "Reads each tool description and assigns capabilities from a closed list of fourteen. Genuinely a language problem: there is no schema, and every server author words it differently.",
                who: "model",
              },
              {
                n: "02",
                t: "Locate",
                d: "Finds spans of description that instruct the model rather than describe the tool, and returns them verbatim. A quote that cannot be found in the source is discarded before you see it.",
                who: "model",
              },
              {
                n: "03",
                t: "Compose",
                d: "Joins capabilities into attack paths from a hand-written rule table, scored against CISA KEV, MITRE ATT&CK and OSV. Every severity is a pure function over committed data.",
                who: "engine",
              },
            ].map((s) => (
              <div key={s.n} className="border-t-2 border-foreground pt-4">
                <div className="flex items-baseline justify-between">
                  <span className="notation text-[11px] tracking-[0.1em] text-faint">{s.n}</span>
                  <span
                    className={`notation rounded-full border px-2 py-0.5 text-[10px] uppercase tracking-[0.08em] ${
                      s.who === "model"
                        ? "border-accent-border bg-accent-soft text-accent"
                        : "border-border-strong bg-surface-sunk text-muted"
                    }`}
                  >
                    {s.who}
                  </span>
                </div>
                <h3 className="mt-3 text-[19px] font-semibold tracking-tight">{s.t}</h3>
                <p className="mt-2 text-[14px] leading-relaxed text-muted">{s.d}</p>
              </div>
            ))}
          </div>

          <p className="mt-10 max-w-2xl border-l-2 border-accent pl-4 text-[15px] leading-relaxed">
            If the classifier returned nonsense you would get{" "}
            <strong>fewer findings, never invented ones</strong>. That is the property worth
            having, and it is enforced rather than promised.
          </p>
        </div>
      </section>

      {/* --- Scanner -------------------------------------------------------- */}
      <section id="scan" className="bg-background">
        <div className="mx-auto max-w-6xl px-6 py-16 sm:py-20">
          <ScanFlow />
        </div>
      </section>

      {/* --- Census --------------------------------------------------------- */}
      <section id="census" className="grain relative isolate overflow-hidden bg-hero">
        <div className="relative z-10 mx-auto max-w-6xl px-6 py-16 sm:py-20">
          <p className="notation text-[11px] uppercase tracking-[0.16em] text-on-hero-muted">
            Measured, not asserted
          </p>
          <h2 className="mt-3 max-w-3xl text-[26px] leading-[1.2] font-semibold tracking-[-0.015em] text-on-hero sm:text-[34px]">
            Is MCP really an unguarded supply chain? We counted all{" "}
            {census.servers.toLocaleString()}.
          </h2>
          <p className="mt-4 max-w-2xl text-[15px] leading-relaxed text-on-hero-muted">
            Every server published to the official registry, across{" "}
            {registry.counts.versions.toLocaleString()} versions, joined against npm, PyPI, OSV and
            CISA KEV. This is a census, not a sample — the figures are exact.
          </p>

          <div className="mt-10 grid gap-x-10 gap-y-8 sm:grid-cols-2 lg:grid-cols-4">
            {[
              {
                v: `${census.percentSoloMaintainer}%`,
                l: `of the ${census.maintainerDataAvailable.toLocaleString()} backing packages have a single maintainer`,
                hi: true,
              },
              {
                v: census.publishedLast30Days.toLocaleString(),
                l: `shipped a new version in the last 30 days; the median last shipped ${census.medianDaysSincePublish} days ago`,
              },
              {
                v: `${census.percentWithoutRepository}%`,
                l: `publish no source repository — ${census.withoutRepository.toLocaleString()} servers whose code cannot be read before it runs`,
              },
              {
                v: census.delivery.remote.toLocaleString(),
                l: "are remote, so the operator sees every argument of every call",
              },
            ].map((s) => (
              <div key={s.l} className="border-t border-white/20 pt-4">
                <div
                  className={`text-[40px] leading-none font-semibold tracking-[-0.02em] ${
                    s.hi ? "text-accent" : "text-on-hero"
                  }`}
                >
                  {s.v}
                </div>
                <p className="mt-3 text-[13px] leading-relaxed text-on-hero-muted">{s.l}</p>
              </div>
            ))}
          </div>

          <p className="mt-10 max-w-3xl text-[14px] leading-relaxed text-on-hero-muted">
            <span className="text-on-hero">Two results cut the other way, and are reported as found.</span>{" "}
            Only {census.serversWithAdvisories} servers are backed by a package with a published
            advisory.{" "}
            {census.serversWithKevCve === 0 ? (
              <>
                And <span className="text-on-hero">none</span> carry a CVE on CISA&rsquo;s
                actively-exploited list — we checked all{" "}
                {threat.counts.kevEntries.toLocaleString()} and found zero. MCP is not yet being
                exploited through its dependencies. The exposure is structural, not historical,
                and reporting a clean result as clean is the only thing that keeps the dirty ones
                meaningful.
              </>
            ) : (
              <>{census.serversWithKevCve} carry an actively-exploited CVE.</>
            )}
          </p>

          {sample && (
            <div className="mt-10 border-t border-white/20 pt-8">
              <h3 className="text-[17px] font-semibold tracking-tight text-on-hero">
                Capability sample · {sample.size} servers
              </h3>
              <p className="mt-2 max-w-3xl text-[14px] leading-relaxed text-on-hero-muted">
                The registry publishes a description per server but not its tool list, and
                enumerating tools for real would mean launching nineteen thousand unknown
                binaries — the exact thing this tool exists to warn against. So classification
                runs over a random, seeded sample of descriptions using the same classifier the
                scanner uses.{" "}
                <span className="text-on-hero">
                  {sample.percentCompletePathAlone}% reach a complete attack path on their own.
                </span>{" "}
                That is a floor twice over: a one-paragraph description carries far less than a
                real tool list, and it counts only servers dangerous <em>alone</em> — which is the
                case per-server tooling already catches.
              </p>
            </div>
          )}
        </div>
      </section>

      <ProvenanceFooter />
    </>
  );
}
