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
  const { threat } = PROVENANCE;
  const { census, sample } = corpus as Corpus;

  return (
    <>
      <Hero />

      {/* --- The claim ------------------------------------------------------ */}
      <section id="how" className="border-b border-border bg-surface">
        <div className="mx-auto max-w-6xl px-6 py-16 sm:py-20">
          <h2 className="max-w-3xl text-[26px] leading-[1.2] font-semibold tracking-[-0.015em] sm:text-[34px]">
            The model reads English. It never decides what is dangerous.
          </h2>

          <div className="mt-10 grid gap-8 md:grid-cols-3">
            {[
              {
                n: "01",
                t: "Classify",
                d: "Reads each tool description and assigns capabilities from a closed list of fourteen.",
                who: "model",
              },
              {
                n: "02",
                t: "Locate",
                d: "Quotes spans that instruct the model rather than describe the tool — verbatim, or discarded.",
                who: "model",
              },
              {
                n: "03",
                t: "Compose",
                d: "Joins capabilities into attack paths from a hand-written rule table, scored against CISA KEV, ATT&CK and OSV.",
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
            <strong>fewer findings, never invented ones</strong>.
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
            We ran this over all {census.servers.toLocaleString()} published MCP servers.
          </h2>
          <p className="mt-4 max-w-2xl text-[15px] leading-relaxed text-on-hero-muted">
            The whole official registry, joined against npm, PyPI, OSV and CISA KEV. A census, not
            a sample — these figures are exact.
          </p>

          <div className="mt-10 grid gap-x-10 gap-y-8 sm:grid-cols-2 lg:grid-cols-4">
            {[
              {
                v: `${census.percentSoloMaintainer}%`,
                l: "of backing packages have a single maintainer",
                hi: true,
              },
              {
                v: census.publishedLast30Days.toLocaleString(),
                l: "shipped a new version in the last 30 days",
              },
              {
                v: `${census.percentWithoutRepository}%`,
                l: "publish no source repository at all",
              },
              {
                v: census.delivery.remote.toLocaleString(),
                l: "are remote — the operator sees every call",
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
            <span className="text-on-hero">One result cuts the other way, and we report it as found.</span>{" "}
            {census.serversWithKevCve === 0 ? (
              <>
                <span className="text-on-hero">None</span> of these servers carry a CVE on
                CISA&rsquo;s actively-exploited list — we checked all{" "}
                {threat.counts.kevEntries.toLocaleString()}. MCP is not being exploited through its
                dependencies yet. The exposure is structural, not historical.
              </>
            ) : (
              <>{census.serversWithKevCve} carry an actively-exploited CVE.</>
            )}
            {sample && (
              <>
                {" "}
                On a seeded sample of {sample.size} servers,{" "}
                <span className="text-on-hero">
                  {sample.percentCompletePathAlone}% reach a complete attack path alone
                </span>{" "}
                — a floor, since it ignores what happens when you install several.
              </>
            )}
          </p>
        </div>
      </section>

      <ProvenanceFooter />
    </>
  );
}
