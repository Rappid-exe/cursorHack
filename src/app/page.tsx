import { SiteHeader, ProvenanceFooter } from "@/components/Chrome";
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
      <SiteHeader />

      <main className="mx-auto w-full max-w-6xl flex-1 px-6 py-12">
        {/* --- Thesis ------------------------------------------------------- */}
        <section className="mb-14 max-w-3xl">
          <h1 className="text-[34px] leading-[1.15] font-semibold tracking-tight sm:text-[42px]">
            A server that reads files is not a vulnerability.
            <br />
            <span className="text-muted">A server that makes HTTP requests is not either.</span>
          </h1>
          <p className="mt-5 text-[15px] leading-relaxed text-muted">
            Installed together, they are an exfiltration primitive — and the model does not
            experience them as two servers. It sees one flat list of tools and will use any of
            them in the same turn. Every MCP security tool audits one server at a time, so none of
            them can see this.
          </p>
          <p className="mt-4 text-[15px] leading-relaxed text-muted">
            Blast Radius reads your client configuration and works out what an attacker who
            controls a web page, an issue comment or an email can actually make your agent do.
          </p>
        </section>

        {/* --- The architectural claim --------------------------------------- */}
        <section className="mb-14 grid gap-px overflow-hidden rounded-lg border border-border bg-border md:grid-cols-2">
          <div className="bg-surface p-5">
            <h2 className="notation text-[11px] uppercase tracking-[0.14em] text-faint">
              What the model does
            </h2>
            <p className="mt-2.5 text-[13px] leading-relaxed text-muted">
              Reads tool descriptions and assigns capabilities from a fixed list of fourteen. Finds
              spans of description that instruct the model rather than describe the tool, and
              quotes them verbatim — a quote that cannot be located in the source is discarded
              before you see it.
            </p>
          </div>
          <div className="bg-surface p-5">
            <h2 className="notation text-[11px] uppercase tracking-[0.14em] text-faint">
              What the model does not do
            </h2>
            <p className="mt-2.5 text-[13px] leading-relaxed text-muted">
              Decide what is dangerous. Every attack path, every severity band and every
              recommendation comes from a hand-written rule table joined against CISA&rsquo;s
              exploited-vulnerability catalogue, MITRE ATT&amp;CK and OSV. If the classifier
              returned nonsense you would get fewer findings, never invented ones.
            </p>
          </div>
        </section>

        <ScanFlow />

        {/* --- Corpus measurement -------------------------------------------- */}
        <section className="mt-16 border-t border-border pt-10">
          <h2 className="text-[22px] font-semibold tracking-tight">
            Is MCP really an unguarded supply chain? We counted.
          </h2>
          <p className="mt-3 max-w-3xl text-[14px] leading-relaxed text-muted">
            Every server published to the official MCP registry —{" "}
            {census.servers.toLocaleString()} of them, across{" "}
            {registry.counts.versions.toLocaleString()} published versions — joined against npm,
            PyPI and OSV. This part is a census, not a sample: the figures below are exact.
          </p>

          <div className="mt-6 grid gap-px overflow-hidden rounded-lg border border-border bg-border sm:grid-cols-2 lg:grid-cols-4">
            {[
              {
                v: `${census.percentSoloMaintainer}%`,
                l: `of the ${census.maintainerDataAvailable.toLocaleString()} backing packages have a single maintainer — one account compromise runs code on every machine that installs them`,
                accent: true,
              },
              {
                v: census.publishedLast30Days.toLocaleString(),
                l: `servers published a new version in the last 30 days; the median server last shipped ${census.medianDaysSincePublish} days ago`,
              },
              {
                v: `${census.percentWithoutRepository}%`,
                l: `publish no source repository at all — ${census.withoutRepository.toLocaleString()} servers whose code cannot be read before it runs`,
              },
              {
                v: census.delivery.remote.toLocaleString(),
                l: "are remote servers, where the operator sees every argument of every call",
              },
            ].map((s) => (
              <div key={s.l} className="bg-surface p-5">
                <div
                  className={`notation text-[28px] leading-none font-medium ${
                    s.accent ? "text-critical" : "text-foreground"
                  }`}
                >
                  {s.v}
                </div>
                <div className="mt-2 text-[12px] leading-snug text-faint">{s.l}</div>
              </div>
            ))}
          </div>

          <p className="mt-5 max-w-3xl text-[13px] leading-relaxed text-muted">
            Two of those numbers are worth stating plainly because they cut the other way.{" "}
            {census.serversWithAdvisories} servers are backed by a package with a published
            advisory, which is low. And{" "}
            {census.serversWithKevCve === 0 ? (
              <>
                <strong className="text-foreground">none</strong>{" "}carry a CVE on CISA&rsquo;s
                actively-exploited list — we checked all{" "}
                {threat.counts.kevEntries.toLocaleString()} and found zero. MCP is not yet being
                exploited through its dependencies. The exposure here is structural, not
                historical, and reporting a clean result as clean is the only way the dirty ones
                stay meaningful.
              </>
            ) : (
              <>
                {census.serversWithKevCve} carry a CVE on CISA&rsquo;s actively-exploited list.
              </>
            )}
          </p>

          {sample && (
            <>
              <h3 className="mt-10 text-[16px] font-semibold tracking-tight">
                Capability sample · {sample.size} servers
              </h3>
              <p className="mt-2 max-w-3xl text-[13px] leading-relaxed text-muted">
                The registry publishes a description per server but not its tool list, and
                enumerating tools for real would mean launching nineteen thousand unknown binaries
                — the exact thing this product exists to warn against. So capability
                classification runs over a random, seeded sample of server descriptions using the
                same classifier the scan above uses.{" "}
                <strong className="text-foreground">
                  {sample.percentCompletePathAlone}%
                </strong>{" "}
                of them reach a complete attack path on their own, with a median of{" "}
                {sample.medianCapabilities} capabilities each.
              </p>
              <p className="mt-3 max-w-3xl text-[13px] leading-relaxed text-muted">
                That is a floor, not an estimate. A one-paragraph description carries less than a
                real tool list, so this under-reports — and it counts only servers dangerous{" "}
                <em>alone</em>, which is the case per-server tooling already catches. The number
                that matters is what happens when you install eleven of them together, which is
                what the scan above measures.
              </p>
            </>
          )}
        </section>
      </main>

      <ProvenanceFooter />
    </>
  );
}
