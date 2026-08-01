# 2-minute demo — the whole thing

Browser on `localhost:3001`, scrolled to the top so the hero fills the screen.
Terminal open behind it in the project directory, nothing typed. You flip to it
once, at 1:45.

**Two minutes is 300 spoken words.** Everything below is timed. The only beat
that must not be cut is 1:15.

---

## 0:00 — Hero on screen, don't touch anything (15s)

> "A server that reads files is not a vulnerability. A server that makes HTTP
> requests is not a vulnerability."

> "Install both and you have an exfiltration path. Every MCP security tool
> audits one server at a time — so none of them can see it."

## 0:15 — Scroll to the config, hit Scan (20s of fill)

> "Eleven servers. Filesystem, GitHub, Postgres, Slack, AWS, a browser. Every
> one is a reasonable thing to install."

**Click Scan. Keep talking — this takes about fifteen seconds:**

> "The model here has exactly one job: read each tool description and assign
> capabilities from a closed list of fourteen. It never decides what's
> dangerous. Every attack path and every severity comes from a rule table a
> human wrote, joined to CISA's exploited-vulnerability catalogue and MITRE
> ATT&CK."

> "So a hallucination can lose you a finding. It can't invent one."

## 0:35 — Results land. Surface map (15s)

> "Eleven servers, twenty-one tools, thirteen capabilities."

Gesture across the grid.

> "Read a row and each server looks fine. Read the grid and you see what the
> model actually holds — the union. Nobody installed that on purpose."

## 0:50 — Attack paths (15s)

> "Ten complete attack paths. Several need more than one server."

Point at a composed card — `filesystem → filesystem → aws`.

> "Filesystem reads. AWS has egress. Neither is a finding alone. Together it's
> a path from an attacker-controlled web page to your files leaving the
> building."

## 1:05 — Tool poisoning (10s)

Scroll to the highlighted quote.

> "This server's description tells the model to read `~/.aws/credentials` and
> not mention it. And because the tool is *described* as reading credentials,
> it becomes the credential leg of that exfiltration path. The poisoning isn't
> a warning beside the graph — it's a leg *of* it."

## 1:15 — What closes these ← **the beat. Never cut this.**

> "So which server do you uninstall?"

> "**Seven of the eleven close zero paths when you remove them.** Including the
> shell server. Including the headless browser. The scariest things on the list
> aren't load-bearing, because six others provide the same leg."

> "No combination of three servers closes them all. The fix isn't uninstalling
> — it's separation. Run ingress-capable servers in a session with no egress.
> That closes all ten."

## 1:35 — Census (10s)

Scroll to the blue band.

> "We ran this across all 19,513 servers in the official registry. 93.8% of
> their packages have a single maintainer. Zero have an actively-exploited CVE
> — we checked all 1,656 and we report that as found."

## 1:45 — Flip to the terminal (10s)

```bash
npm run scan
```

Don't wait for it. Point at the shape as it goes, or at a previous run.

> "Same engine, no browser. Exits one on a critical finding — so it's a CI check
> on your config file. That's the product; the page is how you look at it."

## 1:55 — Close (5s)

> "The model classifies and quotes. The engine decides. Every number traces to
> a file in the repo, and it runs offline."

---

## Cuts, in the order you should make them

Running long is the likeliest failure. Drop in this order:

1. **1:35 census** — the strongest thing you lose, but it's a stat, not a demo.
2. **0:35 surface map** — go straight from scan to attack paths.
3. **1:05 poisoning** — reduce to one sentence: *"and one server's description
   tells the model to read your AWS credentials and hide it."*

Never cut 1:15. Everything before it is setup for that line.

## Emergency

**Scan errors.** It falls back to a recorded classification of this exact config
and says so on screen — paths, severities and remediation are still computed
live because the engine is deterministic and offline. Say that out loud. It's a
better answer than a working demo.

**Page 404s.** `rm -rf .next`, then `npm run dev`. Don't run `npm run build`
before demoing; that's what causes it.

**Scan runs long.** The fill copy at 0:15 is the architecture pitch — you need
to say it regardless, so you're not losing time, just reordering it.

**Terminal shows boxes.** `set NO_COLOR=1`, or scroll past the banner.

## The five questions

**"Isn't this a linter?"**
A linter checks one thing at a time. Seven of eleven servers here are
individually irrelevant to the finding.

**"How do you get the tool list?"**
Config plus definitions captured from a client session. It never launches a
server to enumerate tools — starting eleven unknown binaries to find out whether
they're safe is the problem, not the fix.

**"How do you know the model isn't making it up?"**
It's never asked to. Capabilities validate against a closed vocabulary. Quoted
spans are checked character-for-character against the source and dropped if they
don't match. 72 checks enforce it.

**"Why is everything critical?"**
Eleven servers with shell, cloud admin, repo write and egress genuinely is that
bad. Severity never de-escalates — a rule's base is a floor. The gradation is
the solo/composed split and the remediation panel, not the colour.

**"Why AI Security and not offensive?"**
We use AI security's own failure mode — an untrusted model deciding what's
dangerous — against MCP itself, then prove it's contained.
