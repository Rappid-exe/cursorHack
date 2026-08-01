# Demo script — 3 minutes

Code freeze 15:45. Top 5 present live, 3 minutes each.

**Setup before you start:** dev server on `http://localhost:3001`, page loaded at
the very top so the hero fills the screen, scan **not** yet run. The scan takes
~15–17 seconds, which is dead air you have to fill — the beats below are written
to fill it.

**Read the numbers off the screen, don't memorise them.** Classification is a
live model call, so totals move a little between runs: expect ~9–10 paths, 2–4
composed, 2–3 injection spans. The shape never changes — there are always
composed paths, `notion-sync` is always flagged, most servers always close zero
paths, and the census figures are static and exact.

---

## 0:00 — The line (hero on screen, don't touch anything yet)

> "A server that reads files is not a vulnerability. A server that makes HTTP
> requests is not a vulnerability. Install both, and you have an exfiltration
> primitive."

> "Every MCP security tool audits one server at a time. None of them can see
> that — not because they're bad, but because the finding doesn't exist at the
> level they look at. Your agent doesn't see eleven servers. It sees one flat
> list of tools, and it'll use any two of them in the same turn."

## 0:25 — Show the config, start the scan

Scroll to the textarea. Don't read it out — gesture at it.

> "A normal developer's setup. Eleven servers — filesystem, GitHub, Postgres,
> Slack, AWS, a browser. Every one is a reasonable thing to install, and every
> one is individually defensible."

**Click Scan.** You now have ~15 seconds. Use them:

> "While that runs — the model here has exactly one job. It reads each tool
> description and picks capabilities from a closed list of fourteen. That's a
> language problem, so it's worth a model. What it never does is decide what's
> dangerous. Every path and every severity comes from a rule table a human
> wrote, joined to CISA's exploited-vulnerability catalogue and MITRE ATT&CK.
> If the classifier returned garbage you'd get fewer findings — never invented
> ones."

## 0:55 — The surface map

> "Eleven servers, twenty-one tools, thirteen distinct capabilities."

Point at the column footer counts.

> "Read a row and each server looks fine. Read the grid and you see what the
> model actually holds — the union. Nobody installed *that* on purpose."

## 1:15 — The composition finding

Scroll to Attack paths. **Read the section heading aloud.**

> "Ten complete attack paths. Several need more than one server acting
> together — those are the ones nothing else can find."

Pick a card with the teal **needs N servers together** chip.

> "Filesystem reads. AWS has network egress. Neither is a finding alone —
> filesystem can't reach the network, AWS can't read your project directory.
> Together it's a complete path from an attacker-controlled web page to your
> files leaving the building."

## 1:40 — Tool poisoning, and why it composes

Scroll to Tool poisoning.

> "`notion-sync`'s description tells the model to read `~/.aws/credentials`,
> pass the contents through an unrelated parameter, and not mention it. That
> text is in the model's context every session before you type anything."

> "And because that tool is *described* as reading credentials, the classifier
> tags it `secrets.read` — so it shows up as the credential leg of the
> injected-credential-theft path. The poisoning isn't a warning next to the
> graph. It's a leg *of* the graph."

**If running fast, add:**

> "One flagged span is from the real, official `fetch` server. Not an attack —
> but the same shape, and you can't tell by looking. So the tool quotes the text
> and stops, instead of deciding for you."

## 2:05 — What closes these ← **the strongest beat, do not cut**

Scroll to *What closes these*.

> "So which server do you uninstall? Here's the uncomfortable answer."

Point at the bar chart — most bars are empty.

> "Seven of the eleven close **zero** paths when you remove them. Including the
> shell server. Including the headless browser. The scariest-sounding things on
> the list are not load-bearing, because six other servers provide the same leg."

> "The best single removal closes one path out of ten. No combination of three
> servers closes them all. The surface is irreducibly composed — and that is
> exactly the finding a per-server audit can never produce, because it isn't a
> fact about any server."

> "The remedy isn't uninstalling. It's separation: run ingress-capable servers
> in a session that has no egress. The tool says so, and says how many paths
> that closes."

## 2:35 — The census

Scroll to the blue section.

> "We didn't want to assert MCP is an unguarded supply chain, so we counted.
> Every server in the official registry — 19,513 — joined against npm, PyPI,
> OSV and CISA KEV."

> "93.8% of the packages behind them have a **single maintainer**. One account
> stands between an attacker and code execution on every machine that installs
> them, with your credentials already in the environment."

> "And zero carry an actively-exploited CVE. We checked all 1,656. MCP isn't
> being exploited through its dependencies *yet* — the exposure is structural,
> not historical. Saying so is the only thing that keeps the other numbers worth
> anything."

## 2:55 — Close

> "The model classifies and quotes. The engine decides. Everything traces to a
> file in the repo, and it runs offline."

---

## If asked

**"Isn't this just a linter?"**
A linter checks one thing at a time. This finding only exists across servers —
and seven of eleven servers here are individually irrelevant to it.

**"How do you get the tool list?"**
From the config plus definitions the client supplies. We deliberately don't
launch the servers: enumerating tools for real means starting eleven unknown
binaries to find out whether they're safe, which is the problem, not the fix.

**"How do you know the model isn't making findings up?"**
It can't — it's never asked for one. Capabilities are validated against a closed
vocabulary and dropped if invented. Quoted spans are checked
character-for-character against the source and discarded if they don't match.
Severity is a pure function in one file. 52 checks enforce it.

**"Why is nearly everything critical?"**
Because eleven servers with shell, cloud admin, repo write and network egress
genuinely is that bad. We don't de-escalate — a rule's base severity is a floor.
The gradation you want is the solo/composed split and the remediation panel, not
the colour.

**"What's the product?"** ← *have the terminal ready, this is a 15-second answer*
The CLI. The page is how you look at the output.

```bash
npx tsx scripts/blast-radius.ts
```

It auto-detects your Cursor and Claude Desktop configs, and exits 1 on a
critical finding — so it's a CI check on the config file, and a pre-install
check on a laptop. The composition analysis is the thing nobody else can run,
and it gets monotonically worse every time someone on the team adds a server.

**"What if the API is down / your key dies during the demo?"**
It already did, this morning. The scan falls back to a recorded classification
of the sample config and the UI says so on screen — the engine is deterministic
and offline, so paths, severities and remediation are still computed live.
`npx tsx scripts/verify-fallback.ts` forces a rejected key and proves it.

**"Is the sample config real?"**
Synthetic, and labelled in the fixture. Real package names and launch commands —
so the supply-chain facts are real — with representative tool definitions and two
planted items. No live credential is in the repo.

**"Why does the census say zero exploited CVEs? Isn't that bad for your pitch?"**
It's the honest number and we lead with it. A tool that only ever reports alarm
is a tool nobody can calibrate against. The structural exposure is the finding;
inventing a historical one would undercut it.
