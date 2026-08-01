# Demo script — 3 minutes

Code freeze 15:45. Top 5 present live, 3 minutes each.

**Setup before you start:** dev server on `http://localhost:3001`, page loaded,
scrolled to the top, scan **not** yet run. The scan takes ~15 seconds, which is
dead air you have to fill — the beats below are written to fill it.

**Read the numbers off the screen, don't memorise them.** Classification is a
live model call, so the totals move a little between runs: expect ~9–10 paths,
2–4 of them composed, 2–3 injection spans. Every number below is written as
"read what it says" for that reason. The shape never changes — there are always
composed paths, `notion-sync` is always flagged, and the census figures at the
bottom of the page are static and exact.

---

## 0:00 — The line (say this before touching anything)

> "A server that reads files is not a vulnerability. A server that makes HTTP
> requests is not a vulnerability. Install both, and you have an exfiltration
> primitive."

> "Every MCP security tool audits one server at a time. None of them can see
> that — not because they're bad, but because the finding doesn't exist at the
> level they look at. The model doesn't see eleven servers. It sees one flat
> list of tools, and it'll use any two of them in the same turn."

## 0:25 — Show the config, start the scan

Scroll to the textarea. Don't read it out — just gesture at it.

> "This is a normal developer's setup. Eleven servers. Filesystem, GitHub,
> Postgres, Slack, AWS, a browser. Every one of them is a reasonable thing to
> install, and every one is individually defensible."

**Click Scan.** Now you have 15 seconds. Use them:

> "While that runs — the model here has exactly one job. It reads each tool
> description and picks capabilities from a closed list of fourteen. That's a
> language problem, so it's worth a model. What it never does is decide what's
> dangerous. Every attack path and every severity comes from a rule table a
> human wrote, joined to CISA's exploited-vulnerability catalogue and MITRE
> ATT&CK. If the classifier returned garbage you'd get fewer findings — never
> invented ones."

## 0:55 — The surface map

> "Eleven servers, twenty-one tools, twelve distinct capabilities."

Point at the column footer counts.

> "Read a row and each server looks fine. Read the grid and you're looking at
> what the model actually holds — the union. Nobody installed *that* on
> purpose."

## 1:20 — The composition finding (this is the demo)

Scroll to Attack paths. **Read the section heading aloud** — it says how many
were found and how many span more than one server.

> "Ten complete attack paths. Several of them need more than one server acting
> together — and those are the ones nothing else can find."

Pick any card with the teal **needs N servers together** chip. `Local file
exfiltration` and `Injected credential theft` are the reliable ones.

> "Filesystem reads. AWS has network egress. Neither one is a finding on its
> own — filesystem can't reach the network, AWS can't read your project
> directory. Together they're a complete path from an attacker-controlled web
> page to your files leaving the building."

Point at the "shortest route" line and read the count off it.

> "And that's the *shortest* route. Most of the eleven servers can contribute to
> this path somehow, so removing any one of them doesn't close it."

## 1:55 — Tool poisoning, and why it composes

Scroll up to Tool poisoning.

> "This is `notion-sync`. Its tool description tells the model to read
> `~/.aws/credentials`, pass the contents through an unrelated parameter, and
> not mention it to the user. That text is in the model's context every session
> before you type anything."

> "Here's the part I like. That tool is *described* as reading credentials — so
> the classifier tags it `secrets.read` — so it shows up as the credential leg
> of the injected-credential-theft path. The poisoning isn't a separate warning
> sitting next to the graph. It's a leg *of* the graph."

**If you have 15 spare seconds, this is the strongest thing you can say:**

> "One of these flagged spans is from the real, official `fetch` server. It's
> not an attack. But it's the same shape, and you can't tell by looking — which
> is why the tool quotes the text and stops, instead of deciding for you."

## 2:25 — The census

Scroll to the bottom section.

> "We didn't want to assert MCP is an unguarded supply chain, so we counted.
> Every server in the official registry — 19,513 of them, joined against npm,
> PyPI, OSV and CISA KEV."

> "93.8% of the packages behind them have a **single maintainer**. One account
> is all that stands between an attacker and code execution on every machine
> that installs them — with your credentials already in the environment and no
> pinned version to slow it down."

> "And zero of them carry an actively-exploited CVE. We checked all 1,656. MCP
> isn't being exploited through its dependencies *yet*. The exposure is
> structural, not historical — and saying so is the only thing that keeps the
> other numbers worth anything."

## 2:50 — Close

> "The model classifies and quotes. The engine decides. Everything you saw
> traces to a file in the repo, and it runs offline."

---

## If asked

**"Isn't this just a linter?"**
A linter checks one thing at a time. The finding here only exists across
servers — three of the nine paths have no single server on them.

**"How do you get the tool list?"**
From the config plus definitions the client supplies. We deliberately don't
launch the servers: enumerating tools for real means starting eleven unknown
binaries to find out whether they're safe, which is the problem, not the fix.

**"How do you know the model isn't making findings up?"**
It can't — it's never asked for one. Capabilities are validated against a
closed vocabulary and dropped if invented. Quoted spans are checked
character-for-character against the source and discarded if they don't match.
Severity is a pure function in one file.

**"Why is nearly everything critical?"**
Because eleven servers with shell, cloud admin, repo write and network egress
genuinely is that bad. We don't de-escalate — a rule's base severity is a
floor. The gradation you want is the solo/composed split, not the colour.

**"What's the product?"**
Pre-install review, and CI on the config file. The composition check is the
thing nobody else can run, and it gets worse every time someone adds a server.

**"Is the sample config real?"**
Synthetic, and labelled as such in the fixture. Real package names and real
launch commands — so the supply-chain facts are real — with representative tool
definitions and two planted items. No live credential is in the repo.
