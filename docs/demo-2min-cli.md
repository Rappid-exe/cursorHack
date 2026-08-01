# 2-minute demo — CLI

Terminal open, in `C:\Users\umair\Desktop\cyberHack`, nothing typed yet. Font
size up. One command, typed live.

**Timing is tight.** The scan takes 14–22s, which is a sixth of your slot. The
0:15 block is written to cover twenty seconds of it — if it returns early, cut
to the next beat mid-sentence.

---

## 0:00 — Before you type (15s)

> "A server that reads files is not a vulnerability. A server that makes HTTP
> requests is not a vulnerability."

> "Install both, and you have an exfiltration path. Every MCP security tool
> audits one server at a time, so none of them can see it."

## 0:15 — Type it and hit enter

```bash
npm run scan
```

> "That's my Cursor config. Eleven servers — filesystem, GitHub, Postgres,
> Slack, AWS, a browser. Every one is a reasonable thing to install."

**Fill while it runs (~20s):**

> "The model here has one job: read each tool description and pick capabilities
> from a closed list of fourteen. It never decides what's dangerous. Every
> attack path and every severity comes from a rule table a human wrote, joined
> to CISA's exploited-vulnerability catalogue and MITRE ATT&CK."

> "So a hallucination can lose you a finding. It can't invent one."

## 0:40 — Output lands. Scroll to attack paths (15s)

> "Ten complete attack paths, four of which need more than one server."

Point at a composed route — `filesystem → filesystem → aws`.

> "Filesystem reads. AWS has network egress. Neither is a finding alone.
> Together it's a path from an attacker-controlled web page to your files
> leaving the building."

## 0:55 — Tool poisoning (20s)

Point at the `notion-sync` lines.

> "This one's description tells the model to read `~/.aws/credentials`, pass it
> through an unrelated parameter, and not mention it. That text is in the
> model's context every session before you type anything."

> "And because the tool is *described* as reading credentials, it gets tagged
> `secrets.read` — so it shows up as the credential leg of the exfiltration
> path. The poisoning isn't a warning next to the graph. It's a leg *of* it."

## 1:15 — What closes these ← **the beat. Do not cut.**

Scroll to `What closes these`.

> "So which server do you uninstall?"

> "**Seven of the eleven close zero paths when you remove them.** Including the
> shell server. Including the headless browser. The scariest things on the list
> aren't load-bearing, because six others provide the same leg."

> "Best single removal closes two out of ten. No combination of three closes
> them all. The fix isn't uninstalling — it's separation. Run ingress-capable
> servers in a session with no egress. That closes all ten."

## 1:40 — The product (15s)

Point at the last line: `✗ 9 critical — exit 1`.

> "Exit one. This is a CI check on your config file, and a pre-install check on
> a laptop. It gets worse every time someone on your team adds a server."

## 1:50 — Close (10s)

> "We ran this across all 19,513 servers in the official MCP registry. 93.8% of
> the packages behind them have a single maintainer. Zero have an
> actively-exploited CVE — we checked all 1,656, and we report that as found."

> "The model classifies and quotes. The engine decides. Everything traces to a
> file in the repo, and it runs offline."

---

## If you have 30 more seconds

Open `localhost:3001` and scroll the capability surface grid.

> "Same engine, same numbers. Read a row and each server looks fine. Read the
> grid and you see what the model actually holds — the union, which nobody
> installed on purpose."

## Emergency

**Scan errors out.** It falls back to a recorded classification of this exact
config and says so on screen — the engine is deterministic and offline, so paths
and remediation are still computed live. Say that out loud; it's a better answer
than a working demo.

**npm prints noise after exit 1.** Use `npm run scan -s`.

**Terminal shows boxes instead of the banner.** `set NO_COLOR=1` and rerun, or
just scroll past it.

**Web page 404s.** `rm -rf .next` then `npm run dev`. Don't run `npm run build`
before demoing — that's what causes it.

---

## The four questions you'll get

**"Isn't this a linter?"**
A linter checks one thing at a time. Seven of eleven servers here are
individually irrelevant to the finding.

**"How do you get the tool list?"**
From the config plus definitions captured in a client session. It never launches
a server to enumerate tools — starting eleven unknown binaries to find out
whether they're safe is the problem, not the fix.

**"How do you know the model isn't making it up?"**
It's never asked to. Capabilities validate against a closed vocabulary. Quoted
spans are checked character-for-character against the source and dropped if they
don't match. 72 checks enforce it.

**"Why AI Security and not offensive?"**
We use AI security's own failure mode — an untrusted model deciding what's
dangerous — against MCP itself, then prove it's contained.
