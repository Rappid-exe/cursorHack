import type { Metadata } from "next";
import { IBM_Plex_Sans, IBM_Plex_Mono, Newsreader } from "next/font/google";
import "./globals.css";

/**
 * Three faces, three jobs.
 *
 * IBM Plex Sans runs the interface. It was drawn for technical documentation,
 * holds up at the small sizes this layout needs, and is nobody's framework
 * default.
 *
 * IBM Plex Mono sets everything that is data — capability ids, commands,
 * package names, CVEs, and the quoted spans of poisoned tool descriptions. If
 * it came out of a dataset or a config file, it should look like it did.
 *
 * Newsreader italic sets the wordmark and nothing else. One serif against an
 * otherwise geometric page is a signature; used anywhere else it becomes
 * decoration. Newsreader specifically because the obvious display serifs
 * (Playfair, Fraunces) have become the house style of generated design.
 */
const display = Newsreader({
  variable: "--font-display",
  subsets: ["latin"],
  weight: ["500", "600"],
  style: ["italic"],
  display: "swap",
});
const sans = IBM_Plex_Sans({
  variable: "--font-sans",
  subsets: ["latin"],
  weight: ["400", "500", "600"],
  display: "swap",
});

const mono = IBM_Plex_Mono({
  variable: "--font-mono",
  subsets: ["latin"],
  weight: ["400", "500", "600"],
  display: "swap",
});

export const metadata: Metadata = {
  title: "Blast Radius · What your MCP servers can actually do",
  description:
    "Finds the attack paths your installed MCP servers create together, grounded in CISA KEV, MITRE ATT&CK and OSV.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`${display.variable} ${sans.variable} ${mono.variable} h-full antialiased`}
    >
      <body className="min-h-full flex flex-col">{children}</body>
    </html>
  );
}
