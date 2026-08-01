import type { Metadata } from "next";
import { IBM_Plex_Sans, IBM_Plex_Mono } from "next/font/google";
import "./globals.css";

/**
 * Two faces, two jobs.
 *
 * IBM Plex Sans runs the interface. It was drawn for technical documentation,
 * holds up at the small sizes this layout needs, and is nobody's framework
 * default.
 *
 * IBM Plex Mono sets everything that is data — capability ids, commands,
 * package names, CVEs, and the quoted spans of poisoned tool descriptions. If
 * it came out of a dataset or a config file, it should look like it did.
 */
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
    <html lang="en" className={`${sans.variable} ${mono.variable} h-full antialiased`}>
      <body className="min-h-full flex flex-col">{children}</body>
    </html>
  );
}
