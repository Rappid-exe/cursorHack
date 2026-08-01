import { SiteHeader } from "@/components/Chrome";
import { Brief } from "@/components/Brief";

export const metadata = {
  title: "Security brief · Blast Radius",
};

/**
 * The one-page brief.
 *
 * Same findings as the dashboard, different reader. The dashboard is for the
 * person deciding what to uninstall; this is for the person who has to justify
 * that decision to someone else — a security review, a ticket, a risk register.
 * It prints to one side of A4 and carries its own provenance, because a page
 * that leaves the tool has to stand up without it.
 */
export default function BriefPage() {
  return (
    <>
      <div className="no-print">
        <SiteHeader />
      </div>
      <main className="mx-auto w-full max-w-3xl flex-1 px-6 py-10">
        <Brief />
      </main>
    </>
  );
}
