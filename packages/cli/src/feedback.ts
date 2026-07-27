/**
 * Feedback goes to a prefilled GitHub issue rather than a form.
 *
 * The old Tally form got 11 visits and 0 submissions in 12 months (2s average
 * dwell — people landed and bounced). A prefilled issue is one click, needs no
 * account switch for anyone already on GitHub, and lands somewhere public where
 * it helps other users instead of a private form inbox.
 */
const ISSUE_BODY = [
  "**What were you scanning?**",
  "",
  "",
  "**What happened, and what did you expect instead?**",
  "",
  "",
  "---",
  "_Filed from the ClawVet CLI._",
].join("\n");

/** Full prefilled URL — used when opening a browser. */
export const FEEDBACK_URL =
  "https://github.com/MohibShaikh/clawvet/issues/new" +
  "?labels=feedback" +
  `&title=${encodeURIComponent("Feedback: ")}` +
  `&body=${encodeURIComponent(ISSUE_BODY)}`;

/** Short form for terminal output — the encoded URL is unreadable when wrapped. */
export const FEEDBACK_DISPLAY_URL =
  "https://github.com/MohibShaikh/clawvet/issues/new";
