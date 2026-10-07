import { approveReview, canApprove, compareReviews, createReview, readApproval, writeDocument } from "../review.js";

export async function reviewCommand(target: string, options: { output: string; baseline?: string; blockAt: number }): Promise<void> {
  try {
    const review = await createReview(target, options.blockAt);
    const changes = options.baseline ? compareReviews(readApproval(options.baseline).review, review) : undefined;
    writeDocument(target, options.output, {
      review,
      ...(changes ? { changes } : {}),
      approvable: canApprove(review),
      note: "Indicators are textual matches, not proven behavior. Complete coverage is limited to recognized static references; approval is not a safety certificate.",
    });
    console.log(`Review saved to ${options.output}`);
    console.log(`Risk ${review.scan.riskScore}/100; coverage ${review.scan.coverage.complete ? "complete within supported inspection" : "INCOMPLETE"}; ${review.files.length} files hashed.`);
    if (changes) {
      for (const kind of ["added", "removed", "changed"] as const) for (const file of changes[kind]) console.log(`${kind}: ${JSON.stringify(file)}`);
      for (const signal of changes.newSignals) console.log(`New ${signal.kind}: ${JSON.stringify(signal.value)} at ${JSON.stringify(signal.path)}:${signal.line}`);
      if (changes.engineChanged) console.log("Scanner changed since approval.");
      if (changes.policyChanged) console.log("Policy changed since approval.");
    }
    for (const issue of review.scan.coverage.issues) console.log(`Coverage: ${JSON.stringify(issue.path)}: ${issue.reason}`);
    console.log(canApprove(review) ? "Read the JSON report before running clawvet approve." : "Approval refused: incomplete inspection or blocking findings.");
    if (!canApprove(review)) process.exitCode = 1;
  } catch (err) {
    console.error(`Review failed: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 1;
  }
}

export async function approveCommand(target: string, options: { review: string; output: string }): Promise<void> {
  try {
    await approveReview(target, options.review, options.output);
    console.log(`Approval saved to ${options.output}. It applies only to these files, scanner, and policy.`);
  } catch (err) {
    console.error(`Approval failed: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 1;
  }
}
