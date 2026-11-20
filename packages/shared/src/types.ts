export type Severity = "critical" | "high" | "medium" | "low";
export type RiskGrade = "A" | "B" | "C" | "D" | "F";
export type ScanStatus = "queued" | "scanning" | "complete" | "failed";
export type SkillSource = "local" | "clawhub" | "url";
export type Recommendation = "block" | "warn" | "approve";
export type Plan = "free" | "pro" | "team";

export interface Finding {
  id?: string;
  category: string;
  severity: Severity;
  title: string;
  description: string;
  evidence?: string;
  lineNumber?: number | null;
  analysisPass: string;
  confidence?: number;
  fix?: string;
  /**
   * A disqualifying indicator of compromise (e.g. a known-malicious C2 IP).
   * Its presence forces the worst grade and a block recommendation on its own,
   * independent of the aggregate risk score — a known-bad match is a verdict,
   * not a heuristic to be averaged against benign signal.
   */
  disqualifying?: boolean;
}

export type CapabilityKind = "network" | "secret" | "env" | "persistence" | "behavior";

/** One thing a skill can do, at the first line that does it (scanned-content line). */
export interface Capability {
  kind: CapabilityKind;
  /** A site, a credential store, a secret env var, a persistence location, or a finding title. */
  value: string;
  file?: string;
  line?: number;
  /** env: the frontmatter declares this variable. */
  declared?: boolean;
  /** behavior: the finding's severity. */
  severity?: Severity;
  /** network: a raw IP, tunnel, request bin, paste or file drop, abuse-prone TLD, or a code host owner. */
  risky?: boolean;
}

export interface FindingsCount {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface ScanResult {
  id?: string;
  skillName: string;
  skillVersion?: string;
  skillSource: SkillSource;
  status: ScanStatus;
  riskScore: number;
  riskGrade: RiskGrade;
  findingsCount: FindingsCount;
  findings: Finding[];
  summary?: string;
  recommendation?: Recommendation;
  /** What the skill's code can do; compared across versions to flag new permissions. */
  capabilities?: Capability[];
  createdAt?: Date;
  completedAt?: Date;
  cached?: boolean;
}

export interface SkillFrontmatter {
  name?: string;
  description?: string;
  version?: string;
  metadata?: {
    openclaw?: {
      requires?: {
        env?: string[];
        bins?: string[];
      };
    };
  };
  [key: string]: unknown;
}

export interface ParsedSkill {
  frontmatter: SkillFrontmatter;
  body: string;
  codeBlocks: CodeBlock[];
  urls: string[];
  ipAddresses: string[];
  domains: string[];
  rawContent: string;
}

/** A file the CLI appended to the scanned content, by 1-based line range. */
export interface BundledFile {
  path: string;
  startLine: number;
  endLine: number;
  /** Something in the bundle runs this file by path: it is code whatever its name. */
  executed?: boolean;
}

export type SourceLanguage =
  | "python" | "javascript" | "typescript" | "shell" | "powershell"
  | "ruby" | "perl" | "php" | "lua" | "go" | "rust"
  | "config" | "markdown" | "text" | "other";

/** One unit of code to analyse: a bundled file or a fenced block in SKILL.md. */
export interface SourceFile {
  path: string;
  language: SourceLanguage;
  text: string;
  /** Line of `text`'s first line in the scanned content, so findings map back. */
  startLine: number;
  endLine: number;
}

export interface CodeBlock {
  language: string;
  content: string;
  lineStart: number;
  lineEnd: number;
}

export interface ThreatPattern {
  name: string;
  pattern: RegExp;
  severity: Severity;
  category: string;
  title: string;
  description: string;
  codeOnly?: boolean;
  fix?: string;
  /** See Finding.disqualifying — reserved for curated indicators of compromise. */
  disqualifying?: boolean;
}
