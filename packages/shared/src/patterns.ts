import type { ThreatPattern } from "./types.js";

// Build regex from parts at runtime to avoid AV false positives on signature strings
function re(parts: string[], flags: string): RegExp {
  return new RegExp(parts.join(""), flags);
}

// The text of an inline program: an opening quote (escaped when the command is
// itself inside a string), then anything up to the same quote. Bounded so one
// unclosed quote cannot make every later match rescan the file.
const INLINE_QUOTE = "\\s*\\\\?([\"'])";
const INLINE_CHAR = "(?:\\\\.|(?!\\1)[^\\\\])";
const INLINE_LIMIT = 4000;
// Critical when the program is not a literal a reviewer can read in place (a
// substitution, a bare variable, more than INLINE_LIMIT characters), or when it
// contains one of `tokens`.
function inlinePayload(command: string[], tokens: string[]): RegExp {
  return re([...command,
    "(?:\\s+\\$[\\w{(]|", INLINE_QUOTE, "(?:\\$[\\w{(][^\"']{0,200}\\1|", INLINE_CHAR, `{0,${INLINE_LIMIT}}?(?:`, ...tokens, ")|", INLINE_CHAR, `{${INLINE_LIMIT}}))`], "g");
}

export const THREAT_PATTERNS: ThreatPattern[] = [
  // ═══════════════════════════════════════════════════════
  // CRITICAL: Remote code execution
  // ═══════════════════════════════════════════════════════
  {
    name: "CURL_PIPE_BASH",
    // Only the first `curl` on a line is tried, made atomic by the lookahead
    // and backreference. Any later one matches only if the first does, and
    // retrying each repeat of `curl` made a long line quadratic.
    pattern: re(["^(?=([^\\n]*?curl\\s))\\1[^\\n]*\\|\\s*(ba)?", "sh"], "gim"),
    severity: "critical",
    category: "remote_code_execution",
    title: "Curl piped to shell",
    description: "Downloads and executes remote code directly — classic supply chain attack vector.",
    codeOnly: true,
    fix: "Download the script first, inspect it, then execute: `curl -o setup.sh URL && cat setup.sh && bash setup.sh`",
  },
  {
    name: "WGET_EXECUTE",
    // First `wget` on a line only, as in CURL_PIPE_BASH.
    pattern: re(["^(?=([^\\n]*?wget\\s))\\1[^\\n]*&&\\s*(ba)?", "sh"], "gim"),
    severity: "critical",
    category: "remote_code_execution",
    title: "Wget with shell execution",
    description: "Downloads and executes remote code via wget.",
    codeOnly: true,
    fix: "Download the file first with `wget -O script.sh URL`, review it, then execute.",
  },
  {
    name: "EVAL_DYNAMIC",
    pattern: re(["ev", "al\\s*\\("], "gi"),
    severity: "critical",
    category: "remote_code_execution",
    title: "Dynamic code evaluation",
    description: "Uses dynamic code evaluation which can run arbitrary code.",
    codeOnly: true,
    fix: "Replace dynamic evaluation with a safer alternative like JSON.parse() or a sandboxed environment.",
  },
  {
    name: "BASE64_DECODE",
    pattern: re(["base", "64\\s+(-d|--dec", "ode)"], "gi"),
    severity: "critical",
    category: "obfuscation",
    title: "Base64 decode execution",
    description: "Decodes base64 content, often used to hide malicious payloads.",
    codeOnly: true,
    fix: "Decode and include the command directly so users can review it.",
  },
  // `python -c "import json,sys; ..."` is how shell scripts parse JSON, and the
  // program is right there to read, so on its own it is a note. The payload rule
  // below is the critical one.
  {
    name: "PYTHON_EXEC",
    pattern: re(["pyth", "on[3]?\\s+-c"], "gi"),
    severity: "low",
    category: "remote_code_execution",
    title: "Python inline execution",
    description: "Executes an inline Python program. Review what it does.",
    codeOnly: true,
    fix: "Move inline code to a separate .py file so users can review it before execution.",
  },
  {
    name: "PYTHON_EXEC_PAYLOAD",
    // Runs a shell, opens a socket or evaluates text: what a one-line dropper
    // or reverse shell does and a JSON filter never does.
    pattern: inlinePayload(["pyth", "on[3]?\\s+-c"], [
      "ex", "ec\\s*\\(|ev", "al\\s*\\(|compile\\s*\\(|__import__|",
      "os\\.(?:sys", "tem|popen|dup2|setuid|exec[lv]p?e?)\\s*\\(|pty\\.spawn|socket\\.socket|shell\\s*=\\s*True|",
      "\\/bin\\/(?:ba|z|da)?sh|\\$\\(",
    ]),
    severity: "critical",
    category: "remote_code_execution",
    title: "Python inline payload",
    description: "Runs an inline Python program that starts a shell, opens a socket or evaluates code, or whose text is not visible in the command.",
    codeOnly: true,
    fix: "Ship the program as a .py file and remove shell, socket and exec/eval calls from one-liners.",
  },
  {
    name: "REVERSE_SHELL",
    pattern: re(["\\/dev\\/tc", "p\\/|nc\\s+-[elp]|nca", "t\\s+-|mkfi", "fo\\s+.{0,200}\\/tmp"], "gi"),
    severity: "critical",
    category: "remote_code_execution",
    title: "Reverse shell",
    description: "Creates a reverse connection back to an attacker-controlled server.",
    codeOnly: true,
    fix: "Remove reverse connection commands — these are almost never legitimate in skills.",
  },
  {
    name: "CRON_PERSISTENCE",
    pattern: re(["cron", "tab\\s+-|\\/etc\\/cro", "n|system", "ctl\\s+enable"], "gi"),
    severity: "critical",
    category: "persistence",
    title: "Scheduled task persistence",
    description: "Installs a cron job or systemd service for persistent execution after reboot.",
    codeOnly: true,
    fix: "Document the scheduled task in the skill description and require explicit user consent before installing.",
  },
  {
    name: "PERL_EXEC",
    pattern: re(["per", "l\\s+-e"], "gi"),
    severity: "critical",
    category: "remote_code_execution",
    title: "Perl inline execution",
    description: "Executes inline Perl code which may contain obfuscated payloads.",
    codeOnly: true,
    fix: "Move inline code to a separate .pl file so users can review it before execution.",
  },
  // Same split as Python above: a readable one-liner is a note.
  {
    name: "NODE_EVAL",
    pattern: re(["no", "de\\s+-e\\s"], "gi"),
    severity: "low",
    category: "remote_code_execution",
    title: "Node.js inline execution",
    description: "Executes an inline Node.js program. Review what it does.",
    codeOnly: true,
    fix: "Move inline code to a separate .js file so users can review it before execution.",
  },
  {
    name: "NODE_EVAL_PAYLOAD",
    pattern: inlinePayload(["no", "de\\s+(?:-e|--eval|-p|--print)"], [
      "ev", "al\\s*\\(|new\\s+Function|child_", "process|net\\.(?:connect|createConnection|Socket)|vm\\.run|",
      "at", "ob\\s*\\(|base", "64|\\/bin\\/(?:ba|z|da)?sh|\\$\\(",
    ]),
    severity: "critical",
    category: "remote_code_execution",
    title: "Node.js inline payload",
    description: "Runs an inline Node.js program that starts a process, opens a socket, decodes or evaluates code, or whose text is not visible in the command.",
    codeOnly: true,
    fix: "Ship the program as a .js file and remove process, socket and eval calls from one-liners.",
  },
  {
    name: "RUBY_EXEC",
    pattern: re(["rub", "y\\s+-e"], "gi"),
    severity: "critical",
    category: "remote_code_execution",
    title: "Ruby inline execution",
    description: "Executes inline Ruby code which may contain hidden payloads.",
    codeOnly: true,
    fix: "Move inline code to a separate .rb file so users can review it before execution.",
  },

  // ═══════════════════════════════════════════════════════
  // HIGH: Credential theft
  // ═══════════════════════════════════════════════════════
  {
    name: "ENV_FILE_READ",
    // Match credential files, not the words. A leading letter before ".env"
    // means it is a property access like `process.env`, and bare "credentials"
    // is ordinary English ("store your credentials"); both were the top two
    // false-positive sources on real skills.
    pattern: /(?<![A-Za-z0-9_])\.env\b|[./\\-]credentials\b|credentials\.(?:json|ya?ml)|\.aws\b|\.ssh\b|keychain/gi,
    severity: "high",
    category: "credential_theft",
    title: "Sensitive file access",
    description: "Accesses credential files (.env, .aws, .ssh, keychain).",
    fix: "Declare required env vars in frontmatter under `metadata.openclaw.requires.env`.",
  },
  {
    // Gaps written `.{0,200}`, here and in the prose rules below, rather than
    // `.*`: an unbounded gap retried from every repeat of the first word made
    // one long line quadratic, and 200 characters is far wider than any
    // instruction these describe.
    name: "API_KEY_EXFIL",
    pattern: /(ANTHROPIC|OPENAI|SLACK|DISCORD|TELEGRAM|STRIPE|GITHUB|GITLAB|AWS_SECRET|GROQ|OPENROUTER).{0,200}(_KEY|_TOKEN|_SECRET)/gi,
    severity: "high",
    category: "credential_theft",
    title: "API key reference",
    description: "References specific API keys/tokens that could be exfiltrated.",
    fix: "Use environment variable references ($VAR) instead of hardcoding keys, and declare them in requires.env.",
  },
  {
    name: "DOTFILE_ACCESS",
    pattern: /~\/\.(openclaw|clawdbot|moltbot)\//gi,
    severity: "high",
    category: "credential_theft",
    title: "OpenClaw config access",
    description: "Accesses OpenClaw/Clawdbot/Moltbot configuration directories.",
    fix: "Use the official OpenClaw SDK/API instead of directly reading config directories.",
  },
  {
    name: "SESSION_THEFT",
    pattern: /sessions\/\*\.jsonl/gi,
    severity: "high",
    category: "credential_theft",
    title: "Session data access",
    description: "Accesses session transcript files which may contain sensitive data.",
    fix: "Remove session file access — skills should not read conversation transcripts.",
  },
  {
    name: "SSH_KEY_ACCESS",
    pattern: /~\/\.ssh\/id_|\.pem\b|BEGIN\s+(RSA\s+)?PRIVATE\s+KEY/gi,
    severity: "high",
    category: "credential_theft",
    title: "SSH/private key access",
    description: "Accesses SSH keys or private key files that could be stolen.",
    fix: "Use ssh-agent or a credential manager instead of directly reading key files.",
  },
  {
    name: "BROWSER_DATA",
    pattern: /\.config\/google-chrome|\.mozilla\/firefox|Login\s*Data|Cookies\.sqlite/gi,
    severity: "high",
    category: "credential_theft",
    title: "Browser data access",
    description: "Accesses browser profiles which contain saved passwords, cookies, and tokens.",
    fix: "Remove browser data access — skills should not read browser profiles.",
  },
  {
    name: "GIT_CREDENTIALS",
    pattern: /\.git-credentials|\.gitconfig|git\s+config.{0,200}credential/gi,
    severity: "high",
    category: "credential_theft",
    title: "Git credential access",
    description: "Accesses git credential storage which may contain auth tokens.",
    fix: "Use `git` CLI commands instead of directly reading credential files.",
  },
  {
    name: "NPM_TOKEN",
    pattern: /\.npmrc|npm_token|NPM_AUTH_TOKEN/gi,
    severity: "high",
    category: "credential_theft",
    title: "npm token access",
    description: "Accesses npm auth tokens which could be used to publish malicious packages.",
    fix: "Use `npm whoami` or `npm config get` instead of directly reading .npmrc.",
  },
  {
    name: "KUBE_CONFIG",
    pattern: /~\/\.kube\/config|KUBECONFIG/gi,
    severity: "high",
    category: "credential_theft",
    title: "Kubernetes config access",
    description: "Accesses Kubernetes configuration which contains cluster credentials.",
    fix: "Use `kubectl` CLI commands instead of directly reading kubeconfig.",
  },
  {
    name: "DOCKER_SOCKET",
    pattern: /\/var\/run\/docker\.sock|docker\s+exec/gi,
    severity: "high",
    category: "container_escape",
    title: "Docker socket/exec access",
    description: "Accesses Docker socket or runs exec — could enable container escape.",
    fix: "Use Docker SDK or CLI with limited permissions instead of direct socket access.",
  },

  // ═══════════════════════════════════════════════════════
  // HIGH: Network exfiltration
  // ═══════════════════════════════════════════════════════
  {
    name: "WEBHOOK_SEND",
    pattern: /webhook\.(site|url)|discord\.com\/api\/webhooks|hooks\.slack\.com|api\.telegram\.org\/bot/gi,
    severity: "high",
    category: "data_exfiltration",
    title: "Webhook data exfiltration",
    description: "Sends data to webhook endpoints (Discord, Slack, Telegram) — common exfiltration channel.",
    fix: "If webhook integration is needed, declare it in the skill description and let users configure their own webhook URL.",
  },
  {
    name: "BORE_TUNNEL",
    pattern: /bore\.pub|ngrok|localtunnel|serveo\.net|localhost\.run/gi,
    severity: "high",
    category: "data_exfiltration",
    title: "Tunnel service usage",
    description: "Uses tunneling services to expose local services or exfiltrate data.",
    fix: "Document tunnel usage in the skill description and require explicit user consent.",
  },
  {
    name: "SUSPICIOUS_IP",
    pattern: /\b(?:91\.92\.242\.\d+|45\.61\.\d+\.\d+)\b/g,
    severity: "critical",
    category: "data_exfiltration",
    title: "Known malicious IP",
    description: "Contains IP addresses associated with known ClawHavoc C2 infrastructure.",
    fix: "Remove references to known malicious IP addresses.",
    // Curated indicator of compromise: an exact match against known C2
    // infrastructure is disqualifying on its own, not a signal to be averaged.
    disqualifying: true,
  },
  {
    name: "DNS_EXFIL",
    // First occurrence on a line only, as in CURL_PIPE_BASH.
    pattern: /^(?=([^\n]*?dig\s))\1[^\n]*TXT|^(?=([^\n]*?nslookup\s))\2[^\n]*\$|^(?=([^\n]*?dns))\3[^\n]*exfil|\.burpcollaborator\.|\.oastify\./gim,
    severity: "high",
    category: "data_exfiltration",
    title: "DNS exfiltration",
    description: "Uses DNS queries to exfiltrate data — bypasses most firewalls.",
    fix: "Remove DNS exfiltration patterns — use standard HTTP APIs for data transfer.",
  },
  // Uploads whose payload is local data being read, to any host. Each is
  // medium on its own: what makes it theft is a credential read in the same
  // skill, which the context pass joins into a critical finding. A literal or
  // jq-built request body, or a token sent as an auth header, is not matched.
  // Every gap is bounded: an unbounded one rescans the rest of a long line from
  // each command name on it, which is quadratic on a line of repeated names.
  {
    name: "PIPED_UPLOAD",
    pattern: /\b(?:cat|env|printenv|tar|zip|base64|gzip|find)\b[^\n|]{0,300}\|\s{0,20}(?:[^\n|]{0,300}\|\s{0,20}){0,3}curl\b[^\n]{0,400}?\s(?:-d|--data(?:-binary|-raw|-urlencode)?|-F|--form|-T|--upload-file)\s{1,20}["']?(?:\w{1,100}=)?@-/gi,
    severity: "medium",
    category: "data_exfiltration",
    title: "Local data piped into an upload",
    codeOnly: true,
    description: "Reads files or the environment and sends them as a request body.",
    fix: "Send only the fields the API needs, and say in the description what leaves the machine.",
  },
  {
    name: "SUBSTITUTED_UPLOAD",
    pattern: /curl\b[^\n]{0,400}?\s(?:-d|--data(?:-binary|-raw|-urlencode)?|-F|--form)\s{0,20}["']?[^"'\s]{0,300}\$\((?:\s{0,20}(?:cat|env|printenv|base64)\b|[A-Z_]{0,100}(?:TOKEN|KEY|SECRET|PASS)[A-Z_]{0,100}\))/g,
    severity: "medium",
    category: "data_exfiltration",
    title: "Secret or file substituted into an upload",
    codeOnly: true,
    description: "Builds a request body from a file read or a secret-named variable.",
    fix: "Send only the fields the API needs, and say in the description what leaves the machine.",
  },
  {
    name: "DNS_DATA_LABEL",
    pattern: /\b(?:dig|nslookup|host)\b[^\n]{0,400}?(?:\$\((?:(?!\$\()[^)\n]){0,200}\)|\$\{?\w{1,100}\}?|\{\w{1,100}\})\.[\w-]{1,255}\.[\w.-]+/g,
    severity: "medium",
    category: "data_exfiltration",
    title: "Data carried in a DNS name",
    codeOnly: true,
    description: "Puts a variable or command output into a hostname it looks up, which sends that value to whoever runs the domain's name server.",
    fix: "Look up fixed hostnames only.",
  },
  {
    name: "PASTEBIN_FETCH",
    pattern: /pastebin\.com|paste\.ee|hastebin\.com|ghostbin\.|dpaste\./gi,
    severity: "high",
    category: "data_exfiltration",
    title: "Pastebin service usage",
    description: "References paste services commonly used to host malicious payloads or receive exfiltrated data.",
    fix: "Host code in a version-controlled repository (GitHub, GitLab) instead of paste services.",
  },
  {
    name: "SUSPICIOUS_TLD",
    pattern: /https?:\/\/[^\s"']{0,500}\.(tk|ml|ga|cf|gq|top|xyz|pw|cc|ws|buzz)\b/gi,
    severity: "high",
    category: "data_exfiltration",
    title: "Suspicious TLD",
    description: "URL uses a top-level domain frequently associated with malicious infrastructure.",
    fix: "Use URLs from well-known, reputable domains instead of suspicious TLDs.",
  },
  {
    name: "URL_SHORTENER",
    pattern: /bit\.ly|tinyurl\.com|t\.co\/|goo\.gl|is\.gd|buff\.ly|ow\.ly|rb\.gy/gi,
    severity: "high",
    category: "obfuscation",
    title: "URL shortener",
    description: "Uses URL shorteners to hide the real destination of links.",
    fix: "Use the full, unshortened URL so users can verify the destination.",
  },
  {
    name: "RAW_SOCKET",
    pattern: re(["new\\s+Soc", "ket|net\\.conn", "ect|dgram\\.create", "Socket"], "gi"),
    severity: "high",
    category: "data_exfiltration",
    title: "Raw socket connection",
    description: "Creates raw network sockets which can bypass HTTP monitoring.",
    codeOnly: true,
    fix: "Use standard HTTP libraries (fetch, axios) instead of raw sockets for network communication.",
  },

  // ═══════════════════════════════════════════════════════
  // MEDIUM: Social engineering
  // ═══════════════════════════════════════════════════════
  {
    name: "PREREQUISITE_INSTALL",
    pattern: /prerequisite|install.{0,200}first|run.{0,200}before|required.{0,200}dependency/gi,
    severity: "medium",
    category: "social_engineering",
    title: "Prerequisite install trick",
    description: "Instructs users to install prerequisites — common social engineering tactic.",
    fix: "Declare dependencies in `metadata.openclaw.requires.bins` instead of instructing manual installs.",
  },
  {
    name: "COPY_PASTE_COMMAND",
    pattern: /copy.{0,80}paste.{0,80}terminal|run.{0,80}this.{0,80}command/gi,
    severity: "medium",
    category: "social_engineering",
    title: "Copy-paste command instruction",
    description: "Instructs users to copy-paste commands into their terminal.",
    fix: "Put commands in code blocks with proper context instead of copy-paste instructions.",
  },
  {
    name: "FAKE_DEPENDENCY",
    pattern: /openclaw-core|moltbot-runtime|clawdbot-helper/gi,
    severity: "medium",
    category: "social_engineering",
    title: "Fake dependency reference",
    description: "References fake packages that mimic official OpenClaw components.",
    fix: "Use only official OpenClaw packages from the verified registry.",
  },
  {
    name: "AUTHORITY_SPOOFING",
    pattern: /official\s+(openclaw|clawhub)|endorsed\s+by|verified\s+(skill|publisher)|from\s+the\s+openclaw\s+team/gi,
    severity: "medium",
    category: "social_engineering",
    title: "Authority spoofing",
    description: "Claims official endorsement or verification to gain trust.",
    fix: "Remove false authority claims — let the skill's quality speak for itself.",
  },
  {
    name: "URGENCY_MANIPULATION",
    pattern: /critical\s+update|security\s+patch|must\s+install\s+immediately|urgent.{0,200}update/gi,
    severity: "medium",
    category: "social_engineering",
    title: "Urgency manipulation",
    description: "Creates false urgency to pressure users into installing without review.",
    fix: "Remove urgency language — let users evaluate the skill at their own pace.",
  },

  // ═══════════════════════════════════════════════════════
  // MEDIUM: Prompt injection
  // ═══════════════════════════════════════════════════════
  {
    name: "IGNORE_INSTRUCTIONS",
    pattern: /ignore\s+(all\s+)?previous\s+instructions/gi,
    severity: "medium",
    category: "prompt_injection",
    title: "Prompt injection — ignore instructions",
    description: "Attempts to override the AI agent's existing instructions.",
    fix: "Remove prompt injection attempts — skills should not try to override agent instructions.",
  },
  {
    name: "SYSTEM_OVERRIDE",
    pattern: /you\s+are\s+now|new\s+instructions|forget\s+everything/gi,
    severity: "medium",
    category: "prompt_injection",
    title: "Prompt injection — system override",
    description: "Attempts to redefine the AI agent's identity or instructions.",
    fix: "Remove system override attempts — skills should not alter agent identity.",
  },
  {
    name: "MEMORY_MANIPULATION",
    pattern: /SOUL\.md|MEMORY\.md|AGENTS\.md/gi,
    severity: "medium",
    category: "persistence",
    title: "Memory/personality file manipulation",
    description: "References core personality or memory files, may attempt persistence.",
    fix: "Remove references to agent memory/personality files — skills should not modify agent state.",
  },
  {
    name: "JAILBREAK_ATTEMPT",
    pattern: /\bDAN\b|do\s+anything\s+now|developer\s+mode|evil\s+mode|bypass.{0,200}safety/gi,
    severity: "medium",
    category: "prompt_injection",
    title: "Jailbreak attempt",
    description: "Uses known jailbreak techniques (DAN, developer mode) to bypass safety constraints.",
    fix: "Remove jailbreak attempts — skills should work within the agent's safety constraints.",
  },
  {
    name: "ROLE_HIJACK",
    pattern: /(?:pretend|act|behave)\s+(?:you\s+are|as\s+if|to\s+be)\s+(?:a\s+)?(?:different|new|hacker|evil)/gi,
    severity: "medium",
    category: "prompt_injection",
    title: "Role hijacking",
    description: "Attempts to change the agent's persona to bypass safety restrictions.",
    fix: "Remove role hijacking attempts — skills should not alter the agent's persona.",
  },
  {
    name: "PROMPT_EXTRACTION",
    pattern: /(?:reveal|show|print|output|tell\s+me)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions|rules)/gi,
    severity: "medium",
    category: "prompt_injection",
    title: "System prompt extraction",
    description: "Attempts to extract the agent's system prompt or configuration.",
    fix: "Remove prompt extraction attempts — skills should not try to access system prompts.",
  },

  // ═══════════════════════════════════════════════════════
  // MEDIUM: Obfuscation
  // ═══════════════════════════════════════════════════════
  {
    name: "HEX_ENCODING",
    pattern: /\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){3,}/gi,
    severity: "medium",
    category: "obfuscation",
    title: "Hex-encoded payload",
    description: "Contains hex-encoded strings commonly used to hide malicious commands.",
    codeOnly: true,
    fix: "Replace hex-encoded strings with readable text so users can review the content.",
  },
  {
    name: "JS_OBFUSCATOR",
    pattern: /_0x[a-f0-9]{4,}|var\s+_0x/gi,
    severity: "medium",
    category: "obfuscation",
    title: "JavaScript obfuscator output",
    description: "Contains patterns from JavaScript obfuscation tools used to hide malicious code.",
    codeOnly: true,
    fix: "Provide readable, unobfuscated source code instead of obfuscated JavaScript.",
  },
  {
    name: "UNICODE_STEGANOGRAPHY",
    pattern: /[\u200B\u200C\u200D\u2060\uFEFF]{3,}/g,
    severity: "medium",
    category: "obfuscation",
    title: "Hidden zero-width characters",
    description: "Contains clusters of invisible zero-width Unicode characters that may hide instructions.",
    fix: "Remove zero-width characters — all content should be visible to users.",
  },
  {
    name: "RTL_OVERRIDE",
    pattern: /[\u202A\u202B\u202C\u202D\u202E\u2066\u2067\u2068\u2069]/g,
    severity: "medium",
    category: "obfuscation",
    title: "Bidirectional text override",
    description: "Contains Unicode bidi override characters that can reverse displayed text to hide real content.",
    fix: "Remove bidirectional text override characters — text direction should be natural.",
  },
  {
    name: "HTML_COMMENT_INJECTION",
    pattern: /<!--[\s\S]*?(?:ignore|instructions|system|override|secret)[\s\S]*?-->/gi,
    severity: "medium",
    category: "obfuscation",
    title: "Hidden HTML comment instruction",
    description: "Embeds instructions inside HTML comments that are invisible to users but read by agents.",
    fix: "Move instructions from HTML comments into visible content.",
  },
  {
    name: "STRING_CONCAT_OBFUSC",
    pattern: /["'][a-z]{1,3}["']\s*\+\s*["'][a-z]{1,3}["']\s*\+\s*["'][a-z]{1,3}["']/gi,
    severity: "medium",
    category: "obfuscation",
    title: "String concatenation obfuscation",
    description: "Builds commands via single-character string concatenation to evade pattern detection.",
    codeOnly: true,
    fix: "Use complete string literals instead of character-by-character concatenation.",
  },
  {
    name: "BUFFER_BASE64_DECODE",
    pattern: re(["Buf", "fer\\.from\\s*\\(.{0,200}['\"]base", "64['\"]\\)|at", "ob\\s*\\("], "gi"),
    severity: "critical",
    category: "obfuscation",
    title: "Buffer/atob encoded payload",
    description: "Decodes encoded content via Buffer.from() or atob(), often used to hide malicious payloads.",
    codeOnly: true,
    fix: "Include the decoded content directly so users can review it.",
  },
  {
    name: "STRING_FROMCHARCODE",
    pattern: re(["String\\.from", "CharCode\\s*\\("], "gi"),
    severity: "medium",
    category: "obfuscation",
    title: "String.fromCharCode usage",
    description: "Builds strings from character codes to evade static pattern detection.",
    codeOnly: true,
    fix: "Use plain string literals instead of String.fromCharCode().",
  },
  {
    name: "DYNAMIC_PROPERTY_ACCESS",
    pattern: /(?:process|global|window|globalThis)\s*\[\s*['"`]?\w*['"`]?\s*\+/gi,
    severity: "medium",
    category: "obfuscation",
    title: "Dynamic property access on globals",
    description: "Dynamically accesses global object properties via string concatenation to hide intent.",
    codeOnly: true,
    fix: "Use direct property access (e.g., `process.env`) instead of dynamic bracket notation.",
  },

  // ═══════════════════════════════════════════════════════
  // MEDIUM: Privilege escalation & system access
  // ═══════════════════════════════════════════════════════
  {
    name: "SUDO_USAGE",
    pattern: /sudo\s+(?!apt|dnf|yum|brew)/gi,
    severity: "medium",
    category: "privilege_escalation",
    title: "Sudo usage",
    description: "Requests elevated privileges — check if actually required for the task.",
    codeOnly: true,
    fix: "Remove sudo if not strictly necessary, or document why elevated privileges are required.",
  },
  {
    name: "CHMOD_DANGEROUS",
    pattern: /chmod\s+(?:777|a\+[rwx]|[+]s)/gi,
    severity: "medium",
    category: "privilege_escalation",
    title: "Dangerous file permissions",
    description: "Sets overly permissive file permissions (777) or setuid/setgid bits.",
    codeOnly: true,
    fix: "Use least-privilege permissions (e.g., `chmod 755` or `chmod 644`) instead of 777.",
  },
  // The next three are not in the context pass's dual-use categories on
  // purpose. Sudo and chmod 777 are ordinary and only count next to a sink; a
  // setuid bit, a new administrator account and a miner configuration are not
  // things an ordinary skill does, with or without one. They match in prose
  // too, because an instruction to run the command is the attack. Gaps are
  // bounded: an unbounded one rescans a long line from every `curl` on it.
  {
    name: "SETUID_BIT",
    pattern: re(["chm", "od\\s+(?:-[A-Za-z]+\\s+)*(?:[46][0-7]{3}|(?:[goa]{0,8}u[ugoa]{0,8})?\\+[rwxX]{0,8}s)\\b"], "g"),
    severity: "critical",
    category: "system_tampering",
    title: "Setuid bit set on a file",
    description: "Sets the setuid bit, so the file runs with its owner's privileges whoever starts it. This is how a local privilege escalation is left behind.",
    fix: "Remove the setuid bit. A skill that needs elevated rights should ask for them when it runs.",
  },
  {
    name: "WINDOWS_ACCOUNT_ADD",
    pattern: re(["net\\s+us", "er\\s+[^\\n|;&]{0,200}\\/add\\b|net\\s+local", "group\\s+\"?(?:administrators|remote desktop users)\"?\\s+[^\\n|;&]{0,200}\\/add\\b"], "gi"),
    severity: "critical",
    category: "system_tampering",
    title: "Windows account or administrator group change",
    description: "Creates a local Windows account or adds one to a privileged group, which leaves a way back into the machine.",
    fix: "Remove the account commands. A skill has no reason to create users or grant administrator rights.",
  },
  {
    name: "CRYPTO_MINER_CONFIG",
    // A configuration, a pool URL or a miner binary; a scanner's own signature
    // list (`xmrig|stratum\+tcp`) names these without being one.
    pattern: re(["[\"']nice", "hash[\"']\\s*:|strat", "um\\+(?:tcp|ssl):\\/\\/|[\"']?donate", "-level[\"']?\\s*[:=]|(?:\\.\\/|\\/)xm", "rig\\b"], "gi"),
    severity: "critical",
    category: "resource_abuse",
    title: "Cryptocurrency miner configuration",
    description: "Contains a mining pool URL, a miner configuration or a miner binary. A skill that mines uses the machine for someone else.",
    fix: "Remove the miner and its configuration.",
  },
  {
    name: "POWERSHELL_ENCODED",
    pattern: re(["power", "shell(?:\\.exe)?\\b[^\\n]{0,300}\\s-(?:e|ec|enc|encodedcommand)\\s+\\S"], "gi"),
    severity: "critical",
    category: "obfuscation",
    title: "Encoded PowerShell command",
    description: "Runs a base64-encoded PowerShell command, which hides what is executed from anyone reading the skill.",
    fix: "Write the command in plain text so it can be reviewed.",
  },
  {
    name: "SYSTEM_ACCOUNTS_UPLOAD",
    // The file has to be what is sent: an upload option, a redirect into a
    // socket client, a substituted read, or a local scp source. The path inside
    // a URL (`curl https://host/etc/passwd`) is a download and is not matched.
    pattern: re([
      "\\b(?:(?:curl\\b[^\\n|;&]{0,300}?(?:\\s(?:-[A-Za-z]{0,8}d|--data(?:-binary|-urlencode|-ascii)?)(?:\\s{1,20}|=)?[\"']?(?:\\w{1,100}=?)?@",
      "|\\s(?:-[A-Za-z]{0,8}F|--form)(?:\\s{1,20}|=)?[\"']?[^\\s\"'=]{1,100}=[@<]",
      "|\\s(?:-[A-Za-z]{0,8}T|--upload-file)(?:\\s{1,20}|=)?[\"']?)",
      "|wget\\b[^\\n|;&]{0,300}?\\s--post-file(?:\\s{1,20}|=)[\"']?",
      "|(?:curl|wget|nc|ncat)\\b[^\\n|;&]{0,300}?(?:\\$\\(|`)\\s{0,20}(?:(?:cat|base64|head|tail)\\s[^)`$\\n]{0,40}?|<\\s{0,20})",
      "|(?:nc|ncat)\\b[^\\n|;&]{0,300}?<\\s{0,20}[\"']?)\\/etc\\/(?:pass", "wd|sha", "dow)\\b",
      "|scp\\b[^\\n|;&]{0,300}?\\s[\"']?\\/etc\\/(?:pass", "wd|sha", "dow)[\"']?\\s{1,20}[^\\s|;&]{0,200}:)"], "g"),
    severity: "critical",
    category: "data_exfiltration",
    title: "System account file sent over the network",
    description: "Passes the system account database to a network client.",
    codeOnly: true,
    fix: "Remove the upload. Nothing a skill does needs the machine's account list on a remote host.",
  },
  {
    name: "CLOUD_METADATA_CREDENTIALS",
    pattern: re(["169\\.254\\.169\\.254\\/latest\\/meta-data\\/iam\\/security-cred", "entials|metadata\\.google\\.internal\\/computeMetadata\\/v1\\/instance\\/service-accounts\\/[^\\s\"'\\/]+\\/token"], "g"),
    severity: "critical",
    category: "credential_theft",
    title: "Cloud instance credentials read from the metadata service",
    description: "Requests the instance's temporary cloud credentials from the metadata endpoint.",
    codeOnly: true,
    fix: "Use the cloud SDK's default credential chain instead of reading the metadata endpoint directly.",
  },
  {
    name: "PATH_TRAVERSAL",
    pattern: /\.\.\//g,
    severity: "medium",
    category: "file_system",
    title: "Path traversal",
    description: "Uses relative path traversal (../) which could access files outside expected directories.",
    codeOnly: true,
    fix: "Use absolute paths or paths relative to the skill's working directory.",
  },

  // ═══════════════════════════════════════════════════════
  // LOW: Suspicious but not necessarily malicious
  // ═══════════════════════════════════════════════════════
  {
    name: "SHELL_EXEC",
    pattern: re(["child_", "process|ex", "ec\\(|spa", "wn\\("], "gi"),
    severity: "low",
    category: "code_execution",
    title: "Shell execution API",
    description: "Uses shell execution APIs — legitimate but worth noting.",
    codeOnly: true,
    fix: "If shell execution is needed, use execFile() with explicit arguments instead of exec() with string commands.",
  },
  {
    name: "NETWORK_REQUEST",
    pattern: /fetch\(|axios|node-fetch|got\(/gi,
    severity: "low",
    category: "network",
    title: "Network request API",
    description: "Makes network requests — legitimate but worth reviewing targets.",
    codeOnly: true,
    fix: "Document all network endpoints in the skill description so users can review them.",
  },
  {
    name: "FILE_WRITE",
    pattern: /fs\.write|writeFileSync/gi,
    severity: "low",
    category: "file_system",
    title: "File write operation",
    description: "Writes to the filesystem — check what files are being modified.",
    codeOnly: true,
    fix: "Document which files are written and why in the skill description.",
  },
  {
    name: "ENV_MODIFICATION",
    pattern: /process\.env\[|export\s+[A-Z_]+=|setenv/gi,
    severity: "low",
    category: "environment",
    title: "Environment variable modification",
    description: "Modifies environment variables which could affect other tools or processes.",
    codeOnly: true,
    fix: "Document env var modifications in the skill description and declare them in requires.env.",
  },
  {
    name: "WILDCARD_FILE_ACCESS",
    pattern: /\*\.(pem|key|p12|pfx|jks|keystore|ovpn|rdp)/gi,
    severity: "low",
    category: "credential_theft",
    title: "Sensitive file extension glob",
    description: "Globs for files with sensitive extensions (keys, certificates, VPN configs).",
    fix: "Reference specific files by name instead of using wildcard patterns on sensitive extensions.",
  },
  {
    name: "LARGE_BASE64_LITERAL",
    // The lookbehind starts a match only at the head of a run: without it every
    // position inside a shorter run is retried, which is quadratic in run length.
    pattern: /(?<![A-Za-z0-9+/=])[A-Za-z0-9+/=]{100,}/g,
    severity: "low",
    category: "obfuscation",
    title: "Large base64-like string",
    description: "Contains a long base64-like string that may be an encoded payload.",
    fix: "Include the decoded content directly or explain what the base64 string contains.",
  },
];

export const POPULAR_SKILLS = [
  "todoist-cli",
  "github-manager",
  "slack-assistant",
  "email-composer",
  "calendar-sync",
  "weather-forecast",
  "news-reader",
  "code-reviewer",
  "docker-helper",
  "aws-manager",
  "notion-sync",
  "jira-tracker",
  "spotify-controller",
  "home-assistant",
  "file-organizer",
  "pdf-reader",
  "translate-text",
  "image-generator",
  "web-scraper",
  "database-query",
  "git-assistant",
  "linux-admin",
  "python-helper",
  "react-builder",
  "api-tester",
  "markdown-editor",
  "csv-analyzer",
  "ssh-manager",
  "cron-scheduler",
  "log-analyzer",
];
