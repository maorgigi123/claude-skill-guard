/**
 * The rule engine: a set of regex-based rules used to detect risky or
 * suspicious patterns inside Claude Skill files.
 */

import { Rule } from "./types";

export const rules: Rule[] = [
  {
    id: "rm-rf",
    title: "Recursive force delete (rm -rf)",
    severity: "critical",
    pattern: /\brm\s+(?:-[a-zA-Z]*\s+)*-?[a-zA-Z]*r[a-zA-Z]*f|\brm\s+-rf\b|\brm\s+-fr\b/,
    description:
      "Recursively and forcibly deletes files/directories. Can destroy data or wipe the system.",
  },
  {
    id: "curl-pipe-bash",
    title: "Pipe curl output to a shell (curl | bash)",
    severity: "critical",
    pattern: /\bcurl\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b/,
    description:
      "Downloads and immediately executes a remote script. Classic remote code execution vector.",
  },
  {
    id: "wget-pipe-sh",
    title: "Pipe wget output to a shell (wget | sh)",
    severity: "critical",
    pattern: /\bwget\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b/,
    description:
      "Downloads and immediately executes a remote script. Classic remote code execution vector.",
  },
  {
    id: "sudo",
    title: "Privilege escalation (sudo)",
    severity: "high",
    pattern: /\bsudo\b/,
    description:
      "Runs a command with elevated privileges. Should be reviewed carefully in skill content.",
  },
  {
    id: "chmod-exec",
    title: "Make file executable (chmod +x)",
    severity: "medium",
    pattern: /\bchmod\s+(?:-[a-zA-Z]+\s+)*\+x\b|\bchmod\s+(?:-[a-zA-Z]+\s+)*[0-7]*[1357][0-7]*\b/,
    description:
      "Marks a file as executable, often a precursor to running a dropped or downloaded binary/script.",
  },
  {
    id: "child-process",
    title: "Node child_process usage",
    severity: "high",
    pattern: /\b(?:require\(\s*['"]child_process['"]\s*\)|from\s+['"]child_process['"]|import\s+.*child_process)/,
    description:
      "Imports Node's child_process module, which can run arbitrary system commands.",
  },
  {
    id: "exec-spawn",
    title: "Process exec/spawn call",
    severity: "high",
    pattern: /\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)\s*\(/,
    description:
      "Spawns or executes an external process. Can run arbitrary commands, especially with unsanitized input.",
  },
  {
    id: "process-env",
    title: "Environment variable access (process.env)",
    severity: "low",
    pattern: /\bprocess\.env\b/,
    description:
      "Reads environment variables, which may contain secrets or credentials.",
  },
  {
    id: "dotenv-file",
    title: "Reference to .env file",
    severity: "medium",
    pattern: /(?<![\w./-])\.env(?:\.[a-zA-Z0-9_-]+)?\b/,
    description:
      "References a .env file, a common location for secrets and API keys.",
  },
  {
    id: "ssh-dir",
    title: "Access to ~/.ssh",
    severity: "high",
    pattern: /(?:~|\$HOME|\/home\/[^/\s]+|\/Users\/[^/\s]+)\/\.ssh\b|(?<![\w-])\.ssh\/(?:id_|authorized_keys|known_hosts|config)/,
    description:
      "Accesses the SSH directory, which holds private keys and trusted hosts.",
  },
  {
    id: "private-key",
    title: "Private key material",
    severity: "critical",
    pattern: /-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP|ENCRYPTED)?\s*PRIVATE KEY-----|\bid_(?:rsa|dsa|ecdsa|ed25519)\b/,
    description:
      "Embeds or references private key material. Secrets should never live in skill files.",
  },
  {
    id: "external-network-call",
    title: "External network call (curl/fetch/axios)",
    severity: "medium",
    pattern: /\b(?:curl|wget)\s+[^\n]*\bhttps?:\/\/|\bfetch\s*\(\s*['"`]https?:\/\/|\baxios\b[^\n]*\bhttps?:\/\/|\baxios\.(?:get|post|put|delete|patch|request)\s*\(/,
    description:
      "Makes an outbound network request, which could exfiltrate data or pull remote payloads.",
  },
  {
    id: "prompt-injection",
    title: "Prompt injection phrasing",
    severity: "high",
    pattern: /\bignore\s+(?:all\s+)?(?:previous|prior|above|earlier|the\s+previous)\s+instructions?\b|\bdisregard\s+(?:all\s+)?(?:previous|prior|above|earlier)\b|\byou\s+are\s+now\s+(?:a|an|in)\b|\bact\s+as\s+(?:if|though)\b|\bdo\s+not\s+(?:tell|inform|reveal)\s+(?:the\s+)?(?:user|anyone)\b/i,
    description:
      "Contains language commonly used to hijack or override an AI agent's instructions.",
  },
];

/** Look up a rule by its id. */
export function getRule(id: string): Rule | undefined {
  return rules.find((r) => r.id === id);
}
