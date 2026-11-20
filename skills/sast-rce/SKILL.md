---
name: sast-rce
description: >-
  Find remote code execution in source: OS command injection through exec, system or
  shell-enabled subprocess, eval-like sinks, unsafe deserialization with pickle,
  ObjectInputStream or PHP unserialize, and dynamic require or import. Use when asked
  about command injection or deserialization RCE. Do not use for template injection - use
  sast-ssti.
mitre_attack: [T1190, T1059]
---

# Remote Code Execution (RCE) Detection

You are performing a focused security assessment to find Remote Code Execution vulnerabilities in a codebase. This skill uses a three-phase approach with subagents: **recon** (find dangerous execution sinks), **batched verify** (trace whether user-supplied input reaches each sink in parallel batches of 3), and **merge** (consolidate batch results into the final report).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What is Remote Code Execution

Remote Code Execution (RCE) occurs when an attacker can cause the application to execute arbitrary OS commands or application-level code that they control. This is typically the highest-severity vulnerability class, often resulting in complete server compromise.

RCE arises from three primary root causes:

1. **OS Command Injection**: User input is embedded unsafely into an OS command string, allowing shell metacharacters to inject additional commands.
2. **Code Injection (eval-like)**: User input is passed to functions that interpret it as executable code (`eval`, `exec`, `Function()`, etc.).
3. **Unsafe Deserialization**: User-supplied serialized data is deserialized using a gadget-prone deserializer, triggering arbitrary code execution via crafted payloads.

### What RCE IS

- Passing user input directly or indirectly into OS command execution functions with shell interpretation enabled
- Using `eval()`, `exec()`, `Function()`, or equivalent constructs with user-controlled strings
- Deserializing user-supplied bytes/strings with inherently unsafe deserializers (pickle, PHP unserialize, Java native serialization, Ruby Marshal, etc.)
- Using `yaml.load()` without a safe loader on user-supplied content
- Dynamic `require()`/`import()` with user-controlled module paths
- PHP file inclusion (`include`/`require`) with user-controlled paths

### What RCE is NOT

Do not flag these as RCE:

- **SSRF**: Making HTTP requests to attacker-controlled URLs — different vulnerability class (no code execution)
- **Path Traversal**: Reading/writing arbitrary files — separate class (unless the read file is then executed/deserialized)
- **SSTI**: Template injection via template engines — a separate though related class; flag as SSTI, not RCE
- **XSS**: JavaScript execution in a victim's browser — client-side only, not server-side RCE
- **SQL Injection**: Injecting into database queries — different class (even if `xp_cmdshell` can lead to OS commands, flag it as SQLi)
- **Safe subprocess list-form calls**: `subprocess.run(["ls", user_arg])` with a list and no `shell=True` — arguments are passed directly to the OS without shell expansion; not vulnerable to command injection
- **Safe deserialization**: `json.loads()`, `yaml.safe_load()`, `xml.etree.ElementTree.parse()` — these formats have no code execution semantics

### Patterns That Prevent RCE

When you see these patterns, the code is likely **not vulnerable**:

**1. Subprocess list form without shell interpretation**
```
# Python — list args, no shell=True
subprocess.run(["convert", "-resize", size, input_file, output_file])
subprocess.Popen(["git", "clone", repo_url])

# Node.js — spawn with separate args (no shell)
child_process.spawn("ffmpeg", ["-i", inputFile, outputFile])

# Java — ProcessBuilder with list
new ProcessBuilder("ls", "-la", dir).start()

# Ruby — system() with multiple args (not a single interpolated string)
system("ffmpeg", "-i", "input.mp4", "-f", format, "output")
```

**2. Safe deserialization formats**
```
# Python — JSON instead of pickle
import json
data = json.loads(user_input)  # no code execution semantics

# Python — safe YAML loader
import yaml
data = yaml.safe_load(user_input)  # restricts to basic types only

# Java — Jackson without enableDefaultTyping, with concrete target type
ObjectMapper mapper = new ObjectMapper();
MyClass obj = mapper.readValue(json, MyClass.class);  # safe
```

**3. Strict allowlist before command construction**
```
# Python — allowlist for dynamic arguments
ALLOWED_FORMATS = {"png", "jpg", "webp"}
if fmt not in ALLOWED_FORMATS:
    return abort(400)
subprocess.run(["convert", infile, f"output.{fmt}"])

# Node.js — allowlist for dynamic args
const ALLOWED_COMMANDS = ['ls', 'pwd'];
if (!ALLOWED_COMMANDS.includes(cmd)) return res.status(400).end();
spawn(cmd, []);
```

---

## Reference index

Deep detail for this skill lives in `references/`; open the file that matches
the task instead of loading everything.

| File | Covers |
|------|--------|
| `references/01-vulnerable-vs-secure-examples.md` | Vulnerable vs. Secure Examples |
| `references/02-execution.md` | Execution; Important Reminders |
