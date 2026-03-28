# AI/LLM Security Checks Reference

11 active checks out of 16 reserved IDs: AI-001, AI-002, AI-003, AI-004, AI-006, AI-007, AI-008, AI-011, AI-014, AI-015, AI-016.

---

### AI-001: Prompt Injection
- **Severity:** WARNING
- **CWE:** CWE-74 (Improper Neutralization of Special Elements in Output Used by a Downstream Component)
- **Pattern:** `(?i)(?:messages?\s*[:=].*\{.*role.*content.*(?:req\.|params\.|query\.|body\.|input|user)|prompt\s*[:=].*(?:req\.|params\.|query\.|body\.|input|user))` (DOTALL)
- **Negated by:** `(?i)(?:sanitize|escape|validate|filter|DOMPurify|strip|clean)` present in the same file.
- **Why:** Unsanitized user input in LLM prompts allows attackers to override system instructions, extract data, or make the AI perform unintended actions.
- **Fix:**
```js
// Bad
const messages = [
  { role: "system", content: systemPrompt },
  { role: "user", content: req.body.input }
];

// Good
const sanitizedInput = sanitizeInput(req.body.input);
const messages = [
  { role: "system", content: systemPrompt },
  { role: "user", content: sanitizedInput }
];

function sanitizeInput(input) {
  // Remove common injection patterns
  const cleaned = input.replace(/ignore previous|system:|<\|im_sep\|>/gi, "");
  // Limit length
  return cleaned.slice(0, 2000);
}
```
- **False positives:** The DOTALL flag means `role` and `content` can be on different lines. Any file that builds LLM messages from request params will trigger unless a sanitization keyword appears somewhere in the file, even if that sanitization is for something unrelated.

---

### AI-002: LLM Output Rendered as Raw HTML
- **Severity:** WARNING
- **CWE:** CWE-79 (Cross-site Scripting)
- **Pattern:** `(?i)(?:dangerouslySetInnerHTML|innerHTML|v-html|@html).*(?:completion|response|message|output|result|answer|reply|content)` (DOTALL)
- **Why:** An LLM can be tricked into generating `<script>` tags, event handlers, or other malicious HTML that executes in users' browsers.
- **Fix:**
```jsx
// Bad
<div dangerouslySetInnerHTML={{ __html: aiResponse }} />

// Good - use a markdown renderer with sanitization
import DOMPurify from "dompurify";
import { marked } from "marked";

<div
  dangerouslySetInnerHTML={{
    __html: DOMPurify.sanitize(marked(aiResponse))
  }}
/>

// Better - render as plain text
<pre>{aiResponse}</pre>
```
- **False positives:** Fires if `innerHTML` and a word like `content` appear in the same file (DOTALL matching), even if they are unrelated. The generic terms `content`, `message`, `result` increase false positive rate.

---

### AI-003: AI API Key in Frontend Environment Variable
- **Severity:** CRITICAL
- **CWE:** CWE-798 (Use of Hard-coded Credentials)
- **Pattern:** `(?i)(?:NEXT_PUBLIC_|VITE_|REACT_APP_|NUXT_PUBLIC_|EXPO_PUBLIC_)(?:OPENAI|ANTHROPIC|CLAUDE|COHERE|HUGGING|REPLICATE|TOGETHER|GROQ|MISTRAL|PERPLEXITY|AI)[_\-]?(?:API)?[_\-]?KEY`
- **Why:** Frontend environment variables are embedded in the client bundle. Anyone can extract your API key from the browser, use it, and run up charges or access your data.
- **Fix:**
```js
// Bad - .env
NEXT_PUBLIC_OPENAI_API_KEY=sk-...

// Good - server-side API route
// .env (no NEXT_PUBLIC_ prefix)
OPENAI_API_KEY=sk-...

// app/api/chat/route.ts
export async function POST(req) {
  const { messages } = await req.json();
  const response = await openai.chat.completions.create({
    model: "gpt-4",
    messages,
  });
  return Response.json(response);
}
```
- **False positives:** Fires on any file containing the env var name, including documentation, `.env.example` files, and migration scripts that rename variables. The check does not verify whether an actual key value is present.

---

### AI-004: No Token Limit on AI API Call
- **Severity:** WARNING
- **CWE:** CWE-770 (Allocation of Resources Without Limits or Throttling)
- **Pattern (API call):** `(?i)(?:openai|anthropic|client)\.(?:chat|completions?|messages?)\.create`
- **Negated by:** `(?i)(?:max_tokens|maxTokens|max_completion_tokens|max_output_tokens)` present in the same file.
- **Why:** Without `max_tokens`, a single request can generate an unbounded response, consuming your entire API budget.
- **Fix:**
```js
// Bad
const response = await openai.chat.completions.create({
  model: "gpt-4",
  messages,
});

// Good
const response = await openai.chat.completions.create({
  model: "gpt-4",
  messages,
  max_tokens: 1000,
});
```
- **False positives:** A file with `max_tokens` set on one call suppresses the finding for all calls in that file, even if other calls lack it. Conversely, a wrapper function that sets `max_tokens` in a different file will not suppress the check.

---

### AI-006: System Prompt in Client-Side Code
- **Severity:** CRITICAL
- **CWE:** CWE-200 (Exposure of Sensitive Information)
- **Pattern:** `(?i)(?:system[_\-]?(?:prompt|message|instruction)|systemMessage|system_content)\s*[:=]\s*[`'"]{1,3}[^`'"]{20,}`
- **File gate:** Only fires when the file path matches `(?i)(?:\.tsx?$|\.jsx?$|components?/|pages?/|app/|src/(?!server|api|lib/server))`.
- **Why:** System prompts contain your AI's instructions, guardrails, and sometimes proprietary logic. Exposing them lets users bypass safety measures and steal your prompt engineering.
- **Fix:**
```js
// Bad - in components/Chat.tsx
const systemPrompt = `You are a helpful assistant that...`;

// Good - in app/api/chat/route.ts (server-side)
const systemPrompt = process.env.SYSTEM_PROMPT;
// Or load from a config file not served to clients
```
- **False positives:** The file path gate excludes `src/server`, `src/api`, and `src/lib/server`. May still fire on shared utility files imported by both client and server. The 20+ character minimum for the prompt content reduces noise from short variable assignments.

---

### AI-007: AI Endpoint Without Rate Limiting
- **Severity:** WARNING
- **CWE:** CWE-770 (Allocation of Resources Without Limits or Throttling)
- **Pattern (endpoint):** `(?i)(?:app|router)\s*\.(?:post|get)\s*\(\s*['"](?:/api/(?:chat|ai|generate|complete|ask|prompt))['"]`
- **Negated by:** `(?i)(?:rateLimit|rate_limit|throttle|limiter)` present in the same file.
- **Why:** AI endpoints are expensive. Without rate limiting, an attacker can drain your API credits with a simple loop.
- **Fix:**
```js
import rateLimit from "express-rate-limit";

const aiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // 10 requests per minute
  message: "Too many requests, please try again later.",
});

app.post("/api/chat", aiLimiter, requireAuth, chatHandler);
```
- **False positives:** Rate limiting applied at the infrastructure level (nginx, API gateway, Cloudflare) will not be detected. The check only looks for rate limit keywords in the same source file.

---

### AI-008: PII in Logged Prompts
- **Severity:** WARNING
- **CWE:** CWE-532 (Insertion of Sensitive Information into Log File)
- **Pattern:** `(?i)(?:console\.log|logger\.|logging\.|print\().*(?:prompt|message|system_message|user_message|completion)`
- **Why:** Prompts and completions often contain user PII (names, emails, health data). Logging them creates GDPR/CCPA liability and data breach risk.
- **Fix:**
```js
// Bad
console.log("Prompt:", prompt);
console.log("Completion:", completion);

// Good - log metadata only
logger.info({
  model: "gpt-4",
  tokens_used: response.usage.total_tokens,
  latency_ms: Date.now() - startTime,
  user_id: hashedUserId,
});
```
- **False positives:** Fires on any log statement that references a variable named `prompt`, `message`, or `completion`, even if the variable contains no PII (e.g., logging a prompt template without user data).

---

### AI-011: Vector DB Key in Frontend
- **Severity:** CRITICAL
- **CWE:** CWE-798 (Use of Hard-coded Credentials)
- **Pattern:** `(?i)(?:NEXT_PUBLIC_|VITE_|REACT_APP_)(?:PINECONE|WEAVIATE|QDRANT|CHROMA|MILVUS)[_\-]?(?:API)?[_\-]?KEY`
- **Why:** Vector DB keys give read/write access to your embeddings. An attacker can read your data, poison your vector store, or delete indexes.
- **Fix:**
```js
// Bad
NEXT_PUBLIC_PINECONE_API_KEY=abc123

// Good - server-side API route
// .env (no public prefix)
PINECONE_API_KEY=abc123

// app/api/search/route.ts
export async function POST(req) {
  const { query } = await req.json();
  const embedding = await getEmbedding(query);
  const results = await pinecone.query({ vector: embedding, topK: 5 });
  return Response.json(results);
}
```
- **False positives:** Same as AI-003. Fires on variable name presence, not actual key values. Documentation and example files trigger the check.

---

### AI-014: Model Endpoint Without Authentication
- **Severity:** CRITICAL
- **CWE:** CWE-306 (Missing Authentication for Critical Function)
- **Pattern (endpoint):** `(?i)(?:app|router)\s*\.(?:post|get)\s*\(\s*['"](?:/api/(?:model|predict|infer|embed|generate))['"]`
- **Negated by:** `(?i)(?:auth|authenticate|requireAuth|protect|middleware|guard)` present in the same file.
- **Why:** Unauthenticated model endpoints let anyone run inference on your infrastructure, consuming GPU/API resources and potentially accessing training data.
- **Fix:**
```js
// Bad
app.post("/api/predict", async (req, res) => {
  const result = await model.predict(req.body.input);
  res.json(result);
});

// Good
app.post("/api/predict", requireAuth, apiKeyLimit, async (req, res) => {
  const result = await model.predict(req.body.input);
  res.json(result);
});
```
- **False positives:** Auth middleware applied at a higher level (e.g., `app.use(requireAuth)` in a separate file) will not be detected. The keyword match is broad; an unrelated `guard` import suppresses the finding.

---

### AI-015: Agentic Loop Without Resource Limits
- **Severity:** WARNING
- **CWE:** CWE-400 (Uncontrolled Resource Consumption)
- **Pattern (loop):** `(?i)(?:while\s*\(\s*(?:true|!done|running)|for\s*\(\s*;\s*;\s*\)|recursive.*(?:agent|tool|function))`
- **Negated by:** `(?i)(?:maxIterations|max_iterations|maxSteps|max_steps|timeout|AbortController|deadline)` present in the same file.
- **Why:** An AI agent loop without limits can run indefinitely, making unbounded API calls and consuming unlimited tokens and compute.
- **Fix:**
```js
// Bad
while (!done) {
  const result = await agent.step();
  done = result.finished;
}

// Good
const controller = new AbortController();
const timeout = setTimeout(() => controller.abort(), 30000);
let iterations = 0;
const maxIterations = 10;

while (!done && iterations++ < maxIterations) {
  const result = await agent.step({ signal: controller.signal });
  done = result.finished;
}
clearTimeout(timeout);
```
- **False positives:** Any `while(true)` loop triggers the check, even if unrelated to AI agents (e.g., event loops, server listen loops). The negation keywords are generic enough that a `setTimeout` for an unrelated purpose would suppress the finding.

---

### AI-016: Streaming Output Rendered as Raw HTML
- **Severity:** CRITICAL
- **CWE:** CWE-79 (Cross-site Scripting)
- **Pattern:** `(?i)(?:stream|EventSource|ReadableStream|onmessage).*(?:innerHTML|dangerouslySetInnerHTML|v-html|document\.write)` (DOTALL)
- **Why:** Each chunk of a streaming AI response can contain injected HTML/JS. Because chunks arrive incrementally, standard sanitization that runs once on the final output misses mid-stream injections.
- **Fix:**
```jsx
// Bad
source.onmessage = (event) => {
  container.innerHTML += event.data;
};

// Good
import DOMPurify from "dompurify";

source.onmessage = (event) => {
  const clean = DOMPurify.sanitize(event.data);
  container.innerHTML = DOMPurify.sanitize(container.innerHTML + clean);
};

// Better - use a markdown renderer that sanitizes per-chunk
import { marked } from "marked";
let buffer = "";
source.onmessage = (event) => {
  buffer += event.data;
  container.innerHTML = DOMPurify.sanitize(marked(buffer));
};
```
- **False positives:** DOTALL flag means `stream` and `innerHTML` can match across many lines, even if unrelated. A file with a ReadableStream for file uploads and an unrelated innerHTML assignment would trigger.

---

## Reserved IDs (not yet implemented)

| ID | Planned Check |
|----|--------------|
| AI-005 | Tool/function call output not validated |
| AI-009 | Embedding model API key shared with completion model |
| AI-010 | RAG context injection (retrieval results not sandboxed) |
| AI-012 | Model name from user input (model switching attack) |
| AI-013 | Fine-tuned model endpoint without access control |
