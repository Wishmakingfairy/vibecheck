"""
preflight AI/LLM Security Checker
16 checks for AI API key exposure, prompt injection, system prompt leaks, and LLM output safety.

Author: Haralds Gabrans
License: MIT
"""

import re
from typing import List
from checkers import CheckResult, Severity

CATEGORY = 'AI/LLM Security'

# AI API keys in frontend
AI_FRONTEND_KEY = re.compile(
    r'''(?i)(?:NEXT_PUBLIC_|VITE_|REACT_APP_|NUXT_PUBLIC_|EXPO_PUBLIC_)(?:OPENAI|ANTHROPIC|CLAUDE|COHERE|HUGGING|REPLICATE|TOGETHER|GROQ|MISTRAL|PERPLEXITY|AI)[_\-]?(?:API)?[_\-]?KEY''',
)

# Vector DB keys in frontend
VECTOR_DB_FRONTEND = re.compile(
    r'''(?i)(?:NEXT_PUBLIC_|VITE_|REACT_APP_)(?:PINECONE|WEAVIATE|QDRANT|CHROMA|MILVUS)[_\-]?(?:API)?[_\-]?KEY''',
)

# System prompt in client code
SYSTEM_PROMPT_CLIENT = re.compile(
    r'''(?i)(?:system[_\-]?(?:prompt|message|instruction)|systemMessage|system_content)\s*[:=]\s*[`'"]{1,3}[^`'"]{20,}''',
)
CLIENT_FILE = re.compile(r'(?i)(?:\.tsx?$|\.jsx?$|components?/|pages?/|app/|src/(?!server|api|lib/server))')

# Prompt injection - user input to LLM
PROMPT_INJECTION = re.compile(
    r'''(?i)(?:messages?\s*[:=].*\{.*role.*content.*(?:req\.|params\.|query\.|body\.|input|user)|prompt\s*[:=].*(?:req\.|params\.|query\.|body\.|input|user))''',
    re.DOTALL
)
INPUT_SANITIZE = re.compile(r'(?i)(?:sanitize|escape|validate|filter|DOMPurify|strip|clean)')

# LLM output as HTML
LLM_OUTPUT_HTML = re.compile(
    r'''(?i)(?:dangerouslySetInnerHTML|innerHTML|v-html|@html).*(?:completion|response|message|output|result|answer|reply|content)''',
    re.DOTALL
)

# No token/cost limits
AI_API_CALL = re.compile(
    r'''(?i)(?:openai|anthropic|client)\.(?:chat|completions?|messages?)\.create''',
)
TOKEN_LIMIT = re.compile(r'(?i)(?:max_tokens|maxTokens|max_completion_tokens|max_output_tokens)')

# Rate limiting on AI endpoints
AI_ENDPOINT = re.compile(
    r'''(?i)(?:app|router)\s*\.(?:post|get)\s*\(\s*['"](?:/api/(?:chat|ai|generate|complete|ask|prompt))['"]''',
)
RATE_LIMIT = re.compile(r'(?i)(?:rateLimit|rate_limit|throttle|limiter)')

# PII in prompts logged
PII_IN_LOG = re.compile(
    r'''(?i)(?:console\.log|logger\.|logging\.|print\().*(?:prompt|message|system_message|user_message|completion)''',
)

# Model endpoint without auth
MODEL_ENDPOINT = re.compile(
    r'''(?i)(?:app|router)\s*\.(?:post|get)\s*\(\s*['"](?:/api/(?:model|predict|infer|embed|generate))['"]''',
)
AUTH_MW = re.compile(r'(?i)(?:auth|authenticate|requireAuth|protect|middleware|guard)')

# Agentic loops without limits
AGENT_LOOP = re.compile(
    r'''(?i)(?:while\s*\(\s*(?:true|!done|running)|for\s*\(\s*;\s*;\s*\)|recursive.*(?:agent|tool|function))''',
)
RESOURCE_LIMIT = re.compile(r'(?i)(?:maxIterations|max_iterations|maxSteps|max_steps|timeout|AbortController|deadline)')

# Streaming output as raw HTML
STREAM_HTML = re.compile(
    r'''(?i)(?:stream|EventSource|ReadableStream|onmessage).*(?:innerHTML|dangerouslySetInnerHTML|v-html|document\.write)''',
    re.DOTALL
)


def check(content: str, file_path: str, config: dict = None) -> List[CheckResult]:
    """Run all AI/LLM security checks."""
    results = []

    # AI-003: AI API keys in frontend
    if AI_FRONTEND_KEY.search(content):
        results.append(CheckResult(
            check_id='AI-003',
            severity=Severity.CRITICAL,
            category=CATEGORY,
            message='AI service API key exposed in frontend environment variable. Anyone can use your API key and run up charges.',
            fix_suggestion='Move AI API calls to server-side API routes. Use /api/chat endpoint that proxies to OpenAI/Anthropic with your key server-side only.',
            cwe='CWE-798',
        ))

    # AI-011: Vector DB keys in frontend
    if VECTOR_DB_FRONTEND.search(content):
        results.append(CheckResult(
            check_id='AI-011',
            severity=Severity.CRITICAL,
            category=CATEGORY,
            message='Vector database API key exposed in frontend. Attackers can read/modify your embeddings and data.',
            fix_suggestion='Keep vector DB keys server-side. Create an API route that queries the vector DB and returns results to the client.',
            cwe='CWE-798',
        ))

    # AI-006: System prompt in client-side code
    if SYSTEM_PROMPT_CLIENT.search(content) and file_path and CLIENT_FILE.search(file_path):
        results.append(CheckResult(
            check_id='AI-006',
            severity=Severity.CRITICAL,
            category=CATEGORY,
            message='System prompt visible in client-side code. Users can see and manipulate your AI instructions.',
            fix_suggestion='Move system prompts to server-side only. Load from environment variables or a config file not served to clients.',
            cwe='CWE-200',
        ))

    # AI-001: Prompt injection
    if PROMPT_INJECTION.search(content) and not INPUT_SANITIZE.search(content):
        results.append(CheckResult(
            check_id='AI-001',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='User input passed directly to LLM prompt without sanitization. Vulnerable to prompt injection.',
            fix_suggestion='Sanitize user input before including in prompts. Use structured message format with clear role separation. Consider input validation.',
            cwe='CWE-74',
        ))

    # AI-002: LLM output rendered as HTML
    if LLM_OUTPUT_HTML.search(content):
        results.append(CheckResult(
            check_id='AI-002',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='LLM output rendered as raw HTML. AI can be tricked into generating malicious HTML/scripts.',
            fix_suggestion='Sanitize AI output before rendering: DOMPurify.sanitize(aiResponse). Or render as plain text / markdown.',
            cwe='CWE-79',
        ))

    # AI-004: No token limits
    if AI_API_CALL.search(content) and not TOKEN_LIMIT.search(content):
        results.append(CheckResult(
            check_id='AI-004',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='AI API call without max_tokens limit. A single request could consume your entire budget.',
            fix_suggestion='Set max_tokens: client.chat.completions.create({ ..., max_tokens: 1000 }). Also set billing alerts on your AI provider dashboard.',
            cwe='CWE-770',
        ))

    # AI-007: No rate limiting on AI endpoints
    if AI_ENDPOINT.search(content) and not RATE_LIMIT.search(content):
        results.append(CheckResult(
            check_id='AI-007',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='AI endpoint without rate limiting. Attackers can drain your API credits with automated requests.',
            fix_suggestion='Add rate limiting: app.use("/api/chat", rateLimit({ windowMs: 60000, max: 10 })). Also add per-user limits.',
            cwe='CWE-770',
        ))

    # AI-008: PII in logged prompts
    if PII_IN_LOG.search(content):
        results.append(CheckResult(
            check_id='AI-008',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='AI prompts/completions logged to console. May contain user PII, violating privacy regulations.',
            fix_suggestion='Redact PII before logging. Log only metadata (token count, latency, model). Use structured logging with PII filters.',
            cwe='CWE-532',
        ))

    # AI-014: Model endpoint without auth
    if MODEL_ENDPOINT.search(content) and not AUTH_MW.search(content):
        results.append(CheckResult(
            check_id='AI-014',
            severity=Severity.CRITICAL,
            category=CATEGORY,
            message='AI model/prediction endpoint without authentication. Anyone can access your model and consume resources.',
            fix_suggestion='Add authentication: app.post("/api/predict", requireAuth, handler). Use API keys or JWT tokens.',
            cwe='CWE-306',
        ))

    # AI-015: Agentic loops without limits
    if AGENT_LOOP.search(content) and not RESOURCE_LIMIT.search(content):
        results.append(CheckResult(
            check_id='AI-015',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='AI agent loop without iteration/resource limits. Can consume unlimited tokens and compute.',
            fix_suggestion='Add limits: let iterations = 0; while (!done && iterations++ < maxIterations) { ... }. Add AbortController with timeout.',
            cwe='CWE-400',
        ))

    # AI-016: Streaming output as raw HTML
    if STREAM_HTML.search(content):
        results.append(CheckResult(
            check_id='AI-016',
            severity=Severity.CRITICAL,
            category=CATEGORY,
            message='AI streaming response rendered as raw HTML. Each chunk could contain injected scripts.',
            fix_suggestion='Sanitize each stream chunk before rendering. Use a markdown renderer with XSS protection instead of raw HTML.',
            cwe='CWE-79',
        ))

    return results
