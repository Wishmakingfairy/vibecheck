# Business Logic Checks

6 checks for race conditions, missing idempotency, negative values, sequential IDs, and rate limits.

Source: `checkers/business_logic.py`

---

### BIZ-001: Race Condition in Payment/Transaction
- **Severity:** WARNING
- **CWE:** CWE-362 (Concurrent Execution Using Shared Resource with Improper Synchronization)
- **Pattern:** Triggers when `(?i)(?:payment|charge|transfer|transaction|balance|withdraw|deposit|debit|credit)` matches AND `(?i)(?:mutex|lock|semaphore|synchronized|atomic|serializable|FOR\s+UPDATE|LOCK\s+IN|advisory.?lock|redlock|bullmq)` is absent from the file.
- **Why:** Two concurrent requests can both read the same balance, both pass validation, and both deduct. Result: double-spending, negative balances, or duplicate transfers.
- **Fix:**
```javascript
// Bad
const balance = await getBalance(userId);
if (balance >= amount) {
  await deductBalance(userId, amount);
}

// Good: database-level lock
await db.transaction(async (tx) => {
  const [row] = await tx.query("SELECT balance FROM accounts WHERE id = $1 FOR UPDATE", [userId]);
  if (row.balance >= amount) {
    await tx.query("UPDATE accounts SET balance = balance - $1 WHERE id = $2", [amount, userId]);
  }
});
```
- **False positives:** Files that mention "transaction" in a non-financial context (e.g., database transaction wrappers, logging). The check casts a wide net on financial keywords.

---

### BIZ-002: Missing Idempotency Key on Payment Routes
- **Severity:** WARNING
- **CWE:** CWE-362 (Concurrent Execution Using Shared Resource with Improper Synchronization)
- **Pattern:** Triggers when `(?i)(?:payment|charge|transfer|order)` matches AND `(?i)idempotency` is absent from the file.
- **Why:** Network timeouts cause clients to retry. Without idempotency keys, retries create duplicate charges. Stripe, PayPal, and most payment APIs support idempotency keys natively.
- **Fix:**
```javascript
// Bad
app.post("/api/charge", async (req, res) => {
  await stripe.charges.create({ amount: req.body.amount });
});

// Good
app.post("/api/charge", async (req, res) => {
  const idempotencyKey = req.headers["idempotency-key"];
  if (!idempotencyKey) return res.status(400).json({ error: "Idempotency-Key header required" });

  const existing = await cache.get(`idem:${idempotencyKey}`);
  if (existing) return res.json(existing);

  const charge = await stripe.charges.create(
    { amount: req.body.amount },
    { idempotencyKey }
  );
  await cache.set(`idem:${idempotencyKey}`, charge, "EX", 86400);
  res.json(charge);
});
```
- **False positives:** Files that handle order display, order history, or payment status checks (read-only) rather than payment creation. Any file mentioning "payment" or "order" without the word "idempotency" triggers this.

---

### BIZ-003: Negative Quantity Without Validation
- **Severity:** WARNING
- **CWE:** CWE-20 (Improper Input Validation)
- **Pattern:** Triggers when `(?i)(?:quantity|amount|price|qty)` matches AND `(?i)(?:Math\.abs|Math\.max|>= *0|> *0|positive|unsigned|min\s*[:=]\s*0|min\s*[:=]\s*1|negative|isNegative)` is absent from the file.
- **Why:** Submitting quantity: -5 in a cart can result in credits instead of charges. Negative prices bypass payment. This is one of the most common e-commerce vulnerabilities.
- **Fix:**
```javascript
// Bad
const total = quantity * price;

// Good: validate at input boundary
const schema = z.object({
  quantity: z.number().int().min(1),
  price: z.number().positive(),
});
const { quantity, price } = schema.parse(req.body);
```
- **False positives:** Files that define types/interfaces with quantity fields but do validation in a separate validation layer. Schema definition files, TypeScript type declarations, and database migration files may trigger this.

---

### BIZ-004: Sequential IDs Exposing Resources
- **Severity:** WARNING
- **CWE:** CWE-330 (Use of Insufficiently Random Values)
- **Pattern:** Triggers when `(?i)(?:app|router|server)\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*['"].*/:id['"]` matches AND `(?i)(?:autoIncrement|auto_increment|SERIAL|BIGSERIAL|IDENTITY|nextval)` is present in the file.
- **Why:** Sequential IDs let attackers enumerate every resource: /api/users/1, /api/users/2, /api/users/3. Combined with missing authorization checks, this is a full data breach.
- **Fix:**
```javascript
// Bad
app.get("/api/invoices/:id", async (req, res) => {
  const invoice = await db.invoices.findById(req.params.id); // id = 1, 2, 3...
  res.json(invoice);
});

// Good: UUIDs + authorization
app.get("/api/invoices/:id", auth, async (req, res) => {
  const invoice = await db.invoices.findOne({
    id: req.params.id, // UUID: "a1b2c3d4-..."
    userId: req.user.id  // ownership check
  });
  if (!invoice) return res.status(404).json({ error: "Not found" });
  res.json(invoice);
});
```
- **False positives:** Both the route pattern and auto-increment must be in the same file. If routes and schema are in separate files, this will not trigger. Internal/admin routes where enumeration is acceptable.

---

### BIZ-005: Resource Creation Without Rate Limit
- **Severity:** WARNING
- **CWE:** CWE-770 (Allocation of Resources Without Limits or Throttling)
- **Pattern:** Triggers when `(?i)\.post\s*\(\s*['"].*(?:create|new|register)['"]` matches AND `(?i)(?:rateLimit|rate_limit|rateLimiter|throttle|slowDown|express-rate-limit|@nestjs/throttler|limiter)` is absent from the file.
- **Why:** Without rate limits, attackers can create thousands of spam accounts, flood your database, or abuse free tiers. Registration and creation endpoints are the primary targets.
- **Fix:**
```javascript
// Bad
app.post("/api/register", async (req, res) => {
  await createUser(req.body);
});

// Good
import rateLimit from "express-rate-limit";

const createLimiter = rateLimit({ windowMs: 60 * 1000, max: 5 });
app.post("/api/register", createLimiter, async (req, res) => {
  await createUser(req.body);
});
```
- **False positives:** Files where rate limiting is applied at a higher level (middleware, API gateway, reverse proxy) rather than in the route file itself. The check only looks within the same file.

---

### BIZ-006: Coupon/Discount Without Usage Limit
- **Severity:** INFO
- **CWE:** CWE-799 (Improper Control of Interaction Frequency)
- **Pattern:** Triggers when `(?i)(?:coupon|discount|promo)` matches AND `(?i)(?:limit|max|used|count|remaining|quota|cap|exhausted)` is absent from the file.
- **Why:** Unlimited coupon reuse causes revenue loss. Promo codes shared on deal sites can be applied thousands of times. One viral Reddit post can drain your margin.
- **Fix:**
```javascript
// Bad
if (coupon.code === req.body.code) {
  applyDiscount(order, coupon.percent);
}

// Good
const coupon = await db.coupons.findOne({ code: req.body.code });
if (!coupon) return res.status(404).json({ error: "Invalid code" });
if (coupon.currentUses >= coupon.maxUses) return res.status(410).json({ error: "Code expired" });
if (coupon.expiresAt < new Date()) return res.status(410).json({ error: "Code expired" });

applyDiscount(order, coupon.percent);
await db.coupons.update({ id: coupon.id }, { currentUses: coupon.currentUses + 1 });
```
- **False positives:** Files that mention "discount" in display/UI context (showing a discount badge) without implementing the application logic. The usage-limit keywords are broad enough that most implementation files will have at least one.
