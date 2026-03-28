# Database Security Checks (DB-001 to DB-020)

20 checks for SQL injection, Supabase RLS, mass assignment, and database misconfigurations.

---

### DB-001: Supabase RLS Disabled
- **Severity:** CRITICAL
- **CWE:** CWE-862 (Missing Authorization)
- **Pattern:** `(?i)(?:ALTER\s+TABLE\s+\w+\s+DISABLE\s+ROW\s+LEVEL\s+SECURITY|enable_rls\s*[:=]\s*false)`
- **Why:** Disabling RLS means any authenticated user (or anon key holder) can read and modify ALL rows in the table. One Supabase anon key leak exposes everything.
- **Fix:**
```sql
-- Keep RLS enabled
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;

-- Add restrictive policies
CREATE POLICY "Users read own data" ON profiles
  FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users update own data" ON profiles
  FOR UPDATE USING (auth.uid() = user_id);
```
- **False positives:** Migration rollback scripts that temporarily disable RLS as part of a controlled operation. These should still be flagged since the pattern existing in code is a risk vector.

---

### DB-002: SQL String Concatenation
- **Severity:** CRITICAL
- **CWE:** CWE-89 (SQL Injection)
- **Pattern:** SQL keywords (`SELECT`, `INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`) combined with string concatenation (`+`, template literals `${}`, `f""`, `.format()`) using user input (`req.`, `params.`, `query.`, `input`)
- **Why:** The #1 cause of SQL injection. Concatenated user input lets attackers modify query logic, extract data, or drop tables.
- **Fix:**
```javascript
// BAD: const q = `SELECT * FROM users WHERE id = ${req.params.id}`;

// GOOD: Parameterized query
const result = await db.query(
  "SELECT * FROM users WHERE id = $1",
  [req.params.id]
);

// BETTER: Use an ORM
const user = await prisma.user.findUnique({ where: { id: req.params.id } });
```
- **False positives:** String concatenation in SQL that uses only constants or server-side values (not user input). The regex requires user input indicators (`req.`, `params.`, etc.) to reduce noise. Static query building will not trigger.

---

### DB-004: Database Credentials in Frontend Env Vars
- **Severity:** CRITICAL
- **CWE:** CWE-200 (Exposure of Sensitive Information)
- **Pattern:** `(?i)(?:NEXT_PUBLIC_|VITE_|REACT_APP_).*(?:DATABASE|DB|POSTGRES|MYSQL|MONGO|REDIS)[_\-]?(?:URL|URI|HOST|PASSWORD|USER)`
- **Why:** Frontend env vars (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`) are bundled into client JavaScript. Anyone viewing source gets your database connection string.
- **Fix:**
```env
# .env (server-only, NOT prefixed)
DATABASE_URL=postgresql://user:pass@host:5432/db

# For Supabase in frontend, use ONLY the anon key (not service_role)
NEXT_PUBLIC_SUPABASE_URL=https://xxx.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJ...
```
- **False positives:** Virtually none. There is no legitimate reason to put database credentials in frontend-prefixed env vars.

---

### DB-006: GRANT ALL PRIVILEGES
- **Severity:** WARNING
- **CWE:** CWE-250 (Execution with Unnecessary Privileges)
- **Pattern:** `(?i)GRANT\s+ALL\s+(?:PRIVILEGES\s+)?ON`
- **Why:** Excessive permissions mean a SQL injection or compromised service account can DROP tables, modify schemas, or access unrelated data.
- **Fix:**
```sql
-- Grant only what the application needs
GRANT SELECT, INSERT, UPDATE ON public.profiles TO app_role;
GRANT SELECT ON public.products TO app_role;
-- Never: GRANT ALL PRIVILEGES ON ALL TABLES TO app_role;
```
- **False positives:** Development/seed scripts that set up local databases with broad permissions. Still worth flagging since these scripts sometimes leak into production.

---

### DB-007: CREATE TABLE Without RLS
- **Severity:** WARNING
- **CWE:** CWE-862 (Missing Authorization)
- **Pattern:** `CREATE TABLE` statement in `.sql` or migration files without a corresponding `ALTER TABLE ... ENABLE ROW LEVEL SECURITY`
- **Why:** New tables in Supabase default to RLS disabled. Forgetting to enable it leaves the table wide open.
- **Fix:**
```sql
CREATE TABLE IF NOT EXISTS documents (
  id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id uuid REFERENCES auth.users(id),
  content text
);

-- Always pair with RLS
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users manage own documents" ON documents
  USING (auth.uid() = user_id);
```
- **False positives:** Only runs on `.sql` and migration files. Tables that genuinely should be public (e.g., static lookup tables) will trigger. In those cases, enable RLS with a permissive policy to be explicit about the intent.

---

### DB-011: NoSQL Injection
- **Severity:** CRITICAL
- **CWE:** CWE-943 (Improper Neutralization of Special Elements in Data Query Logic)
- **Pattern:** MongoDB operators (`$where`, `$regex`, `$ne`, `$gt`, `$lt`, `$nin`) with user input, OR query methods (`find`, `findOne`, `aggregate`, `deleteMany`, `updateMany`) receiving `req.body`/`req.query`/`req.params` directly
- **Why:** Passing user-controlled objects to MongoDB queries lets attackers inject operators. `{ "password": { "$ne": "" } }` bypasses password checks entirely.
- **Fix:**
```javascript
// BAD: User can send { "$ne": "" } as password
const user = await User.findOne({ email, password: req.body.password });

// GOOD: Validate types with Zod/Joi
const { email, password } = loginSchema.parse(req.body);
const user = await User.findOne({ email });
const valid = await bcrypt.compare(password, user.passwordHash);
```
- **False positives:** Server-side code that intentionally uses MongoDB operators on validated data. The check requires user input indicators in the same expression.

---

### DB-013: Raw SQL in ORM
- **Severity:** CRITICAL
- **CWE:** CWE-89 (SQL Injection)
- **Pattern:** `(?i)(?:\$queryRaw|\$executeRaw|\.raw\s*\(|\.rawQuery\s*\()` for Prisma, or `(?i)(?:sql\.raw|sql\`.*\$\{)` for Drizzle
- **Why:** ORMs protect against injection by default. Raw queries bypass that protection. One raw query with string interpolation undoes all the safety of using an ORM.
- **Fix:**
```typescript
// BAD: Prisma raw with interpolation
const users = await prisma.$queryRaw`SELECT * FROM users WHERE name = ${name}`;

// GOOD: Prisma.sql tagged template (auto-parameterized)
const users = await prisma.$queryRaw(
  Prisma.sql`SELECT * FROM users WHERE name = ${name}`
);

// BEST: Use the ORM query builder
const users = await prisma.user.findMany({ where: { name } });
```
- **False positives:** Safe raw query usage with proper parameterization (e.g., Prisma.sql tagged template). The check flags all raw query usage since even safe patterns warrant review.

---

### DB-015: Admin Routes Without Authentication
- **Severity:** CRITICAL
- **CWE:** CWE-306 (Missing Authentication for Critical Function)
- **Pattern:** Route definitions for `/admin`, `/api/admin`, `/dashboard`, `/internal` paths without auth middleware references (`authenticate`, `requireAuth`, `isAdmin`, `@login_required`, etc.)
- **Why:** Unauthenticated admin routes give attackers full control over the application. This is consistently in the OWASP Top 10.
- **Fix:**
```javascript
// Apply auth middleware BEFORE the route handler
app.use("/admin", requireAuth, requireRole("admin"));

// Or per-route
app.get("/admin/users", requireAuth, requireRole("admin"), (req, res) => {
  // handler
});
```
- **False positives:** Files where auth middleware is applied in a parent router or app-level middleware (not visible in the route file). Split architectures where routes and middleware live in separate files.

---

### DB-016: Mass Assignment
- **Severity:** WARNING
- **CWE:** CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes)
- **Pattern:** `(?i)(?:\.create|\.update|\.insert|\.save)\s*\(\s*(?:req\.body|request\.body|body|data)\s*\)`
- **Why:** Passing the entire request body to a database write lets attackers set fields they shouldn't control: `role`, `isAdmin`, `price`, `balance`.
- **Fix:**
```javascript
// BAD: Attacker can send { name: "John", role: "admin" }
await prisma.user.create({ data: req.body });

// GOOD: Destructure only allowed fields
const { name, email, bio } = req.body;
await prisma.user.create({ data: { name, email, bio } });

// ALSO GOOD: Validate with Zod schema
const data = createUserSchema.parse(req.body);
await prisma.user.create({ data });
```
- **False positives:** Cases where `req.body` has already been validated/filtered by a prior middleware (Zod, Joi, class-validator). The check cannot see cross-function data flow.

---

### DB-017: List Endpoint Without Pagination
- **Severity:** WARNING
- **CWE:** CWE-770 (Allocation of Resources Without Limits or Throttling)
- **Pattern:** Query methods that return all results (`.find({})`, `.findAll({})`, `.findMany({})`, `SELECT * FROM`) without pagination keywords (`limit`, `take`, `pageSize`, `offset`, `skip`, `cursor`)
- **Why:** A table with 10M rows queried without LIMIT will exhaust server memory and crash the process. Trivial DoS vector.
- **Fix:**
```javascript
// Offset-based pagination
const users = await prisma.user.findMany({
  take: 20,
  skip: (page - 1) * 20,
  orderBy: { createdAt: "desc" },
});

// Cursor-based (better for large datasets)
const users = await prisma.user.findMany({
  take: 20,
  cursor: lastId ? { id: lastId } : undefined,
  orderBy: { id: "asc" },
});
```
- **False positives:** Internal scripts or cron jobs that intentionally process all records. Admin-only endpoints where the dataset is known to be small. The check has no awareness of dataset size.

---

### DB-018: GraphQL Without Depth Limiting
- **Severity:** WARNING
- **CWE:** CWE-400 (Uncontrolled Resource Consumption)
- **Pattern:** GraphQL indicators (`resolvers`, `typeDefs`, `schema`, `graphql`) present without depth limiting references (`depthLimit`, `maxDepth`, `query.complexity`)
- **Why:** Without depth limits, attackers send deeply nested queries (`{ user { posts { comments { author { posts { ... } } } } } }`) that cause exponential database load.
- **Fix:**
```javascript
const depthLimit = require("graphql-depth-limit");
const { createComplexityLimitRule } = require("graphql-validation-complexity");

app.use("/graphql", graphqlHTTP({
  schema,
  validationRules: [
    depthLimit(5),
    createComplexityLimitRule(1000),
  ],
}));
```
- **False positives:** GraphQL client code (not server) that imports graphql utilities. The check cannot distinguish client from server usage.

---

### DB-020: Supabase Realtime Without RLS
- **Severity:** WARNING
- **CWE:** CWE-862 (Missing Authorization)
- **Pattern:** `(?i)(?:\.channel|\.on\s*\(\s*['"]postgres_changes|supabase.*subscribe|realtime)`
- **Why:** Supabase Realtime broadcasts changes to all subscribed clients. Without RLS policies, every user sees every change in the table, including other users' data.
- **Fix:**
```javascript
// 1. Enable RLS on the table
// ALTER TABLE messages ENABLE ROW LEVEL SECURITY;
// CREATE POLICY "Users see own messages" ON messages
//   FOR SELECT USING (auth.uid() = user_id);

// 2. Subscribe with user context (RLS is enforced automatically)
const channel = supabase
  .channel("my-messages")
  .on("postgres_changes", {
    event: "*",
    schema: "public",
    table: "messages",
    filter: `user_id=eq.${userId}`,
  }, (payload) => console.log(payload))
  .subscribe();
```
- **False positives:** Realtime subscriptions on intentionally public tables (e.g., a live scoreboard). The check flags all realtime usage as a reminder to verify RLS status on the subscribed table.
