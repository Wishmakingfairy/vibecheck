"""
0xguard Database Security Checker
20 checks for SQL injection, Supabase RLS, mass assignment, and database misconfigurations.

Author: Haralds Gabrans
License: MIT
"""

import re
from typing import List
from checkers import CheckResult, Severity

CATEGORY = 'Database Security'

# SQL injection patterns
SQL_CONCAT = re.compile(
    r'''(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\s+.*(?:\+\s*(?:req\.|params\.|query\.|input|user)|[`'"].*\$\{|f['"].*\{|\.format\()''',
    re.IGNORECASE | re.DOTALL
)
SQL_TEMPLATE_LITERAL = re.compile(
    r'''(?:`\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\s+.*\$\{)''',
    re.IGNORECASE
)

# Supabase RLS
RLS_DISABLED = re.compile(
    r'(?i)(?:ALTER\s+TABLE\s+\w+\s+DISABLE\s+ROW\s+LEVEL\s+SECURITY|enable_rls\s*[:=]\s*false)',
)
CREATE_TABLE = re.compile(r'(?i)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)', re.IGNORECASE)
ENABLE_RLS = re.compile(r'(?i)ALTER\s+TABLE\s+\w+\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY')

# NoSQL injection
NOSQL_INJECTION = re.compile(
    r'''(?i)(?:\$where|\$regex|\$ne|\$gt|\$lt|\$nin)\s*[:=].*(?:req\.|params\.|query\.|body\.|input)''',
)
NOSQL_INJECTION_2 = re.compile(
    r'''(?i)(?:find|findOne|findMany|aggregate|deleteMany|updateMany)\s*\(\s*(?:req\.body|req\.query|req\.params)''',
)

# Raw queries
PRISMA_RAW = re.compile(r'''(?i)(?:\$queryRaw|\$executeRaw|\.raw\s*\(|\.rawQuery\s*\()''')
DRIZZLE_RAW = re.compile(r'''(?i)(?:sql\.raw|sql`.*\$\{)''')

# Mass assignment
MASS_ASSIGNMENT = re.compile(
    r'''(?i)(?:\.create|\.update|\.insert|\.save)\s*\(\s*(?:req\.body|request\.body|body|data)\s*\)''',
)

# GRANT ALL
GRANT_ALL = re.compile(r'(?i)GRANT\s+ALL\s+(?:PRIVILEGES\s+)?ON', re.IGNORECASE)

# DB creds in frontend
DB_CREDS_FRONTEND = re.compile(
    r'''(?i)(?:NEXT_PUBLIC_|VITE_|REACT_APP_).*(?:DATABASE|DB|POSTGRES|MYSQL|MONGO|REDIS)[_\-]?(?:URL|URI|HOST|PASSWORD|USER)''',
)

# Admin routes without auth
ADMIN_ROUTE = re.compile(
    r'''(?i)(?:app|router)\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*['"](?:/admin|/api/admin|/dashboard|/internal)''',
)
AUTH_MIDDLEWARE = re.compile(
    r'''(?i)(?:authenticate|isAuthenticated|requireAuth|authMiddleware|protect|isAdmin|requireRole|@auth|@login_required|@permission_required)''',
)

# GraphQL depth
GRAPHQL_RESOLVER = re.compile(r'(?i)(?:resolvers?|typeDefs|schema|graphql)', re.IGNORECASE)
GRAPHQL_DEPTH = re.compile(r'(?i)(?:depthLimit|maxDepth|depth.?limit|query.?complexity)', re.IGNORECASE)

# Pagination
LIST_ENDPOINT = re.compile(
    r'''(?i)(?:\.find\s*\(\s*\)|\.findAll\s*\(\s*\)|\.findMany\s*\(\s*\)|SELECT\s+\*\s+FROM)''',
)
PAGINATION = re.compile(r'(?i)(?:limit|take|pageSize|per_page|offset|skip|cursor|paginate)', re.IGNORECASE)

# Realtime subscriptions
SUPABASE_REALTIME = re.compile(
    r'''(?i)(?:\.channel|\.on\s*\(\s*['"]postgres_changes|supabase.*subscribe|realtime)''',
)


def check(content: str, file_path: str, config: dict = None) -> List[CheckResult]:
    """Run all database security checks."""
    results = []

    # DB-001: Supabase RLS disabled
    if RLS_DISABLED.search(content):
        results.append(CheckResult(
            check_id='DB-001',
            severity=Severity.CRITICAL,
            category=CATEGORY,
            message='Row Level Security (RLS) is being DISABLED. Any authenticated user can read/modify ALL data in this table.',
            fix_suggestion='Keep RLS enabled. Create policies: CREATE POLICY "Users can read own data" ON table FOR SELECT USING (auth.uid() = user_id);',
            cwe='CWE-862',
        ))

    # DB-007: CREATE TABLE without RLS (only in .sql files or migration files)
    if file_path and ('.sql' in file_path or 'migration' in file_path.lower()):
        tables = CREATE_TABLE.findall(content)
        if tables and not ENABLE_RLS.search(content):
            results.append(CheckResult(
                check_id='DB-007',
                severity=Severity.WARNING,
                category=CATEGORY,
                message=f'Table(s) created without enabling Row Level Security: {", ".join(tables[:3])}',
                fix_suggestion='Add after CREATE TABLE: ALTER TABLE table_name ENABLE ROW LEVEL SECURITY; Then add appropriate policies.',
                cwe='CWE-862',
            ))

    # DB-002: SQL string concatenation
    if SQL_CONCAT.search(content) or SQL_TEMPLATE_LITERAL.search(content):
        results.append(CheckResult(
            check_id='DB-002',
            severity=Severity.CRITICAL,
            category=CATEGORY,
            message='SQL query built with string concatenation/interpolation. This is the #1 cause of SQL injection.',
            fix_suggestion='Use parameterized queries: db.query("SELECT * FROM users WHERE id = $1", [userId]). Or use an ORM (Prisma, Drizzle, Sequelize).',
            cwe='CWE-89',
        ))

    # DB-004: Database credentials in frontend
    if DB_CREDS_FRONTEND.search(content):
        results.append(CheckResult(
            check_id='DB-004',
            severity=Severity.CRITICAL,
            category=CATEGORY,
            message='Database credentials exposed in frontend environment variables. Anyone can connect directly to your database.',
            fix_suggestion='Database credentials must NEVER be in NEXT_PUBLIC_/VITE_/REACT_APP_ vars. Use server-side API routes to proxy database access.',
            cwe='CWE-200',
        ))

    # DB-006: GRANT ALL PRIVILEGES
    if GRANT_ALL.search(content):
        results.append(CheckResult(
            check_id='DB-006',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='GRANT ALL PRIVILEGES detected. This gives excessive database permissions.',
            fix_suggestion='Grant only the minimum required permissions: GRANT SELECT, INSERT, UPDATE ON table TO role;',
            cwe='CWE-250',
        ))

    # DB-011: NoSQL injection
    if NOSQL_INJECTION.search(content) or NOSQL_INJECTION_2.search(content):
        results.append(CheckResult(
            check_id='DB-011',
            severity=Severity.CRITICAL,
            category=CATEGORY,
            message='User input passed directly to NoSQL query operators. Attackers can manipulate query logic.',
            fix_suggestion='Validate and sanitize input before queries. Use schema validation (Joi, Zod). Reject objects where strings are expected.',
            cwe='CWE-943',
        ))

    # DB-013: Prisma/Drizzle raw queries
    if PRISMA_RAW.search(content) or DRIZZLE_RAW.search(content):
        results.append(CheckResult(
            check_id='DB-013',
            severity=Severity.CRITICAL,
            category=CATEGORY,
            message='Raw SQL query detected in ORM. This bypasses the ORM\'s built-in SQL injection protection.',
            fix_suggestion='Use Prisma: prisma.$queryRaw`SELECT * FROM users WHERE id = ${Prisma.sql`${userId}`}` with tagged template literals for safe interpolation.',
            cwe='CWE-89',
        ))

    # DB-015: Admin routes without auth
    if ADMIN_ROUTE.search(content) and not AUTH_MIDDLEWARE.search(content):
        results.append(CheckResult(
            check_id='DB-015',
            severity=Severity.CRITICAL,
            category=CATEGORY,
            message='Admin/internal route detected without authentication middleware.',
            fix_suggestion='Add auth middleware: app.use("/admin", requireAuth, requireRole("admin"), adminRouter). Never expose admin routes without authentication.',
            cwe='CWE-306',
        ))

    # DB-016: Mass assignment
    if MASS_ASSIGNMENT.search(content):
        results.append(CheckResult(
            check_id='DB-016',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='Entire request body passed directly to database create/update. Attackers can set any field (role, isAdmin, etc.).',
            fix_suggestion='Destructure only allowed fields: const { name, email } = req.body; await db.create({ data: { name, email } })',
            cwe='CWE-915',
        ))

    # DB-017: List endpoints without pagination
    if LIST_ENDPOINT.search(content) and not PAGINATION.search(content):
        results.append(CheckResult(
            check_id='DB-017',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='Database query returns all results without pagination. Large tables can cause DoS.',
            fix_suggestion='Add pagination: .findMany({ take: 20, skip: page * 20 }) or use cursor-based pagination.',
            cwe='CWE-770',
        ))

    # DB-018: GraphQL without depth limit
    if GRAPHQL_RESOLVER.search(content) and not GRAPHQL_DEPTH.search(content):
        results.append(CheckResult(
            check_id='DB-018',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='GraphQL schema detected without query depth limiting. Deep nested queries can cause DoS.',
            fix_suggestion='Add depth limiting: const depthLimit = require("graphql-depth-limit"); app.use("/graphql", depthLimit(5))',
            cwe='CWE-400',
        ))

    # DB-020: Supabase Realtime without RLS
    if SUPABASE_REALTIME.search(content):
        results.append(CheckResult(
            check_id='DB-020',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='Supabase Realtime subscription detected. Ensure RLS is enabled on subscribed tables, or all changes are broadcast to all users.',
            fix_suggestion='Enable RLS on all tables with Realtime subscriptions. Add policies that restrict which rows each user can see.',
            cwe='CWE-862',
        ))

    return results
