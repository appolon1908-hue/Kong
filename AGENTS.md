# Codestra Agent Rules

1. Work only in the assigned subsection branch/worktree.
2. Follow: subsection -> section -> development -> testing -> staging -> production.
3. Fetch first; require a clean tree; record base SHA; check ahead/behind.
4. Never overwrite unknown local work or bypass conflicts.
5. Every atomic task needs code, tests, docs/contracts/migrations when applicable.
6. Run applicable lint, type, unit, integration, contract, migration, security, secret-scan, and diff checks before push.
7. Push every validated checkpoint and verify remote SHA.
8. No direct work on main/development/testing/staging/production and no force push to protected branches.
9. Keep PRODUCTION_GO=NO, LIVE_CAPABILITIES_ENABLED=NO, EXTERNAL_EFFECTS=false unless an approved activation mission explicitly changes them.
10. COMPLETE requires clean tree, pushed branch, tests, docs, zero unresolved blockers, and local/remote SHA match.
11. CERTIFIED additionally requires exact-SHA CI, independent review, regression/security gates, and stored evidence.
12. If safety or correctness cannot be proven, mark BLOCKED and stop.
