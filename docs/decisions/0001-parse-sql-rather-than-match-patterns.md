# 0001 — Parse SQL rather than match patterns

**Status:** accepted

## Context

The gateway has to decide whether a statement written by a language model may run against a customer's database. The obvious implementation is a list of forbidden words: reject anything containing `DROP`, `INSERT`, `;`, and so on.

## Decision

Statements are parsed into an abstract syntax tree with `sqlglot` and the tree is inspected. Nothing is decided by matching text.

## Consequences

- **The usual bypasses stop working.** Comments, nested sub-selects, unions, unusual whitespace and case tricks all change how a statement is spelled without changing what it does. A pattern matcher sees the spelling; a tree sees the operation.
- **Writes hidden inside reads are visible.** `WITH x AS (INSERT ... RETURNING id) SELECT * FROM x` parses as a `SELECT` at the top level. Walking the tree finds the `INSERT` wherever it sits.
- **Scope can be enforced properly.** Every table reference in the statement is enumerated, including those reached through unions and sub-selects, so a role's allowlist cannot be escaped by reading a forbidden table in a subquery.
- **Aliases resolve.** A column rule on `customers` would otherwise be bypassed by writing `c.email`. The alias map is built from the same tree.
- **An unparseable statement is refused.** If the guard cannot understand it, it cannot approve it.
- **The cost is a dependency and dialect awareness.** `sqlglot` must be kept current, and the guard has to be told which dialect it is reading. That is a smaller risk than a regular expression nobody can fully reason about.

Two of the first adversarial tests failed against the initial implementation: a dangerous function nested inside a subquery, and a denied column reached through an alias. Both were implementation defects rather than design ones, and both were found because the tests were written as attacks rather than as examples.
