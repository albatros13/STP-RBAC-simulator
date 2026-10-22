# STP-RBAC authorisation predicate Auth_Theta(q) in Rego (OPA v1 syntax).
#
# A direct transcription of stprbac/engine.py (Definitions 3-6 and the
# two-phase split of Corollary 2). The rules are generic: the policy Theta is
# supplied as data under data.policy, in the shape produced by
# stprbac.rego.policy_to_opa_data():
#
#   roles : [r, ...]                       R
#   ua    : {u: {r: [[a, b], ...]}}        tau_U as closed integer intervals
#   pa    : {r: {o: [[a, b], ...]}}        tau_P
#   h     : {senior: {junior: [[a, b]]}}   tau_H
#   rho_u : {u: [l, ...]}
#   rho_g : {o: [l, ...]}                  governing regimes
#   rho_s : {o: [l, ...]}                  storage sites
#   gamma : {l: [l', ...]}                 l may process l'-data
#   pi    : {r: {o: [p, ...]}}
#   delta : {p: [o, ...]}
#
# The request q = (u, r, o, p, l, t) is the input document. Entry points:
#
#   data.stprbac.authz.decision     all six conjuncts, allow, first_failure
#   data.stprbac.authz.coordinator  purpose-independent phase (never reads input.p)
#   data.stprbac.authz.worker       purpose-dependent phase
#   data.stprbac.authz.batch        decisions for input.requests, in order
package stprbac.authz

P := data.policy

# Fixed evaluation order, so that every denial has a well-defined first cause.
conjunct_order := ["activation", "locus", "assignment", "spatial", "purpose", "minimisation"]

active(ivs, t) if {
	some iv in ivs
	iv[0] <= t
	t <= iv[1]
}

# ---------------------------------------------------------------------------
# Time-indexed derived relations (Definitions 3-4)
# ---------------------------------------------------------------------------

# H restricted to the edges active at input.t, as an adjacency map for
# graph.reachable (Rego has no recursion; the built-in gives the reflexive
# transitive closure). Every role must be a key: graph.reachable drops nodes
# that are not.
h_at_t[s] := {j | some j, ivs in object.get(P.h, s, {}); active(ivs, input.t)} if some s in P.roles

# { r' | r >=_t r' }
juniors := graph.reachable(h_at_t, {input.r})

# Act_t(u): roles reachable from an assignment of u that is active at t.
act := graph.reachable(h_at_t, {r | some r, ivs in P.ua[input.u]; active(ivs, input.t)})

# ---------------------------------------------------------------------------
# The six conjuncts of Auth (Definition 6)
# ---------------------------------------------------------------------------
default activation := false

activation if input.r in act

default locus := false

locus if input.l in P.rho_u[input.u]

default assignment := false

assignment if {
	some r in juniors
	active(P.pa[r][input.o], input.t)
}

# RegionOK(l, o): every governing regime admits l, and some replica is
# reachable from l (Definition 5).
default spatial := false

spatial if {
	every lg in P.rho_g[input.o] {
		lg in P.gamma[input.l]
	}
	some ls in P.rho_s[input.o]
	ls in P.gamma[input.l]
}

# p in Pi_t(r, o), including purposes inherited from active juniors.
default purpose := false

purpose if {
	some r in juniors
	active(P.pa[r][input.o], input.t)
	input.p in P.pi[r][input.o]
}

default minimisation := false

minimisation if input.o in P.delta[input.p]

# ---------------------------------------------------------------------------
# Two-phase enforcement (Corollary 2)
# ---------------------------------------------------------------------------
coordinator_conjuncts := {
	"activation": activation,
	"locus": locus,
	"assignment": assignment,
	"spatial": spatial,
}

worker_conjuncts := {
	"purpose": purpose,
	"minimisation": minimisation,
}

phase(cs) := {
	"passed": every_true(cs),
	"conjuncts": cs,
	"first_failure": first_failure(cs),
}

every_true(cs) if {
	every _, v in cs {
		v
	}
} else := false

first_failure(cs) := fs[0] if {
	fs := [c | some c in conjunct_order; cs[c] == false]
	count(fs) > 0
} else := null

coordinator := phase(coordinator_conjuncts)

worker := phase(worker_conjuncts)

conjuncts := object.union(coordinator_conjuncts, worker_conjuncts)

default allow := false

allow if every_true(conjuncts)

decision := {
	"allow": allow,
	"conjuncts": conjuncts,
	"first_failure": first_failure(conjuncts),
}

batch := [d | some q in input.requests; d := decision with input as q]
