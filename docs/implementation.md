# STP-RBAC Simulator

A reference implementation and federated simulation of **STP-RBAC**:
*Spatio-Temporal Purpose-aware Role-Based Access Control for Federated Data
Processing*. The paper is in `docs/main.tex`; the evaluation plan is in
`docs/EVALUATION-IMPLEMENTATION.md`.

The project has two parts:

1. **`stprbac/`**: a pure-Python core (standard library only) that follows the
   paper's formal model. Field names match Definition 1, and the authorisation
   predicate matches Definitions 3–6.
2. **`federation/`**: a FastAPI simulation of a federated deployment. One
   **coordinator** (Central node) and several regional **workers** (data
   providers) each run as a separate HTTP service. Together they enforce the
   policy in two phases (Corollary 2).

## The model in brief

An access request is a tuple **q = (u, r, o, p, l, t)**: user `u`, acting in
role `r` from jurisdiction (locus) `l`, asks for object `o` for purpose `p` at
integer time `t`.

A policy `Θ` contains users, roles, objects, jurisdictional labels and
purposes. It also contains:

| Field | Meaning |
|---|---|
| `ua`, `pa`, `h` | user–role assignment, role–object permission and role hierarchy (senior → junior), each valid over an `IntervalSet` of times (`τ_U`, `τ_P`, `τ_H`) |
| `rho_u` | user → loci the user may operate from |
| `rho_g` | object → **governing** jurisdictions (whose law applies) |
| `rho_s` | object → **storage** sites (where replicas sit) |
| `gamma` | directed pairs `(l, l')`: locus `l` may process `l'`-data (not necessarily symmetric or transitive) |
| `pi` | `(role, object)` → permitted purposes |
| `delta` | purpose → admissible objects (data minimisation) |
| `sod` | conflicting role pairs (separation of duty) |

`Auth(q)` is a conjunction of six named conjuncts. They are always evaluated in
this order, so every denial has a well-defined first cause:

| # | Conjunct | Holds when | Enforced at |
|---|---|---|---|
| 1 | `activation` | `r ∈ Act_t(u)`: `u` can act in `r` at `t`, either directly or through an active senior role | coordinator |
| 2 | `locus` | `l ∈ rho_u(u)` | coordinator |
| 3 | `assignment` | `(r, o) ∈ PA*_t`: `r` holds or inherits a permission on `o` that is active at `t` | coordinator |
| 4 | `spatial` | `RegionOK(l, o)`: **every** governing regime of `o` admits `l`, **and** at least one storage site of `o` is reachable from `l` | coordinator |
| 5 | `purpose` | `p ∈ Π_t(r, o)` (including inherited purposes) | worker |
| 6 | `minimisation` | `o ∈ Δ(p)` | worker |

Conjuncts 1–4 do not depend on the purpose. The coordinator checks them
without learning *why* the data is wanted. Conjuncts 5–6 depend on the purpose
and are checked by the worker that holds the data. Because conjunction is
associative, the two-phase result is exactly `Auth(q)`.

> **Note:** as in the paper, `sod` is not a condition of `Auth`. It is a
> property of the policy as a whole (temporal SoD), and the analysis that
> would check it (algorithm A2) is not implemented yet.

Constructing a `Policy` raises `ValueError` when the policy breaks the side
conditions of Definition 1:

- a name that is used but never declared;
- an empty or missing `rho_u`, `rho_g` or `rho_s` entry;
- a `gamma` that is not reflexive;
- a `pi` entry outside `pa`;
- a malformed SoD pair;
- a cyclic hierarchy.

## Repository layout

```
stprbac/                 core library (no third-party dependencies)
  intervals.py           IntervalSet: normalised sets of closed integer intervals
  model.py               Request and Policy (Definition 1); validates the policy on construction
  engine.py              Act_t, PA*_t, Pi_t, RegionOK, Auth, two-phase split
  diagnose.py            denial -> failing conjunct, responsible policy entries
  serde.py               exact JSON round-trip of Policy for shipping between nodes
  rego.py                Policy -> OPA data; evaluate via `opa eval` or the OPA REST API
policies/
  stprbac.rego           Auth and the two-phase split in Rego (policy-independent rules)
  stprbac_test.rego      `opa test` cases for the example scenario
  scenarios/pharma_hospital/data.json   the example policy as OPA data (generated)
federation/
  central.py             coordinator service (phase 1 + routing)
  worker.py              data-provider service (phase 2 + local "execution")
  schemas.py             Pydantic wire models
scenarios/
  pharma_hospital.py     example policy + default 1-coordinator/3-worker topology
tests/
  test_engine.py         unit tests, incl. agreement with a naive reference oracle
  test_rego.py           agreement of the Rego encoding with the engine (needs `opa`)
run_federation.py        starts the whole federation on localhost
run_opa.py               evaluates a scenario on OPA (local or over the REST API)
demo_client.py           sends a set of annotated requests to the coordinator
docs/                    paper sources and evaluation spec
main.py, test_main.http  leftover PyCharm FastAPI template (not used)
```

## Installation

Python 3.10+ (the code uses `X | None` annotations). The core library needs
nothing else. The federation needs:

```bash
python -m venv .venv
source .venv/bin/activate
pip install fastapi uvicorn httpx pydantic
```

## Usage

### 1. Run the federation

```bash
python run_federation.py
```

This command:

- builds the policy from the scenario module and writes it to
  `.runtime/policy.json`, so every node loads the same copy;
- starts the coordinator on `http://127.0.0.1:9000`;
- starts one worker per region (`eu-hospital` :9001, `uk-datacentre` :9002,
  `us-lab` :9003); each worker registers its region and objects with the
  coordinator;
- watches the processes. If any node exits, the launcher stops everything.
  Press Ctrl-C to stop the federation.

Options:

```bash
python run_federation.py --scenario scenarios.pharma_hospital   # any module with build_policy() and default_topology()
python run_federation.py --central-port 9100 --base-worker-port 9101
```

### 2. Run the demo client

Run this in a second terminal:

```bash
python demo_client.py            # human-readable trace
python demo_client.py --json     # raw JSON decisions
python demo_client.py --central http://127.0.0.1:9100
```

The client lists the registered workers and then sends six requests. Each one
targets a different decision path:

| Request | Expected result |
|---|---|
| alice / clinician / ehr / care / EU / t=50 | authorised at `eu-hospital` |
| erin / coordinator_role / ehr / care / EU / t=50 | authorised through the role hierarchy |
| dan / auditor / consent / audit / CH / t=150 | denied at coordinator: `activation` (auditor is only active in phase 4) |
| carol / analyst / genome / research / EU / t=150 | denied at coordinator: `locus` (carol may only operate from US) |
| carol / analyst / report / reporting / US / t=250 | denied at coordinator: `spatial` (US → EU is not in Γ) |
| bob / data_manager / ehr / care / UK / t=50 | denied at worker: `purpose` (only `anonymisation` is allowed) |

### 3. Call the HTTP API directly

**Coordinator** (`:9000`)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | status and registered workers |
| `GET` | `/nodes` | worker registry (region, URL, objects) |
| `POST` | `/register` | worker self-registration (`node_id`, `region`, `url`, `objects`) |
| `POST` | `/request` | submit an access request, get a final `Decision` |

**Worker** (`:9001+`)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | node id, region, objects held |
| `POST` | `/enforce` | purpose-dependent phase (normally called by the coordinator) |

Example:

```bash
curl -s -X POST http://127.0.0.1:9000/request \
  -H 'Content-Type: application/json' \
  -d '{"u":"carol","r":"analyst","o":"genome","p":"research","l":"US","t":150}'
```

The response is a `Decision`. It has these fields:

- `authorised`;
- `decided_at`: `"coordinator"` or the deciding worker's `node_id`;
- `phases`: one report per phase, with the verdict of each conjunct;
- `output`: on success, a summary of the processed result that does not
  contain the raw data, which stays on the worker;
- `denial`: on refusal, the failing conjunct, the enforcement point, the
  responsible policy entries, all failing conjuncts and a readable message.

When the prefilter passes, the coordinator sends the request to a registered
worker that declares the object. It prefers a worker whose region is in
`rho_s(o)`. If no worker holds the object, it returns HTTP 503.

### 4. Use the core library directly

You can do this without running any servers:

```python
from scenarios.pharma_hospital import build_policy
from stprbac import engine, diagnose
from stprbac.model import Request

policy = build_policy()
q = Request(u="bob", r="data_manager", o="ehr", p="care", l="UK", t=50)

engine.auth(policy, q)                    # False
engine.evaluate_conjuncts(policy, q)      # {'activation': True, ..., 'purpose': False, ...}
engine.coordinator_prefilter(policy, q)   # PhaseResult(passed=True, ...)
engine.worker_decision(policy, q)         # PhaseResult(passed=False, first_failure='purpose')
diagnose.diagnose(policy, q)              # Denial(failing_conjunct='purpose', enforcement_point='worker', ...)
```

`engine.evaluate_conjuncts(policy, q, names)` and
`diagnose.diagnose(policy, q, conjuncts)` accept a subset of conditions
(for example `engine.COORDINATOR_CONJUNCTS`), so each node evaluates only the
conditions it enforces.

Other useful helpers: `engine.juniors_t`, `engine.act_t`, `engine.pa_star_t`, `engine.pi_t`,
`engine.region_ok`, `IntervalSet` operations (`union`, `intersect`,
`first_after`, `t in iv`), and `serde.policy_to_dict` / `policy_from_dict`.

### 5. Evaluate on OPA / Rego

`policies/stprbac.rego` encodes the six conjuncts of `Auth` and the
coordinator/worker split in Rego. The rules do not depend on a particular
policy: a policy `Θ` is passed to OPA as the data document `data.policy`, built
by `stprbac.rego.policy_to_opa_data`. Role closure uses OPA's
`graph.reachable` built-in, because Rego has no recursion. This requires the
[`opa`](https://www.openpolicyagent.org/docs/latest/#running-opa) binary (≥ 1.0)
on `PATH`.

```bash
python run_opa.py demo                     # demo requests, local `opa eval`
python run_opa.py demo --server            # same, through a temporary OPA server's REST API
python run_opa.py serve --port 8181        # keep an OPA server running with the scenario loaded
python run_opa.py demo --url http://127.0.0.1:8181   # use that server (rules + data are pushed first)
python run_opa.py export                   # regenerate policies/scenarios/pharma_hospital/data.json
python run_opa.py --scenario your.module demo
```

The demo checks every OPA decision against `stprbac.engine`. OPA can also be
used without Python:

```bash
opa run --server policies/stprbac.rego policies/scenarios/pharma_hospital/data.json
curl -s localhost:8181/v1/data/stprbac/authz/decision \
  -d '{"input": {"u":"carol","r":"analyst","o":"report","p":"reporting","l":"US","t":250}}'
# {"result":{"allow":false,"conjuncts":{...,"spatial":false},"first_failure":"spatial"}}
```

The rules have four entry points under `data.stprbac.authz`:

| Rule | Returns |
|---|---|
| `decision` | `allow`, all six `conjuncts`, `first_failure` (in the fixed order, or `null`) |
| `coordinator` | `passed`, `conjuncts`, `first_failure` for conjuncts 1–4. `input.p` may be omitted |
| `worker` | the same for conjuncts 5–6 |
| `batch` | `decision` for each element of `input.requests`, in order |

From Python:

```python
from stprbac import rego

with rego.OpaCli(policy) as opa:            # local; one process per call
    opa.decide(q)                           # also opa.decide(q, "coordinator") / "worker"
    opa.decide_many(qs)                     # one `opa eval` for the whole list

with rego.opa_server(policy) as srv:        # starts `opa run --server` on a free port
    srv.decide(q)

srv = rego.OpaServer("http://127.0.0.1:8181")   # an existing server
srv.load(policy)                            # PUT the rules and data.policy
```

SoD is not exported, because it is not a conjunct of `Auth`.

## Tests

The tests use only the standard library:

```bash
python -m unittest discover -s tests -t . -v
opa test policies/ -v
```

`tests/test_rego.py` is skipped when `opa` is not on `PATH`. Otherwise it
compares the Rego decision (all conjuncts and the first failure) with the
engine on every request of the example scenario (45,000 requests: all users ×
roles × objects × purposes × loci, at every interval endpoint ±1). It also
checks 20 random synthetic policies and the two phases over the REST API.

## The example scenario

`scenarios/pharma_hospital.py` encodes a multi-jurisdiction pharmaceutical and
hospital study:

- **5 users:** alice (EU clinician), bob (UK data manager), carol (US
  analyst), dan (CH auditor) and erin (study coordinator, EU or UK).
- **5 roles:** `coordinator_role` is senior to `clinician` at all times, and
  senior to `analyst` during phases 2–3.
- **6 objects:** `ehr`, `imaging`, `genome`, `labresults`, `consent` and
  `report`, each with its own governing jurisdictions and storage sites.
- **5 purposes:** care, research, anonymisation, audit and reporting.
- **5 jurisdictions:** EU, UK, US, CH and IN.
- **4 project phases** on the time axis: `[0,99]` setup, `[100,199]`
  analysis, `[200,299]` reporting and `[300,399]` archival.
- **Γ:** reflexive, plus EU↔UK, EU↔CH, UK→US and EU→US. US→EU is
  intentionally missing, and IN has no adequacy agreements.

## Adding a scenario

Create a module that defines:

- `build_policy() -> Policy`
- `default_topology() -> dict`, shaped like this:
  `{"central": {"host", "port"}, "workers": [{"node_id", "region", "host", "port", "objects"}, ...]}`

Then pass it to the launcher with
`python run_federation.py --scenario your.module`.
