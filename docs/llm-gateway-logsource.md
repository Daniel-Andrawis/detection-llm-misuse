# Proposal: an `llm_gateway` logsource for Sigma

**Status:** proposal / request for comment. Implemented and in use by the rules in
this repository; not yet submitted upstream.

## The gap

Sigma has no way to describe LLM inference telemetry. As of 2026-09-01,
`SigmaHQ/sigma` (≈11k stars) contains five files with `llm` anywhere in the path
and four with `prompt`. There is **no `llm_gateway` logsource, and no agreed field
names for prompt payloads, key identifiers, or model stop reasons**.

The consequence is that every project writing detections for this surface invents
its own schema, and no rule is portable between them. That is the state this
document is trying to end. The rules in `rules/sigma/` use the contract below; it
is offered as a starting point, not a finished standard.

## Proposed logsource

```yaml
logsource:
  product: llm_gateway
  service: inference_api
```

`llm_gateway` is the reverse proxy, API gateway, or SDK middleware that sits in
front of a model endpoint and observes traffic. It is deliberately not named for
any vendor: the same rules should work whether the gateway fronts a self-hosted
model or a commercial API.

## Field contract

A gateway claiming this logsource should emit the following. Fields marked
**required** are needed by at least one rule in this repository.

### Request identity

| Field | Type | Notes |
|---|---|---|
| `api_key_id` | string | **Required.** A *hashed* key identifier, e.g. `sha256:aa11…`. Never the raw key, and never a prefix long enough to be usable. Correlation needs a stable pseudonym, not a credential. |
| `principal_ip` | string | Source address. |
| `request_id` | string | Gateway-assigned, for joining to application logs. |
| `endpoint` | string | Request path, e.g. `/v1/messages`. |

### Prompt payload

| Field | Type | Notes |
|---|---|---|
| `prompt` | string | The user-supplied prompt body. **Privacy-sensitive** — see below. |
| `prompt_chars` | integer | **Required.** Length of the prompt body in characters. |
| `prompt_turn_markers` | integer | **Required.** Count of role delimiters (`Human:`, `Assistant:`, `User:`, chat-template equivalents) found inside a *single* prompt body. This is the field that makes many-shot scaffolding detectable. |

`prompt` is the field a deployment is most likely to withhold, redact, or
truncate, and that is a legitimate choice. **The structural fields are the reason
the split matters:** `prompt_chars` and `prompt_turn_markers` carry no user
content, so a gateway that cannot log prompt bodies at all can still support
structural detections. A schema that only offers the raw prompt forces an
all-or-nothing privacy decision; this one does not.

### Model response

| Field | Type | Notes |
|---|---|---|
| `stop_reason` | string | **Required.** The API's own terminal state — `end_turn`, `refusal`, `max_tokens`, `tool_use`, `stop_sequence`. |
| `stop_details.category` | string | Refusal category where the API supplies one. |
| `model_requested` | string | What the caller asked for. |
| `model_served` | string | What actually served it. These differ under aliasing and the difference matters when reading a finding months later. |
| `input_tokens` / `output_tokens` | integer | Usage. Drives volumetric and extraction rules. |

`stop_reason` deserves emphasis. Detecting refusals by string-matching response
text for "I can't help with that" is fragile and localisation-dependent; the API
reports its own terminal state directly. Any gateway that discards it is throwing
away the single highest-quality safety signal it has.

## UDM mapping (Google SecOps)

The YARA-L rules in this repository read these fields from UDM `NETWORK_HTTP`
events:

| Contract field | UDM path |
|---|---|
| `api_key_id` | `additional.fields["api_key_id"]` |
| `stop_reason` | `additional.fields["stop_reason"]` |
| `principal_ip` | `principal.ip` |
| `endpoint` | `target.url` |

## Two tagging gaps found while validating

Running `sigma check` against these rules surfaces two problems that a logsource
alone does not fix:

1. **There is no `atlas.` tag namespace.** Tagging a rule with
   `atlas.aml.t0051` raises `InvalidNamespaceTagIssue`. MITRE ATLAS is the
   framework for adversarial ML, so detections on this surface have nowhere
   standard to record which technique they cover. Sigma's taxonomy needs an
   `atlas.` namespace, or an agreed convention for referencing ATLAS IDs.

2. **ATT&CK tactic tags are rejected for these rules.** `attack.defense_evasion`
   and `attack.defense-evasion` both raise `InvalidATTACKTagIssue`, while
   `attack.execution` and technique IDs such as `attack.t1059` validate cleanly.
   Multi-word tactic tags need a documented form.

The deeper version of problem 1 is not Sigma's to solve. Anthropic's threat
intelligence team, mapping a year of AI-enabled cyber activity to ATT&CK,
reported that *"there is no ATT&CK ID for this type of agentic orchestration"*.
Framework coverage for AI-enabled attacker behaviour is genuinely incomplete, and
detection content is running ahead of the taxonomies used to describe it.

## Open questions

- Should `prompt` be in the logsource contract at all, or should the standard
  assume redaction and define a `prompt_sha256` alongside the structural fields?
- Is `prompt_turn_markers` better defined as a raw count, or normalised per
  thousand characters so thresholds port across deployments?
- Multi-turn APIs pass an array of messages. Does the contract describe the whole
  request, or one message? These rules assume the whole request.
- Should agentic traffic (tool calls, sub-agent chains) get its own service under
  the same product, rather than being flattened into `inference_api`?

## References

- SigmaHQ specification — <https://github.com/SigmaHQ/sigma-specification>
- MITRE ATLAS — <https://atlas.mitre.org/>
- Anthropic, *What we learned mapping a year's worth of AI-enabled cyber threats*
- Anthropic, *Many-shot jailbreaking* — <https://www.anthropic.com/research/many-shot-jailbreaking>
- Shen et al., *"Do Anything Now"*, ACM CCS 2024 — <https://arxiv.org/abs/2308.03825>
- WildTeaming — <https://arxiv.org/abs/2406.18510>
