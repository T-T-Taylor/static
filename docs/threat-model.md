# Static Threat Model

## Adversaries

1. Global passive adversary (ISP, nation-state)
2. Malicious node operators
3. Physical seizure of nodes
4. Active attacker (inject/delay/drop traffic)

## What We Protect

- Content identity (what is being sent)
- Communication relationships (who talks to whom)
- Hosting location (where content physically lives)
- Node activity patterns (is a node active or idle)

## What We Do Not Protect

- Endpoint compromise (machine is hacked)
- Physical coercion (torture for keys)
- Large-scale active attacks (mitigated, not eliminated)

Detailed threat model to be written as implementation progresses.
