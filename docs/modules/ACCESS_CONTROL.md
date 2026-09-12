# Broken Access Control Engine

**Input:** either two dedicated test identities for differential comparison, or one test identity plus `--object-param`/`--object-value` for same-session object mutation. Optional markers strengthen both modes.

**How it works:** comparison mode requests the same resource under both identities; object-mutation mode requests the baseline object and a second object identifier under the same session. Both modes compare status, size, fingerprints, JSON shape, and operator-supplied markers.

**Evidence:** differential response metadata and matched markers.

**Best signal:** an A-only marker returned to Identity B.


### Object/resource mutation mode

Use one dedicated test session with `--object-param/-P` and `--object-value/-V`. The engine requests the baseline URL and then the mutated object identifier without following redirects. An optional `--marker-target/-N` marker can raise confidence when it is absent from the baseline response but appears in the mutated response. Generic 200/2xx similarity is reported only as a candidate; it is never treated as proof by itself.
