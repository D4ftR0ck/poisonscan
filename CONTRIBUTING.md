# Contributing rules

1. One rule per YAML file under `rules/<family>/PSN-xxxx-short-name.yml`. Ids are never reused;
   retired rules move to `status: deprecated`.
2. Every rule has `tests.positive` and `tests.negative` examples.
3. Every rule has a synthetic sample in `corpus/poisoned/by-rule/<RULE-ID>.txt` (or `.html`):
   an ordinary-looking document with the payload slipped in. Use fictitious domains
   (`example.test`) and no real personal data or copyrighted text.
4. Run before opening a pull request:

   ```bash
   poisonscan rules lint rules
   poisonscan rules test rules --corpus corpus
   ```

   `rules test` fails if an example is wrong, if a poisoned document is missed, if a
   benign one is flagged, if a `by-rule` sample does not trigger its own rule, or if a
   rule has no `by-rule` sample.

Payloads quoted in articles, papers or test write-ups count as payloads: an LLM that
reads them from a RAG may still follow them. A false positive is ordinary text with no
injection in it, not a quoted attack.
