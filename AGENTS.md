# Project rules

- All application workflows remain dry-run until the user approves an exact live workflow.
- Never add personal names, email addresses, private deployment hostnames, domains, IP or MAC addresses, personal usernames or paths, hardware specifications, or credentials to repository files or Git metadata.
- Keep live configuration, operational logs/state and downloaded data outside the checkout.
- Keep the handoff exclusively in the administration user's home directory, never in this repository.
- Keep project documentation in the repository using generic configurable examples.
- Public checker scope requires exact category, corresponding Sonarr queue hash, recorded Sonarr grab history and known content identity. Category alone is insufficient.
- Classify sources through explicit per-instance indexer lists. Private and unknown sources are protected.
- Paused/stopped status is never evidence of failure. Never resume torrents.
- Do not access media-library files, change seeding policies, execute payloads, or mutate production queues/downloads during dry-run.
- Review staged contents and author metadata before commits. Do not commit or push without satisfying privacy requirements.
