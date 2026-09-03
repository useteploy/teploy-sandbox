# AGENTS.md

This repository is **public** and mirrored to GitHub at https://github.com/useteploy/teploy-sandbox.
Part of the [Teploy](https://teploy.com) ecosystem. Every commit is publicly
visible — treat all work as public-facing.

## Do not commit private/transient context
- No `SESSION_NOTES.md`, `*_NOTES.md`, `HANDOFF*.md`, scratch/status docs
- No `.claude/`, `.opencode/` local configs
- No secrets, no internal network addresses (Tailscale IPs, internal hostnames)
- Use generic fixtures (`forge.example.com`, not real hosts)

## Commits
- Conventional style (`feat:`, `fix:`, `chore:`, `docs:`).

## Remotes
`git push origin` fans out to both Forgejo and GitHub (dual push-URL).
