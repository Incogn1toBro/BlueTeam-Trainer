# Contributing to Blue Team Trainer

Thank you for the interest. This lab gets better when more people add to it.

## What is especially welcome

- **More techniques.** The frontend's `TECHNIQUES` array in `blueteam-trainer.jsx` is straightforward to extend. Add an entry with `id`, `tactic`, `name`, `description`, `atomicTests`, `huntPack` and the `offlineCapable` / `prereqStage` flags. Match the shape of existing entries.
- **Better hunt packs.** Real-world SPL queries you have used in investigations are gold here. Same for VQL artifacts and PowerShell live response one-liners.
- **Scenario templates.** Realistic attack chains (insider threat, business email compromise, ransomware operator) make the platform more useful as training.
- **Bug fixes and clarifications** in `BUILD.md`. If you build the lab and hit something the guide does not cover, that is worth a PR.

## Getting started

1. Fork the repo
2. Build the lab using `BUILD.md` to confirm everything works on your end
3. Make your changes
4. Test them — for technique additions, actually detonate the test against your lab Victim and verify the hunt pack queries return what you expect
5. Open a PR with a clear description of what you changed and why

## Style notes

- **Keep `BUILD.md` linear.** It is the most-read document. New phases or steps belong there only if they are essential to first-time setup.
- **Reference docs go in `docs/`.** Use `REFERENCE.md` for detailed explanations and troubleshooting.
- **Keep the frontend single-file.** The `.jsx` is bundled into a self-contained `.html` for offline analyst-laptop use. Adding new dependencies makes the bundle harder to ship.
- **Commit `.env.example` updates** whenever you add new env vars. Do not commit `.env`.

## Safety

This is a lab platform that detonates real malicious tradecraft on a victim VM. Anything that:

- Removes the explicit "lab use only" warnings
- Targets a real system rather than the lab VM
- Could be repurposed offensively against systems the user does not own

…will not be merged. Educational defensive use is the only goal.
