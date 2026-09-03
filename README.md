# SGdbg

A minimal, professional Hugo blog for malware analysis reports, threat-intel
notes, YARA rules, and automation scripts. Built as a static site so it's
free to host, fast, and fully yours (no platform lock-in).

Live sections: **Writeups** (home + archive), **YARA Rules**, **Scripts**, **About**.

## 1. First-time setup (a few placeholders still to fill in)

The name is set, but a couple of details still need to be yours in `hugo.toml`:

```toml
title  = "SGdbg"                            # your blog name/handle
[params]
  author  = "Shruti Gurlhosur"                     # <- update this
  handle  = "@SGdbg"                        # shown under the homepage title
  tagline = "..."                           # one-line description
  github  = "https://github.com/ShrutiGurlhosur"
  twitter = "https://x.com/shrutigurlhosur"
  email   = "shruti.gurlhosur@gmail.com"
```

Also edit `content/about.md` with your own bio/contact info, and replace
the sample post in `content/posts/` and its matching rule in
`content/yara-rules/` (or just delete both once you've published your own
content).

## 2. Run it locally

Requires [Hugo extended](https://gohugo.io/installation/) (this site was
built and tested against v0.140.2 extended).

```bash
hugo server -D
```

Open the URL it prints (something like `http://localhost:1313/`). `-D`
includes draft posts (anything with `draft: true` in its front matter) so
you can preview before publishing.

## 3. Add new content

```bash
hugo new content posts/my-new-writeup.md        # malware analysis / threat intel / technique
hugo new content yara-rules/my-new-rule.md       # YARA rule entry
hugo new content scripts/my-new-tool.md          # script / tool entry
```

Each archetype (in `themes/carbon/archetypes/`) pre-fills the front matter
fields the theme uses. New posts are created as drafts (`draft: true`) —
flip that to `false` when ready to publish. **Don't put dates in filenames**
(use `my-writeup.md`, not `2026-08-31-my-writeup.md`) — the `date:` field in
the front matter is what controls ordering; a date-prefixed filename just
changes the URL slug.

Post front matter supports a few extras used by the theme:

- `category` — one of `malware-analysis`, `threat-intel`, `technique`, `tool`
  (shown as a badge; you can invent more).
- `tags` — a list, rendered as `#hashtags` and browsable at `/tags/<tag>/`.
- `summary` — a one-line excerpt for list pages (falls back to
  auto-truncated content if omitted).
- `tldr` — an optional highlighted callout at the top of the post.
- `iocs` — a list of `{type, value, note}` objects, rendered as a table at
  the bottom of the post:

  ```yaml
  iocs:
    - type: SHA256
      value: "..."
      note: "dropper"
  ```

YARA rule and script pages support `family` / `language`, `summary`, and
(for rules) `related_post` to link back to the writeup that produced them.

## 4. Publish to GitHub Pages (free hosting)

1. Create a new **public** GitHub repo and push this project to it:

   ```bash
   git init
   git add .
   git commit -m "Initial blog"
   git branch -M main
   git remote add origin https://github.com/<you>/<repo>.git
   git push -u origin main
   ```

2. In the repo, go to **Settings → Pages** and set **Source** to
   **GitHub Actions**. The included workflow
   (`.github/workflows/deploy.yml`) builds the site with Hugo and deploys
   it automatically on every push to `main` — no need to commit the
   built `public/` folder (it's git-ignored).
3. Your site will be live at `https://<you>.github.io/<repo>/` a minute or
   two after the workflow finishes (check the **Actions** tab for progress).

Update `baseURL` in `hugo.toml` to match that URL once you know it — it's
used for the RSS feed and absolute links; the GitHub Actions build itself
auto-detects the right URL regardless.

### Using your own domain

1. Add a `static/CNAME` file containing just your domain
   (e.g. `notes.example.com`) — Hugo copies it to the built site root.
2. Point your domain's DNS at GitHub Pages (an `ALIAS`/`ANAME`/`A` record
   for an apex domain, or a `CNAME` record for a subdomain — see
   [GitHub's docs](https://docs.github.com/pages/configuring-a-custom-domain-for-your-github-pages-site)).
3. Update `baseURL` in `hugo.toml` to `https://notes.example.com/`.

## Project layout

```
content/
  posts/          writeups (malware analysis, threat intel, technique)
  yara-rules/     one file per rule (or per rule family)
  scripts/        one file per script/tool
  about.md
themes/carbon/    the theme (layouts, CSS, JS) — edit freely, it's yours
hugo.toml         site config: title, author, nav, syntax highlighting
.github/workflows/deploy.yml   auto-deploy to GitHub Pages
```

## Notes on the sample content

`content/posts/unpacking-cobweaver-net-loader.md` and
`content/yara-rules/cw-dotnet-loader-stub.md` are a sample writeup + rule
pair included only to show the formatting (front matter fields, IOC table,
code blocks, cross-linking). "CobWeaver" is not a real malware family —
delete both files (or overwrite them) once you've got real content to
publish.
