# Documentation development

The root README introduces DevBox Gateway and links to the detailed guides in
`page/docs/`. Keep each detailed guide in one maintained location, and link to
it from the README or other guides. Contributor setup remains in
[`CONTRIBUTING.md`](https://github.com/define42/DevBox-Gateway/blob/main/CONTRIBUTING.md),
while image recipes and SauronAgent keep their component-specific documentation
alongside their sources.

## Preview locally

Run these commands from the repository root with Python 3.12 and its `venv`
module available. The site uses MkDocs with the Material theme; its dependencies
are pinned in `page/requirements.txt`.

```sh
python3 -m venv /tmp/devbox-docs-venv
/tmp/devbox-docs-venv/bin/python -m pip install -r page/requirements.txt
/tmp/devbox-docs-venv/bin/python -m mkdocs serve --config-file page/mkdocs.yml
```

Open `http://127.0.0.1:8000` to preview the site. Editing a page rebuilds the
preview. Docker, libvirt, and a running gateway are not needed to build or
preview the documentation.

## Validate changes

```sh
/tmp/devbox-docs-venv/bin/python -m mkdocs build --strict --config-file page/mkdocs.yml
git diff --check
```

The generated site is written to `page/site/`, which is ignored by Git. Strict
builds fail on documentation warnings, including missing pages and broken
links or section anchors within the site. They do not check external websites.

When adding or moving a guide:

- Update the navigation in `page/mkdocs.yml`.
- Use relative Markdown links between pages inside `page/docs/` so links work
  in the repository and in the generated site.
- Use full GitHub URLs for source files and component guides outside the site.
- Update links in the README, `CONTRIBUTING.md`, component documentation, and
  `llms.txt` when their targets move.
- Keep release-note guide links in `.github/workflows/go.yml` pinned to the
  release's Git tag, using `page/docs/` paths within that tag.

## Publishing

The [documentation workflow](https://github.com/define42/DevBox-Gateway/blob/main/.github/workflows/pages.yml)
builds the site in strict mode for pull requests and pushes to `main` that
change documentation or the workflow. After a successful build on a push to
`main`, it publishes the site to the `gh-pages` branch with `mkdocs gh-deploy`.

In the repository's **Settings → Pages**, configure **Deploy from a branch**
with branch **gh-pages** and folder **/ (root)**. The configured site address is
`https://define42.github.io/DevBox-Gateway/`. Publishing follows a merge or push
to `main`; building or previewing locally does not publish the site.
