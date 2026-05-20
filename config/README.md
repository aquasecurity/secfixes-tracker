# Configuration

Rewriter and importer settings are synced from [Alpine infra/docker/secfixes-tracker](https://gitlab.alpinelinux.org/alpine/infra/docker/secfixes-tracker).

| Alpine (production) | This repo (active) |
|---------------------|-------------------|
| `config/prod.application.toml` | `config/application.toml` (`db_path` set for local use) |
| `config/prod.settings.py` | `secfixes_tracker/application.cfg` (`CUSTOM_REWRITERS`, `PACKAGE_EXCLUSIONS`) |

`config/prod.*` files mirror upstream for easier diffing when pulling new Alpine commits.

`secfixes_tracker/application.cfg` also keeps repository URLs and is updated by `scripts/update_alpine_config.py` for supported Alpine releases.
