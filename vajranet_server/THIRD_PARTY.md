# Third-party components

The MIT license in `LICENSE` covers the Vajra code in this repository. The backend and frontend
use many npm packages, each with its own license (see `backend/package.json` and
`frontend/package.json`). To list them all, run `npx license-checker --summary` in `backend/`
and in `frontend/`.

Other included material:

| Component | Where | License |
|---|---|---|
| Sample saved queries | `backend/data/savedqueries.csv` | the query names look like osquery community queries: confirm their origin and license |
| Embedded font | `templates/framework_report1.html` (base64 `@font-face`) | not confirmed: identify the font and check its license |
| Grafana (installed by `grafana/setup.sh`) | not included, installed from Grafana's packages | AGPL-3.0 |

This list was written by hand and is not a legal review.
