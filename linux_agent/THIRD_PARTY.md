# Third-party components

The MIT license in `LICENSE` covers the Vajra code in this repository. The agent installs
these components, which keep their own licenses.

| Component | Used as | License |
|---|---|---|
| osquery (`osqueryd`) | the endpoint query engine, supplied as `common/osqueryd` (fetched at build time, not stored in git) | Apache-2.0 or GPL-2.0, at your choice |
| ClamAV (optional, `-installav`) | installed from the distribution's packages | GPL-2.0 |

This list was written by hand and is not a legal review. Check it against what you ship in the package.
