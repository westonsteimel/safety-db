Consider using the data from the [Python Packaging Advisory Database](https://github.com/pypa/advisory-db) instead of this.  It is available in the [OSV json schema](https://ossf.github.io/osv-schema/) from via https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip.  You can also audit pip dependencies directly using [pip-audit](https://github.com/trailofbits/pip-audit).

# safety-db
A custom-generated database of insecure Python packages compatible with the pyup.io [safety](https://github.com/pyupio/safety) tool.

## Getting Started

You can use this custom database using something like:

```console
git clone --depth 1 https://github.com/westonsteimel/safety-db /tmp/safety-db
safety check --db /tmp/safety-db/data/
```

