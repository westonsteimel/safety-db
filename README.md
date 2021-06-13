# safety-db
A custom-generated database of insecure Python packages compatible with the pyup.io [safety](https://github.com/pyupio/safety) tool.

## Getting Started

You can use this custom database using something like:

```console
git clone --depth 1 https://github.com/westonsteimel/safety-db /tmp/safety-db
safety check --db /tmp/safety-db/data/
```

