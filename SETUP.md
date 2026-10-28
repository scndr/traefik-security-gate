# Local development

## Build

```bash
go build ./...
```

## Vet

```bash
go vet ./...
```

## Test

```bash
# run all tests
go test ./...

# verbose output (shows each test with PASS/FAIL)
go test -v ./...

# run only tests whose name contains a given string
go test -run TestMTLS ./...

# run with race detector
go test -race ./...
```

## Lint

Requires [golangci-lint](https://golangci-lint.run/):

```bash
golangci-lint run
```

## Local Traefik integration

Mount the plugin directory and add it to the static configuration:

```yaml
experimental:
  localPlugins:
    securitygate:
      moduleName: github.com/scndr/traefik-security-gate
```

The plugin directory must be mounted at:

```
/plugins-local/src/github.com/scndr/traefik-security-gate/
```
