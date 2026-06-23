# Host Benchmark

`benchyd` is a server that benchmarks Sia hosts over RHP4. It runs a single-address
wallet and a consensus node, forms a contract with a target host, then measures
upload and download throughput, latency, and cost.

## Building

`benchyd` uses SQLite, so CGO must be enabled (the default on most platforms):

```sh
CGO_ENABLED=1 go build -o bin/ ./cmd/benchyd
```

A container image is published to the GitHub Container Registry:

```sh
docker run -d --name benchyd \
  -e BENCHY_SEED="your twelve word recovery phrase" \
  -p 8484:8484 -p 9981:9981 \
  -v benchyd-data:/data \
  ghcr.io/siafoundation/host-bench
```

The image exposes the API on `8484` and the syncer on `9981`, and stores data in
the `/data` volume.

## Configuration

Configuration is resolved in three layers, each overriding the previous:

1. Built-in defaults.
2. A `benchy.yml` config file.
3. Command line flags.

The wallet seed is read from the `BENCHY_SEED` environment variable when it is not
set in the config file. It is the only value read from the environment.

### Config file

On startup `benchyd` looks for `benchy.yml` in the following locations, in order,
and uses the first one found:

1. `./benchy.yml`
2. `<data directory>/benchy.yml`
3. The OS config directory:
   - Linux: `/etc/benchyd/benchy.yml`
   - macOS: `~/Library/Application Support/benchyd/benchy.yml`
   - Windows: `%APPDATA%\benchyd\benchy.yml`

Run `benchyd config` to generate a config file interactively.

All fields are optional. A complete file with the defaults looks like this:

```yaml
directory: ""
recoveryPhrase: ""
http:
  address: :8484
syncer:
  address: :9981
  bootstrap: true
  peers: []
consensus:
  network: mainnet
explorer:
  url: ""
log:
  stdout:
    enabled: true
    level: info
    format: human
    enableANSI: true
  file:
    enabled: false
    level: info
    format: json
    path: ""
```

Notes:

- `recoveryPhrase` is the wallet seed. Prefer the `BENCHY_SEED` environment
  variable for it rather than committing it to disk.
- `explorer.url` is only used for instant sync. When empty it defaults to
  `https://api.siascan.com` (`https://api.siascan.com/zen` on the `zen` network).
- `log.file.path` defaults to `<data directory>/benchyd.log` when file logging is
  enabled without a path.

## CLI

```
benchyd [flags] [command]
```

Running `benchyd` with no command starts the daemon.

| Flag | Default | Description |
| --- | --- | --- |
| `-dir` | OS data directory | Data directory |
| `-api.addr` | `:8484` | API listen address |
| `-syncer.addr` | `:9981` | Syncer listen address |
| `-bootstrap` | `true` | Connect to bootstrap peers |
| `-network` | `mainnet` | Network: `mainnet` or `zen` |
| `-instant` | `false` | Instant sync from an explorer checkpoint |
| `-log.level` | | Override the log level: `debug`, `info`, `warn`, `error` |

When `-dir` is not set, the data directory defaults to the current directory if it
already contains a `benchy.sqlite3` or `consensus.db`, otherwise to the OS data
directory (`/var/lib/benchyd` on Linux, `~/Library/Application Support/benchyd` on
macOS, `%APPDATA%\benchyd` on Windows).

Commands:

| Command | Description |
| --- | --- |
| `seed` | Generate a new wallet seed and print its address |
| `config` | Interactively generate a config file |
| `version` | Print the version |

## Running

1. Generate a wallet seed and note the recovery phrase and address:

   ```sh
   benchyd seed
   ```

2. Provide the seed through the environment (or `recoveryPhrase` in `benchy.yml`)
   and start the daemon:

   ```sh
   export BENCHY_SEED="your twelve word recovery phrase"
   benchyd -network zen
   ```

   The node syncs the chain on first start. Pass `-instant` to sync from an
   explorer checkpoint instead of from genesis.

3. Send Siacoin to the wallet address. Benchmarking forms a contract, so the
   wallet must hold funds. Check the balance and sync height:

   ```sh
   curl localhost:8484/wallet
   ```

4. Scan a host to read its current settings:

   ```sh
   curl localhost:8484/scan -X POST -d '{
     "address": "host.example.com:9984",
     "hostKey": "ed25519:..."
   }'
   ```

5. Benchmark a host by uploading and downloading the given number of sectors:

   ```sh
   curl localhost:8484/benchmark -X POST -d '{
     "address": "host.example.com:9984",
     "hostKey": "ed25519:...",
     "sectors": 64
   }'
   ```

The full API is described in [api/openapi.yaml](api/openapi.yaml).
