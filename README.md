# ICAP Inspector

A web page that talks ICAP (RFC 3507) directly to any ICAP server (antivirus, DLP, content-filtering gateways and so on), without a proxy in between. It shows every protocol step live: connect, request headers, preview, `100 Continue`, scan wait, response, and the encapsulated HTTP and body.

Browsers can't open raw TCP sockets, so a small Node.js backend (`server.js`, no dependencies) performs the ICAP transactions and streams each step to the page.

## Run

Requires Node.js 18 or later. Nothing else to install.

```
npx github:reddoubledecker/icap-inspector --open
```

Or from a clone:

```
git clone https://github.com/reddoubledecker/icap-inspector.git
cd icap-inspector
node bin/icap-inspector.js --open      # Windows: start.cmd
```

Then open http://127.0.0.1:8090 if the browser didn't open by itself.

| Option                | Env var         | Default     | Purpose                                            |
|-----------------------|-----------------|-------------|----------------------------------------------------|
| `-p, --port <n>`      | `PORT`          | `8090`      | Web UI port                                        |
| `-b, --bind <addr>`   | `BIND`          | `127.0.0.1` | Use `0.0.0.0` to open the UI from other lab hosts  |
| `--max-upload-mb <n>` | `MAX_UPLOAD_MB` | `200`       | Largest file you can upload                        |
| `-o, --open`          |                 |             | Open the UI in the default browser                 |

By default the UI only listens on this machine. The tool can connect to any host you type in, so only expose it with `--bind 0.0.0.0` on a trusted lab network.

## Test samples

The built-in samples are generated in memory when the server starts. None of them are stored as files in this repository:

| Sample              | What it tests                                                                  |
|---------------------|--------------------------------------------------------------------------------|
| `clean.txt`         | Normal allow path                                                              |
| `eicar.com`         | Antivirus detection, using the [EICAR](https://www.eicar.org/) test string    |
| `eicar.zip`         | Detection inside an archive                                                    |
| `eicar-nested.zip`  | Detection three archive levels deep                                            |
| `invoice.pdf`       | A real, harmless Windows program (it only exits) named as a PDF, for file-type verification |
| `customers.csv`     | DLP, using publicly documented test card numbers and SSNs                      |
| `large-clean.txt`   | 10 MB file, for size limits, preview and throughput                            |

EICAR is harmless, but it is designed to be detected. Antivirus on the machine running the ICAP server may flag the scanner's temporary files, and on managed machines a detection may alert your security team. Tell them before you test.

## Using it

1. Enter the ICAP host and port (1344, or 11344 for ICAPS), then click **Probe service (OPTIONS)**.
   This confirms the service name and shows the server's Methods, Preview size and ISTag.
2. Pick **RESPMOD** (simulates a download) or **REQMOD** (simulates an upload).
3. Choose a built-in sample or drop in your own file, then click **Send to ICAP**.
4. Click any step in the timeline to see the raw bytes on the wire.
5. **Run test suite** sends every built-in sample and compares each result with what it should be.

The service name is the path after the port in `icap://host:port/<service>`, and each ICAP product names it differently.
Look it up in your server's configuration or documentation. If OPTIONS returns 404, the service name is wrong.
Your settings are remembered in the browser.

## How verdicts are derived

| ICAP response                                       | Shown as |
|-----------------------------------------------------|----------|
| `204 No Content`                                    | Allowed  |
| `200` + encapsulated HTTP 4xx/5xx (block page)      | Blocked  |
| `200` to REQMOD with a `res-hdr` (upload replaced)  | Blocked  |
| `200` + body identical to what was sent             | Allowed  |
| `200` + different body (CDR / DLP redaction)        | Modified |

ICAP `X-*` response headers (e.g. `X-Infection-Found`, `X-Violations-Found`) are highlighted in the details panel.
