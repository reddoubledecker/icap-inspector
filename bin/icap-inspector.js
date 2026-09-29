#!/usr/bin/env node
'use strict';
// CLI entry point: `npx icap-inspector [--port 8090] [--bind 127.0.0.1] [--open]`

const { execFile } = require('child_process');
const pkg = require('../package.json');

const HELP = `ICAP Inspector ${pkg.version}
${pkg.description}

Usage: icap-inspector [options]

Options:
  -p, --port <n>           Web UI port (default 8090, env PORT)
  -b, --bind <addr>        Address to listen on (default 127.0.0.1, env BIND)
                           Use 0.0.0.0 to reach the UI from other lab machines.
      --max-upload-mb <n>  Largest file you can upload (default 200, env MAX_UPLOAD_MB)
  -o, --open               Open the UI in the default browser
  -v, --version            Print the version
  -h, --help               Show this help
`;

const args = process.argv.slice(2);
let open = false;
for (let i = 0; i < args.length; i++) {
  const [flag, inline] = args[i].split(/=(.*)/s);
  const value = () => {
    const v = inline !== undefined ? inline : args[++i];
    if (v === undefined || v === '') { console.error(`${flag} needs a value`); process.exit(2); }
    return v;
  };
  switch (flag) {
    case '-p': case '--port': process.env.PORT = value(); break;
    case '-b': case '--bind': process.env.BIND = value(); break;
    case '--max-upload-mb': process.env.MAX_UPLOAD_MB = value(); break;
    case '-o': case '--open': open = true; break;
    case '-v': case '--version': console.log(pkg.version); process.exit(0); break;
    case '-h': case '--help': console.log(HELP); process.exit(0); break;
    default: console.error(`Unknown option: ${args[i]}\n\n${HELP}`); process.exit(2);
  }
}

const server = require('../server.js');

if (open) {
  server.once('ready', (url) => {
    const [cmd, cmdArgs] = process.platform === 'win32' ? ['cmd', ['/c', 'start', '""', url]]
      : process.platform === 'darwin' ? ['open', [url]]
      : ['xdg-open', [url]];
    execFile(cmd, cmdArgs, { windowsHide: true }, (e) => { if (e) console.log(`Could not open a browser — go to ${url}`); });
  });
}
