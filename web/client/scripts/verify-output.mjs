// Post-`nuxt generate` integrity gate.
//
// The root shell is written twice by the SPA build: once as 200.html (the
// fallback) and once as index.html, from the same document. The index.html copy
// comes out short — correct final size, data only up to a cutoff, tail
// NUL-padded — which slices the inline `window.__NUXT__.config = {...}` literal
// in half. The browser hits a SyntaxError there, never assigns the config, and
// the deferred entry chunk dies on `useRuntimeConfig().app` with
// "om() is undefined". Nothing about it is visible at build time: the file
// exists, the byte count looks right, and every deep-linked route is fine
// because only index.html is affected.
//
// So: repair index.html from 200.html when it is provably damaged, then refuse
// to ship any shell that doesn't close its document.

import { readFile, writeFile } from "node:fs/promises";
import { readdirSync } from "node:fs";
import { join, relative } from "node:path";

// Defaults to the generate output; the release flow also points it at the
// staged embed payload, since the copy in between can short-write too.
const ROOT = process.argv[2] ?? ".output/public";

function htmlFiles(dir) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...htmlFiles(path));
    else if (entry.name.endsWith(".html")) out.push(path);
  }
  return out;
}

function damage(buf) {
  if (buf.includes(0)) return `NUL byte at offset ${buf.indexOf(0)}`;
  if (!buf.subarray(-32).includes("</html>")) return "does not close </html>";
  return null;
}

const fallback = join(ROOT, "200.html");
const index = join(ROOT, "index.html");

const indexBuf = await readFile(index);
if (damage(indexBuf)) {
  const fallbackBuf = await readFile(fallback);
  if (damage(fallbackBuf)) {
    throw new Error(
      `both ${relative(".", index)} (${damage(indexBuf)}) and its ${relative(".", fallback)} ` +
        `source (${damage(fallbackBuf)}) are damaged — nothing to repair from`,
    );
  }
  await writeFile(index, fallbackBuf);
  console.log(
    `verify-output: repaired index.html from 200.html (was ${indexBuf.length}B, ${damage(indexBuf)})`,
  );
}

const broken = [];
for (const file of htmlFiles(ROOT)) {
  const reason = damage(await readFile(file));
  if (reason) broken.push(`${relative(".", file)}: ${reason}`);
}

if (broken.length) {
  throw new Error(`damaged prerender output:\n  ${broken.join("\n  ")}`);
}

console.log("verify-output: all prerendered shells intact");
