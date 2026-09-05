# dcb deployment example

A minimal, ready-to-adapt setup for RFC 9842 shared-dictionary
compression (`Content-Encoding: dcb`) on a site with content-hashed
assets (Angular/Vite/webpack-style `main-C7X1ZM2K.js` names):

- [`dcb-site.conf`](dcb-site.conf) — nginx server config: the
  `Use-As-Dictionary` map, the compression location, and the
  deploy-generated dictionary include.
- [`make-dcb-dictionaries.sh`](make-dcb-dictionaries.sh) — deploy hook
  that regenerates the dictionary include from each app's previous
  release (multi-app aware; a single-app site uses a one-entry `APPS`
  array).

## How it plays out

1. **Deploy N** serves `main-AAA.js` with
   `Use-As-Dictionary: match="/assets/main-*.js"`. Compatible browsers
   (Chromium ≥ 130, HTTPS, same-origin) store the file as a dictionary
   for that pattern.
2. **Deploy N+1** flips the `current` symlink and runs
   `make-dcb-dictionaries.sh`, which registers deploy N's assets as
   dictionaries and reloads nginx.
3. A returning browser requests `main-BBB.js` with
   `Available-Dictionary: :<sha-256>:` and `dcb` in `Accept-Encoding`;
   the module compresses the new file *against the old one* — typically
   a couple of orders of magnitude smaller than plain `br`, since most
   of the file is unchanged.

The first deploy after enabling this only *plants* dictionaries;
`Content-Encoding: dcb` appears from the following deploy on.

## Verifying

```
curl -sk https://example.com/assets/main-AAA.js -o /dev/null \
     -w '%{header_json}' | grep -i use-as-dictionary
```

Then, with `HASH` being `sha256sum old-main.js` in base64
(`openssl dgst -sha256 -binary old-main.js | base64`):

```
curl -sk https://example.com/assets/main-BBB.js \
     -H 'Accept-Encoding: dcb, br' \
     -H "Available-Dictionary: :$HASH:" \
     -H 'Sec-Fetch-Site: same-origin' -o body.dcb
```

Expect `Content-Encoding: dcb`. The payload is the 36-byte dcb header
(magic `FF 44 43 42` + the dictionary SHA-256) followed by a brotli
stream; brotli decoders do **not** skip that header, so strip it first:

```
tail -c +37 body.dcb | brotli -d -D old-main.js > roundtrip.js
diff roundtrip.js new-main.js   # byte-exact
```

In DevTools, the Network tab's `content-encoding` header plus the
transferred-vs-resource size columns tell the whole story.

## Gotchas (each of these was learned the hard way)

- **`include` the generated file — never pass it to
  `brotli_dcb_dict_file` directly.** The directive loads its argument
  *as a dictionary*: you get `Vary: Available-Dictionary` and a
  registered hash that never matches anything. If dcb never negotiates,
  run `nginx -T | grep dcb_dict_file` and check the loaded entries are
  your asset files.
- **Dedupe is mandatory, not an optimization**: the module refuses to
  start on two dictionaries with identical content, and multi-locale
  builds routinely produce byte-identical files (the script dedupes by
  SHA-256; one entry covers every URL — hash lookup is URL-independent).
- **Key the map on `$request_uri`, not `$uri`**: `try_files` and
  internal rewrites change `$uri`, so patterns built from it stop
  matching what the *browser* requested — and the browser's URL is what
  the dictionary match pattern is scoped to.
- **Prune order**: regenerate the include *before* release cleanup
  deletes old dirs — `nginx -t` fails on a dangling dictionary path.
  Never delete the release the live include points at.
- **Canonicalize paths when sites sit behind a symlinked parent**
  (mount points, DRBD/NFS layouts): `ls` under the symlink path and
  `readlink -f current` return different spellings of the same
  directory, so the previous-release filter silently keeps the current
  release — registering the live files as their own "previous" version.
  The script `realpath`s `BASEDIR` up front for exactly this reason.
- **Skip lazy chunks** (`chunk-XXXX.js`): no stable name prefix, no
  sane match pattern. Entry files and styles are most of the win.
- **Memory**: each registered dictionary is held in worker memory
  (shared across requests). Sum the previous release's entry files and
  start with one previous release before getting ambitious.
- Serving `dcz` (nginx-zstd-module) from the same dictionaries works —
  clients pick one coding; the script has the twin line commented out.
