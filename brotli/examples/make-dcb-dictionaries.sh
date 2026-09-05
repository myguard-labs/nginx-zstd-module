#!/bin/bash
# Regenerate the dictionary include from each app's previous release.
#
# Run right after flipping the `current` symlink(s), and BEFORE any
# release cleanup deletes old dirs (nginx -t fails on a dangling
# dictionary path).
set -euo pipefail

### Begin setup vars ###########################################################
BASEDIR=/var/www
APPS=( "app" )                  # one entry per deployed app under $BASEDIR
CONF=/etc/nginx/dcb-dictionaries.conf
### End setup vars #############################################################

# Use realpaths in case the websites are located on a symlinked path to a
# mount: `ls` under the symlink path and `readlink -f current` would
# disagree (one symlink path, one realpath), so the previous-release
# filter below would silently keep the current release — duplicating the
# live files as their own "previous" version instead of finding the real
# one.
BASEDIR=$(realpath "$BASEDIR")
CONF=$(realpath -m "$CONF")

# Create or truncate the tmp CONF file
: > "$CONF.tmp"

# Use a "seen" dictionary to prevent duplicates, shared across all apps:
# the module refuses duplicate-content dictionaries at config load, and
# builds routinely produce byte-identical files (e.g. per-locale copies).
# One entry serves every URL — the hash lookup is URL-independent.
declare -A seen

for app in "${APPS[@]}"; do
    APPDIR=$BASEDIR/$app

    # previous release = newest dir that is not what `current` points at.
    # No previous release yet (first deploy): skip the app — that deploy
    # only plants dictionaries in browsers, dcb starts on the next one.
    current=$(readlink -f "$APPDIR/current")
    prev=$(ls -1dt "$APPDIR"/releases/*/ 2>/dev/null | grep -vF "$current/" | head -1 || true)
    [ -n "$prev" ] || continue

    # NOTE: all registered files are held in worker memory: the combined
    #   (deduped) file sizes in steady state — one physical copy shared
    #   across workers via fork/COW — and up to 2x during a graceful
    #   reload until the last old worker drains (bounded by
    #   worker_shutdown_timeout). Each in-flight dcb response additionally
    #   uses roughly dictionary-sized scratch memory while compressing.
    #   Double both figures if the dcz twin lines below are enabled.
    echo -e "\n# $app" >> "$CONF.tmp"

    # The inner glob must mirror your build layout. This matches
    # <release>/<localedir>/main-HASH.js style output; for single-dir
    # builds flatten it to e.g. "$prev"assets/{main,polyfills}-*.js
    for f in "$prev"*/{main,polyfills,scripts}-*.js "$prev"*/styles-*.css; do
        [ -f "$f" ] || continue
        h=$(sha256sum "$f" | cut -d' ' -f1)
        [ -n "${seen[$h]:-}" ] && continue          # dedupe: identical across locales
        seen[$h]=1
        # The hash we just computed doubles as the directive's optional
        # second argument: the module trusts it verbatim and skips its
        # own read-and-hash pass, which dominates nginx -t/reload time
        # at hundreds of dictionaries. Safe here because these are
        # content-hashed immutable release files and this script is the
        # single source of the config — if you edit dictionary files in
        # place, drop the argument and let the module hash them itself.
        printf 'brotli_dcb_dict_file %s %s;\n' "$f" "$h" >> "$CONF.tmp"
        # Serving dcz from the same dictionaries (nginx-zstd-module) —
        # clients pick one coding:
        #printf 'zstd_dcz_dict_file %s %s;\n'   "$f" "$h" >> "$CONF.tmp"
    done
done

# Finished. Move tmp config into place and reload nginx for it to take
# effect.
mv "$CONF.tmp" "$CONF"
nginx -t && nginx -s reload
