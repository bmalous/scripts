#!/usr/bin/env bash
set -euo pipefail

TITLE="Hash Compare"

dialog() {
    local msg="$1"
    if command -v zenity >/dev/null 2>&1; then
        zenity --info --no-markup --no-wrap --title="$TITLE" --text="$msg" || true
    else
        printf '%s\n' "$msg"
    fi
}

die() { printf '%s\n' "$1" >&2; exit 1; }

clipboard_text() {
    local data=""
    if [[ -n "${WAYLAND_DISPLAY:-}" ]] && command -v wl-paste >/dev/null 2>&1; then
        data=$(wl-paste --no-newline 2>/dev/null || true)
    elif command -v xclip >/dev/null 2>&1; then
        data=$(xclip -selection clipboard -o 2>/dev/null || true)
    elif command -v xsel >/dev/null 2>&1; then
        data=$(xsel --clipboard --output 2>/dev/null || true)
    else
        die "Clipboard utility not found"
    fi
    printf '%s' "$data"
}

hash_stream() {
    local algo="$1"
    python3 - "$algo" <<'PYHASH'
import binascii, hashlib, sys, zlib
algo = sys.argv[1]
chunk = 1024 * 1024
buf = sys.stdin.buffer

def finish(tag, value=""):
    print(f"{tag} {algo} {value}")
    sys.exit(0)

core = {
    "MD5": "md5", "SHA1": "sha1", "SHA224": "sha224", "SHA256": "sha256",
    "SHA384": "sha384", "SHA512": "sha512",
    "SHA3-224": "sha3_224", "SHA3-256": "sha3_256",
    "SHA3-384": "sha3_384", "SHA3-512": "sha3_512",
    "BLAKE2b": "blake2b", "BLAKE2s": "blake2s",
}
if algo in core:
    func = getattr(hashlib, core[algo], None)
    if not func:
        finish("MISSING")
    h = func()
    while True:
        block = buf.read(chunk)
        if not block:
            break
        h.update(block)
    finish("COMPUTED", h.hexdigest().lower())

if algo == "WHIRLPOOL":
    if "whirlpool" in hashlib.algorithms_available:
        try:
            h = hashlib.new("whirlpool")
        except Exception:
            finish("MISSING")
        for block in iter(lambda: buf.read(chunk), b""):
            h.update(block)
        finish("COMPUTED", h.hexdigest().lower())
    finish("MISSING")

if algo == "RIPEMD":
    name = next((n for n in ("ripemd160", "RIPEMD160") if n in hashlib.algorithms_available), None)
    if not name:
        finish("MISSING")
    try:
        h = hashlib.new(name)
    except Exception:
        finish("MISSING")
    for block in iter(lambda: buf.read(chunk), b""):
        h.update(block)
    finish("COMPUTED", h.hexdigest().lower())

if algo == "BLAKE3":
    try:
        import blake3
    except Exception:
        finish("MISSING")
    h = blake3.blake3()
    for block in iter(lambda: buf.read(chunk), b""):
        h.update(block)
    finish("COMPUTED", h.hexdigest().lower())

if algo == "XXHash":
    try:
        import xxhash
    except Exception:
        finish("MISSING")
    h = xxhash.xxh64()
    for block in iter(lambda: buf.read(chunk), b""):
        h.update(block)
    finish("COMPUTED", h.hexdigest().lower())

if algo == "CRC32":
    value = 0
    for block in iter(lambda: buf.read(chunk), b""):
        value = binascii.crc32(block, value)
    finish("COMPUTED", f"{value & 0xffffffff:08x}")

if algo == "Adler32":
    value = 1
    for block in iter(lambda: buf.read(chunk), b""):
        value = zlib.adler32(block, value)
    finish("COMPUTED", f"{value & 0xffffffff:08x}")

finish("MISSING")
PYHASH
}

run_parallel() {
    local target="$1"; shift
    local tmpdir; tmpdir=$(mktemp -d) || return 1
    local pipes="" algo
    for algo in "$@"; do
        local out="$tmpdir/$algo.out"
        pipes+=" >(hash_stream $(printf '%q' "$algo") >$(printf '%q' "$out"))"
    done
    local cmd="tee${pipes} >/dev/null"
    if ! eval "$cmd" <"$target"; then
        rm -rf "$tmpdir"
        return 1
    fi
    local output=""
    for algo in "$@"; do
        local out="$tmpdir/$algo.out"
        [[ -f "$out" ]] && output+=$(<"$out")$'\n'
    done
    rm -rf "$tmpdir"
    printf '%s' "$output"
}

[[ $# -gt 0 ]] || die "No files provided"
command -v python3 >/dev/null 2>&1 || die "python3 required"

clipboard=$(clipboard_text | tr -d '[:space:]')
[[ -n "$clipboard" ]] || die "Clipboard empty"
[[ "$clipboard" =~ ^[[:xdigit:]]+$ ]] || die "Clipboard not hex"

clipboard_lower=${clipboard,,}
case ${#clipboard} in
    8)   algos=(CRC32 Adler32) ;;
    16)  algos=(XXHash) ;;
    32)  algos=(MD5) ;;
    40)  algos=(SHA1 RIPEMD) ;;
    56)  algos=(SHA224 SHA3-224) ;;
    64)  algos=(SHA256 SHA3-256 BLAKE2s BLAKE3) ;;
    96)  algos=(SHA384 SHA3-384) ;;
    128) algos=(SHA512 SHA3-512 BLAKE2b WHIRLPOOL) ;;
    *)   die "Unsupported hash length ${#clipboard}" ;;
esac

results=()
for path in "$@"; do
    if [[ ! -f "$path" ]]; then
        results+=("$path: Did Not Match")
        continue
    fi
    if ! output=$(run_parallel "$path" "${algos[@]}"); then
        results+=("$(basename -- "$path"): Did Not Match")
        continue
    fi
    declare -A hashes=()
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        if [[ $line == COMPUTED* ]]; then
            read -r _ algo digest <<<"$line"
            hashes[$algo]=$digest
        fi
    done <<<"$output"
    matches=()
    for algo in "${algos[@]}"; do
        [[ ${hashes[$algo]:-} == "$clipboard_lower" ]] && matches+=("$algo")
    done
    if [[ ${#matches[@]} -gt 0 ]]; then
        results+=("$(basename -- "$path"): Matched ${matches[*]}")
    else
        results+=("$(basename -- "$path"): Did Not Match")
    fi
    unset hashes
done

dialog "$(printf '%s\n' "${results[@]}")"
