#!/usr/bin/env bash
set -euo pipefail

SCRIPT_TITLE="Thunar Hash Compare"

show_dialog() {
    local dialog_type="$1"
    local message="$2"

    if command -v zenity >/dev/null 2>&1; then
        if [[ "$dialog_type" == "error" ]]; then
            zenity --error --no-markup --no-wrap --title="$SCRIPT_TITLE" --text="$message" || true
        else
            zenity --info --no-markup --no-wrap --title="$SCRIPT_TITLE" --text="$message" || true
        fi
    else
        if [[ "$dialog_type" == "error" ]]; then
            printf 'Error: %s\n' "$message" >&2
        else
            printf '%s\n' "$message"
        fi
    fi
}

fail() {
    show_dialog error "$1"
    exit 1
}

extract_clipboard() {
    local content=""
    if [[ -n "${WAYLAND_DISPLAY:-}" ]] && command -v wl-paste >/dev/null 2>&1; then
        content=$(wl-paste --no-newline 2>/dev/null || true)
    elif command -v xclip >/dev/null 2>&1; then
        content=$(xclip -selection clipboard -o 2>/dev/null || true)
    elif command -v xsel >/dev/null 2>&1; then
        content=$(xsel --clipboard --output 2>/dev/null || true)
    else
        fail "No clipboard utility found. Install wl-clipboard (Wayland) or xclip/xsel (X11)."
    fi

    printf '%s' "$content"
}

sanitize_hash() {
    local raw="$1"
    local trimmed
    trimmed=$(printf '%s' "$raw" | tr -d '[:space:]')
    printf '%s' "$trimmed"
}

get_possible_algorithms() {
    local hash_len="$1"
    local algorithms=()
    
    case "$hash_len" in
        8)
            algorithms+=(CRC32 Adler32 XXHash)
            ;;
        16)
            algorithms+=(MD5)
            ;;
        32)
            algorithms+=(MD5 SHA256 BLAKE2s)
            ;;
        40)
            algorithms+=(SHA1 RIPEMD)
            ;;
        56)
            algorithms+=(SHA224 SHA3-224)
            ;;
        64)
            algorithms+=(SHA256 SHA3-256 BLAKE2s BLAKE2b XXHash)
            ;;
        96)
            algorithms+=(SHA384 SHA3-384)
            ;;
        128)
            algorithms+=(SHA512 SHA3-512 BLAKE2b WHIRLPOOL)
            ;;
    esac
    
    printf '%s\n' "${algorithms[@]}"
}

if [[ $# -lt 1 ]]; then
    fail "No files provided."
fi

if ! command -v python3 >/dev/null 2>&1; then
    fail "python3 is required but not found in PATH."
fi

clipboard_raw=$(extract_clipboard)
clipboard=$(sanitize_hash "$clipboard_raw")

if [[ -z "$clipboard" ]]; then
    fail "Clipboard does not contain any text."
fi

if [[ ! "$clipboard" =~ ^[[:xdigit:]]+$ ]]; then
    fail "Clipboard content is not a hexadecimal hash."
fi

clipboard_lower=${clipboard,,}
hash_len=${#clipboard}
case "$hash_len" in
    8|16|32|40|56|64|96|128)
        ;;
    *)
        fail "Clipboard hash length ($hash_len) is not supported."
        ;;
esac

# Get possible algorithms for this hash length
mapfile -t possible_algorithms < <(get_possible_algorithms "$hash_len")

declare -a dialog_lines=()

ordered_algorithms=(
    MD5
    SHA1
    SHA224
    SHA256
    SHA384
    SHA512
    SHA3-224
    SHA3-256
    SHA3-384
    SHA3-512
    BLAKE2b
    BLAKE2s
    BLAKE3
    WHIRLPOOL
    RIPEMD
    XXHash
    CRC32
    Adler32
)

for target in "$@"; do
    if [[ ! -f "$target" ]]; then
        dialog_lines+=("$target: Did not Match")
        continue
    fi

    # Create temporary directory for storing hash results
    temp_dir=$(mktemp -d)
    trap "rm -rf '$temp_dir'" EXIT

    # Determine which algorithms to calculate based on hash length
    declare -A needed_algorithms=()
    for algo in "${possible_algorithms[@]}"; do
        needed_algorithms["$algo"]=1
    done

    # Use tee with process substitution for parallel hash calculation
    if ! tee \
        >(python3 - "$target" "$temp_dir" <<'PYBLOCK'
import binascii
import hashlib
import sys
import zlib
from pathlib import Path

path = Path(sys.argv[1])
temp_dir = sys.argv[2]

if not path.exists():
    with open(f"{temp_dir}/error", "w") as f:
        f.write(f"ERROR not-found {path}")
    sys.exit(1)
if not path.is_file():
    with open(f"{temp_dir}/error", "w") as f:
        f.write(f"ERROR not-file {path}")
    sys.exit(1)

hashlib_funcs = [
    ("MD5", "md5"),
    ("SHA1", "sha1"),
    ("SHA224", "sha224"),
    ("SHA256", "sha256"),
    ("SHA384", "sha384"),
    ("SHA512", "sha512"),
    ("SHA3-224", "sha3_224"),
    ("SHA3-256", "sha3_256"),
    ("SHA3-384", "sha3_384"),
    ("SHA3-512", "sha3_512"),
    ("BLAKE2b", "blake2b"),
    ("BLAKE2s", "blake2s"),
]

hashers = []
missing = set()

for name, attr in hashlib_funcs:
    func = getattr(hashlib, attr, None)
    if func is None:
        missing.add(name)
        continue
    hashers.append((name, func()))

if "whirlpool" in hashlib.algorithms_available:
    try:
        hashers.append(("WHIRLPOOL", hashlib.new("whirlpool")))
    except Exception:
        missing.add("WHIRLPOOL")
else:
    missing.add("WHIRLPOOL")

if "ripemd160" in hashlib.algorithms_available:
    try:
        hashers.append(("RIPEMD", hashlib.new("ripemd160")))
    except Exception:
        missing.add("RIPEMD")
else:
    missing.add("RIPEMD")

try:
    import blake3
except Exception:
    missing.add("BLAKE3")
else:
    hashers.append(("BLAKE3", blake3.blake3()))

try:
    import xxhash
except Exception:
    missing.add("XXHash")
else:
    hashers.append(("XXHash", xxhash.xxh64()))

crc32_value = 0
adler32_value = 1
chunk_size = 1024 * 1024
try:
    with path.open('rb') as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            for _, hasher in hashers:
                hasher.update(chunk)
            crc32_value = binascii.crc32(chunk, crc32_value)
            adler32_value = zlib.adler32(chunk, adler32_value)
except Exception as exc:
    with open(f"{temp_dir}/error", "w") as f:
        f.write(f"ERROR read-failed {exc}")
    sys.exit(1)

computed = {}
for name, hasher in hashers:
    try:
        computed[name] = hasher.hexdigest().lower()
    except Exception:
        missing.add(name)

computed["CRC32"] = f"{crc32_value & 0xffffffff:08x}"
computed["Adler32"] = f"{adler32_value & 0xffffffff:08x}"

with open(f"{temp_dir}/python_hashes", "w") as f:
    for name in sorted(computed):
        f.write(f"COMPUTED {name} {computed[name]}\n")

with open(f"{temp_dir}/python_missing", "w") as f:
    for name in sorted(missing):
        if name not in computed:
            f.write(f"MISSING {name}\n")
PYBLOCK
        ) \
        >(if [[ -n "${needed_algorithms[BLAKE3]:-}" ]] && command -v b3sum >/dev/null 2>&1; then
            if output=$(b3sum -- "$target" 2>/dev/null); then
                digest=$(printf '%s' "$output" | awk '{print $1}')
                digest=${digest,,}
                if [[ $digest =~ ^[0-9a-f]+$ ]]; then
                    printf 'COMPUTED BLAKE3 %s\n' "$digest" > "$temp_dir/b3sum_result"
                fi
            fi
        fi) \
        >(if [[ -n "${needed_algorithms[WHIRLPOOL]:-}" ]] && command -v openssl >/dev/null 2>&1; then
            if output=$(openssl dgst -whirlpool -- "$target" 2>/dev/null); then
                digest=$(printf '%s' "$output" | awk '{print $NF}')
                digest=${digest,,}
                if [[ $digest =~ ^[0-9a-f]+$ ]]; then
                    printf 'COMPUTED WHIRLPOOL %s\n' "$digest" > "$temp_dir/openssl_whirlpool"
                fi
            fi
        fi) \
        >(if [[ -n "${needed_algorithms[RIPEMD]:-}" ]] && command -v openssl >/dev/null 2>&1; then
            if output=$(openssl dgst -ripemd160 -- "$target" 2>/dev/null); then
                digest=$(printf '%s' "$output" | awk '{print $NF}')
                digest=${digest,,}
                if [[ $digest =~ ^[0-9a-f]+$ ]]; then
                    printf 'COMPUTED RIPEMD %s\n' "$digest" > "$temp_dir/openssl_ripemd"
                fi
            fi
        fi) \
        >(if [[ -n "${needed_algorithms[XXHash]:-}" ]] && command -v xxhsum >/dev/null 2>&1; then
            if output=$(xxhsum -- "$target" 2>/dev/null); then
                digest=$(printf '%s' "$output" | tr '[:upper:]' '[:lower:]' | grep -Eo '[0-9a-f]{8,}' | head -n1)
                if [[ $digest =~ ^[0-9a-f]+$ ]]; then
                    printf 'COMPUTED XXHash %s\n' "$digest" > "$temp_dir/xxhsum_result"
                fi
            fi
        fi) \
        < "$target" >/dev/null 2>&1; then
        
        base_name=$(basename -- "$target")
        dialog_lines+=("$base_name: Did not Match")
        continue
    fi

    # Wait for all background processes to complete
    wait

    # Check for errors
    if [[ -f "$temp_dir/error" ]]; then
        base_name=$(basename -- "$target")
        dialog_lines+=("$base_name: Did not Match")
        continue
    fi

    # Collect all computed hashes
    unset computed_hashes
    declare -A computed_hashes=()
    unset missing_map
    declare -A missing_map=()

    # Read Python results
    if [[ -f "$temp_dir/python_hashes" ]]; then
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            if [[ $line == COMPUTED* ]]; then
                read -r _ algo digest <<<"$line"
                computed_hashes["$algo"]="$digest"
            fi
        done < "$temp_dir/python_hashes"
    fi

    if [[ -f "$temp_dir/python_missing" ]]; then
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            if [[ $line == MISSING* ]]; then
                read -r _ algo <<<"$line"
                missing_map["$algo"]=1
            fi
        done < "$temp_dir/python_missing"
    fi

    # Read external tool results
    for result_file in "$temp_dir/b3sum_result" "$temp_dir/openssl_whirlpool" "$temp_dir/openssl_ripemd" "$temp_dir/xxhsum_result"; do
        if [[ -f "$result_file" ]]; then
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                if [[ $line == COMPUTED* ]]; then
                    read -r _ algo digest <<<"$line"
                    computed_hashes["$algo"]="$digest"
                    unset "missing_map[$algo]" 2>/dev/null || true
                fi
            done < "$result_file"
        fi
    done

    # Check for matches among possible algorithms only
    matches=()
    for algo in "${possible_algorithms[@]}"; do
        if [[ -n "${computed_hashes[$algo]:-}" ]]; then
            if [[ "${computed_hashes[$algo]}" == "$clipboard_lower" ]]; then
                matches+=("$algo")
            fi
        fi
    done

    base_name=$(basename -- "$target")
    if [[ ${#matches[@]} -gt 0 ]]; then
        dialog_lines+=("$base_name: Matched ${matches[*]}")
    else
        dialog_lines+=("$base_name: Did not Match")
    fi

    # Clean up temp directory
    rm -rf "$temp_dir"
    trap - EXIT

done

message=$(printf '%s\n' "${dialog_lines[@]}")
show_dialog info "$message"
