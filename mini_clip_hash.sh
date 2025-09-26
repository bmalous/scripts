#!/usr/bin/env bash
set -euo pipefail

# Compare clipboard hash with file hashes and report matches via Zenity dialogs.

readonly APP_TITLE="Hash Compare"
readonly VERSION="1.2.0"

# notify LEVEL MESSAGE -> Display a Zenity dialog at the requested severity level.
notify() {
    local level=$1
    local message=$2

    case $level in
        info)
            zenity --info --title="$APP_TITLE" --text="$message" --width=400
            ;;
        warn)
            zenity --warning --title="$APP_TITLE" --text="$message" --width=400
            ;;
        error)
            zenity --error --title="$APP_TITLE" --text="$message" --width=400
            ;;
        question)
            zenity --question --title="$APP_TITLE" --text="$message" --width=400
            ;;
    esac
}

# show_help -> Display usage information
show_help() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS] FILE...

Compare file hashes against clipboard hash value.

OPTIONS:
    -h, --help      Show this help message
    -v, --version   Show version information
    -c, --copy      Copy file hash to clipboard instead of comparing
    -a, --algo ALGO Force specific algorithm
    -l, --list      List all supported hash algorithms
    -m, --multiple  Compute multiple hashes for comparison
    -q, --quiet     Suppress progress dialogs for large files
    -s, --save      Save results to file

SUPPORTED ALGORITHMS:
    md5, sha1, sha224, sha256, sha384, sha512, sha3-224, sha3-256, sha3-384, sha3-512,
    blake2b, blake2s, blake3, xxhash, crc32, adler32, whirlpool, ripemd160

EXAMPLES:
    $(basename "$0") file.iso
    $(basename "$0") --copy file.iso
    $(basename "$0") --algo sha256 file.zip
    $(basename "$0") --multiple file.bin
    $(basename "$0") --list

EOF
}

# list_algorithms -> Display all supported hash algorithms
list_algorithms() {
    local algos=(
        "MD5:32:md5sum:Common but cryptographically broken"
        "SHA1:40:sha1sum:Deprecated, use SHA256+ instead"
        "SHA224:56:sha224sum:SHA-2 family member"
        "SHA256:64:sha256sum:Most widely used secure hash"
        "SHA384:96:sha384sum:SHA-2 family member"
        "SHA512:128:sha512sum:SHA-2 family member"
        "SHA3-224:56:sha3sum -a 224:SHA-3 Keccak-based"
        "SHA3-256:64:sha3sum -a 256:SHA-3 Keccak-based"
        "SHA3-384:96:sha3sum -a 384:SHA-3 Keccak-based"
        "SHA3-512:128:sha3sum -a 512:SHA-3 Keccak-based"
        "BLAKE2b:128:b2sum:Fast, secure alternative to SHA"
        "BLAKE2s:64:b2sum -l 256:BLAKE2 variant for smaller inputs"
        "BLAKE3:64:b3sum:Latest BLAKE variant (if available)"
        "WHIRLPOOL:128:whirlpool:ISO/IEC standard hash"
        "RIPEMD160:40:rmd160sum:Alternative to SHA1"
        "XXHash:16:xxhsum:Extremely fast non-cryptographic"
        "CRC32:8:crc32:Simple checksum (not cryptographic)"
        "Adler32:8:adler32:Fast checksum (not cryptographic)"
    )
    
    printf "%-12s %-6s %-20s %s\n" "Algorithm" "Length" "Command" "Description"
    printf "%s\n" "$(printf '=%.0s' {1..80})"
    
    for algo in "${algos[@]}"; do
        IFS=':' read -r name length cmd desc <<< "$algo"
        printf "%-12s %-6s %-20s %s\n" "$name" "$length" "${cmd%% *}" "$desc"
    done
}

# ensure_dependencies -> Abort if required GUI dependency is missing.
ensure_dependencies() {
    local missing_deps=()
    
    if ! command -v zenity >/dev/null 2>&1; then
        missing_deps+=("zenity")
    fi
    
    # Check clipboard read/write capabilities separately to support Wayland + X11 tools
    local has_reader=false
    local has_writer=false

    if command -v wl-paste >/dev/null 2>&1; then
        has_reader=true
    fi
    if command -v wl-copy >/dev/null 2>&1; then
        has_writer=true
    fi
    if command -v xsel >/dev/null 2>&1; then
        has_reader=true
        has_writer=true
    fi
    if command -v xclip >/dev/null 2>&1; then
        has_reader=true
        has_writer=true
    fi

    if [[ $has_reader == false ]]; then
        missing_deps+=("wl-paste or xsel or xclip")
    fi
    if [[ $has_writer == false ]]; then
        missing_deps+=("wl-copy or xsel or xclip")
    fi
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        printf 'Missing dependencies: %s\n' "${missing_deps[*]}" >&2
        exit 1
    fi
}

# read_clipboard_hash -> Return sanitized, lowercase hexadecimal clipboard contents.
read_clipboard_hash() {
    local raw clipboard_cmd
    
    # Try Wayland first, then X11 clipboard tools
    if command -v wl-paste >/dev/null 2>&1; then
        clipboard_cmd="wl-paste"
    elif command -v xsel >/dev/null 2>&1; then
        clipboard_cmd="xsel --clipboard"
    elif command -v xclip >/dev/null 2>&1; then
        clipboard_cmd="xclip -selection clipboard -o"
    else
        notify error "No clipboard tool available (xsel, xclip, or wl-paste required)."
        exit 1
    fi
    
    if raw=$($clipboard_cmd 2>/dev/null); then
        # Extract hash from common formats (just hash, "hash filename", "algo: hash")
        # Support for more hash lengths including CRC32 and XXHash
        local cleaned
        cleaned=$(printf '%s' "$raw" | grep -oE '[0-9a-fA-F]{8,128}' | head -1 | tr '[:upper:]' '[:lower:]')
        printf '%s' "$cleaned"
    else
        notify error "Failed to read clipboard."
        exit 1
    fi
}

# write_clipboard -> Write text to clipboard
write_clipboard() {
    local text=$1
    
    if command -v wl-copy >/dev/null 2>&1; then
        printf '%s' "$text" | wl-copy
    elif command -v xsel >/dev/null 2>&1; then
        printf '%s' "$text" | xsel --clipboard --input
    elif command -v xclip >/dev/null 2>&1; then
        printf '%s' "$text" | xclip -selection clipboard
    else
        notify error "No clipboard tool available for writing."
        return 1
    fi
}

# determine_hash_algorithm HASH [FORCE_ALGO] -> Echo LABEL|COMMAND for supported hash lengths.
determine_hash_algorithm() {
    local clipboard_hash=$1
    local force_algo=${2:-}
    
    if [[ -n $force_algo ]]; then
        case $force_algo in
            md5)
                printf 'MD5|md5sum'
                ;;
            sha1)
                printf 'SHA1|sha1sum'
                ;;
            sha224)
                printf 'SHA224|sha224sum'
                ;;
            sha256)
                printf 'SHA256|sha256sum'
                ;;
            sha384)
                printf 'SHA384|sha384sum'
                ;;
            sha512)
                printf 'SHA512|sha512sum'
                ;;
            sha3-224)
                printf 'SHA3-224|sha3sum -a 224'
                ;;
            sha3-256)
                printf 'SHA3-256|sha3sum -a 256'
                ;;
            sha3-384)
                printf 'SHA3-384|sha3sum -a 384'
                ;;
            sha3-512)
                printf 'SHA3-512|sha3sum -a 512'
                ;;
            blake2b)
                printf 'BLAKE2b|b2sum'
                ;;
            blake2s)
                printf 'BLAKE2s|b2sum -l 256'
                ;;
            blake3)
                printf 'BLAKE3|b3sum'
                ;;
            whirlpool)
                printf 'WHIRLPOOL|whirlpoolsum'
                ;;
            ripemd160)
                printf 'RIPEMD160|rmd160sum'
                ;;
            xxhash)
                printf 'XXHash|xxhsum'
                ;;
            crc32)
                printf 'CRC32|crc32'
                ;;
            adler32)
                printf 'Adler32|adler32'
                ;;
            *)
                notify error "Unsupported algorithm: $force_algo"
                exit 1
                ;;
        esac
        return
    fi

    # Auto-detect based on length
    case ${#clipboard_hash} in
        8)
            # CRC32 or Adler32
            local choice
            choice=$(zenity --list --title="$APP_TITLE" --text="8-character hash detected. Choose algorithm:" \
                --column="Algorithm" --column="Description" \
                "CRC32" "Cyclic Redundancy Check" \
                "Adler32" "Adler-32 checksum" \
                --height=200 --width=400 2>/dev/null || echo "CRC32")
            
            case $choice in
                "CRC32")
                    printf 'CRC32|crc32'
                    ;;
                "Adler32")
                    printf 'Adler32|adler32'
                    ;;
                *)
                    printf 'CRC32|crc32'
                    ;;
            esac
            ;;
        16)
            # XXHash (64-bit) truncated or other 16-char hashes
            printf 'XXHash|xxhsum'
            ;;
        32)
            printf 'MD5|md5sum'
            ;;
        40)
            # SHA1 or RIPEMD160
            local choice
            choice=$(zenity --list --title="$APP_TITLE" --text="40-character hash detected. Choose algorithm:" \
                --column="Algorithm" --column="Description" \
                "SHA1" "Most common 40-char hash (deprecated)" \
                "RIPEMD160" "Alternative hash algorithm" \
                --height=200 --width=400 2>/dev/null || echo "SHA1")
            
            case $choice in
                "SHA1")
                    printf 'SHA1|sha1sum'
                    ;;
                "RIPEMD160")
                    printf 'RIPEMD160|rmd160sum'
                    ;;
                *)
                    printf 'SHA1|sha1sum'
                    ;;
            esac
            ;;
        56)
            # Could be SHA224 or SHA3-224
            local choice
            choice=$(zenity --list --title="$APP_TITLE" --text="56-character hash detected. Choose algorithm:" \
                --column="Algorithm" --column="Description" \
                "SHA224" "SHA-2 family (most common)" \
                "SHA3-224" "SHA-3 Keccak variant" \
                --height=200 --width=400 2>/dev/null || echo "SHA224")
            
            case $choice in
                "SHA224")
                    printf 'SHA224|sha224sum'
                    ;;
                "SHA3-224")
                    printf 'SHA3-224|sha3sum -a 224'
                    ;;
                *)
                    printf 'SHA224|sha224sum'
                    ;;
            esac
            ;;
        64)
            # Multiple possibilities: SHA256, SHA3-256, BLAKE2s
            local choice
            choice=$(zenity --list --title="$APP_TITLE" --text="64-character hash detected. Choose algorithm:" \
                --column="Algorithm" --column="Description" \
                "SHA256" "Most common 64-char hash" \
                "SHA3-256" "SHA-3 Keccak variant" \
                "BLAKE2s" "BLAKE2s (256-bit)" \
                "BLAKE3" "Modern BLAKE3 hash" \
                --height=300 --width=400 2>/dev/null || echo "SHA256")
            
            case $choice in
                "SHA256")
                    printf 'SHA256|sha256sum'
                    ;;
                "SHA3-256")
                    printf 'SHA3-256|sha3sum -a 256'
                    ;;
                "BLAKE2s")
                    printf 'BLAKE2s|b2sum -l 256'
                    ;;
                "BLAKE3")
                    printf 'BLAKE3|b3sum'
                    ;;
                *)
                    printf 'SHA256|sha256sum'
                    ;;
            esac
            ;;
        96)
            # Could be SHA384 or SHA3-384
            local choice
            choice=$(zenity --list --title="$APP_TITLE" --text="96-character hash detected. Choose algorithm:" \
                --column="Algorithm" --column="Description" \
                "SHA384" "SHA-2 family (most common)" \
                "SHA3-384" "SHA-3 Keccak variant" \
                --height=200 --width=400 2>/dev/null || echo "SHA384")
            
            case $choice in
                "SHA384")
                    printf 'SHA384|sha384sum'
                    ;;
                "SHA3-384")
                    printf 'SHA3-384|sha3sum -a 384'
                    ;;
                *)
                    printf 'SHA384|sha384sum'
                    ;;
            esac
            ;;
        128)
            # Multiple possibilities: SHA512, SHA3-512, BLAKE2b, WHIRLPOOL
            local choice
            choice=$(zenity --list --title="$APP_TITLE" --text="128-character hash detected. Choose algorithm:" \
                --column="Algorithm" --column="Description" \
                "SHA512" "Most common 128-char hash" \
                "SHA3-512" "SHA-3 Keccak variant" \
                "BLAKE2b" "Modern BLAKE2b hash" \
                "WHIRLPOOL" "ISO/IEC standard hash" \
                --height=300 --width=400 2>/dev/null || echo "SHA512")
            
            case $choice in
                "SHA512")
                    printf 'SHA512|sha512sum'
                    ;;
                "SHA3-512")
                    printf 'SHA3-512|sha3sum -a 512'
                    ;;
                "BLAKE2b")
                    printf 'BLAKE2b|b2sum'
                    ;;
                "WHIRLPOOL")
                    printf 'WHIRLPOOL|whirlpoolsum'
                    ;;
                *)
                    printf 'SHA512|sha512sum'
                    ;;
            esac
            ;;
        *)
            notify error "Unsupported hash length: ${#clipboard_hash} characters"
            exit 1
            ;;
    esac
}

# compute_file_hash COMMAND LABEL FILE [QUIET] -> Output hash for FILE using COMMAND or OpenSSL fallback.
compute_file_hash() {
    local algo=$1
    local label=$2
    local file=$3
    local quiet=${4:-false}
    local tool

    tool=${algo%% *}

    # Progress dialog for large files (unless quiet mode)
    if [[ $quiet == false ]] && [[ -f $file ]]; then
        local file_size
        if file_size=$(get_file_size "$file") && (( file_size > 104857600 )); then
            # File is larger than 100MB, show a pulsating progress dialog while hashing
            zenity --progress --pulsate --title="$APP_TITLE" --text="Computing $label hash for $(basename "$file")..." --auto-close --no-cancel >/dev/null 2>&1 &
            local zenity_pid=$!
            local hash_result
            if hash_result=$($algo "$file" | awk '{print $1}'); then
                kill $zenity_pid 2>/dev/null || true
                wait $zenity_pid 2>/dev/null || true
                printf '%s' "$hash_result"
                return
            else
                kill $zenity_pid 2>/dev/null || true
                wait $zenity_pid 2>/dev/null || true
                return 1
            fi
        fi
    fi

    # Try native tool first
    if command -v "$tool" >/dev/null 2>&1; then
        $algo "$file" | awk '{print $1}'
        return
    fi

    # Extended OpenSSL fallback support
    if command -v openssl >/dev/null 2>&1; then
        local openssl_flag
        case $label in
            MD5)
                openssl_flag='md5'
                ;;
            SHA1)
                openssl_flag='sha1'
                ;;
            SHA224)
                openssl_flag='sha224'
                ;;
            SHA256)
                openssl_flag='sha256'
                ;;
            SHA384)
                openssl_flag='sha384'
                ;;
            SHA512)
                openssl_flag='sha512'
                ;;
            SHA3-224)
                openssl_flag='sha3-224'
                ;;
            SHA3-256)
                openssl_flag='sha3-256'
                ;;
            SHA3-384)
                openssl_flag='sha3-384'
                ;;
            SHA3-512)
                openssl_flag='sha3-512'
                ;;
            WHIRLPOOL)
                openssl_flag='whirlpool'
                ;;
            RIPEMD160)
                openssl_flag='rmd160'
                ;;
        esac

        if [[ -n $openssl_flag ]]; then
            openssl dgst -$openssl_flag "$file" | awk '{print $2}'
            return
        fi
    fi

    # Fallback for some algorithms using alternative methods
    case $label in
        CRC32)
            if command -v python3 >/dev/null 2>&1; then
                python3 -c "import zlib; print(format(zlib.crc32(open('$file', 'rb').read()) & 0xffffffff, '08x'))"
                return
            fi
            ;;
        XXHash)
            if command -v python3 >/dev/null 2>&1 && python3 -c "import xxhash" 2>/dev/null; then
                python3 -c "import xxhash; print(xxhash.xxh64(open('$file', 'rb').read()).hexdigest())"
                return
            fi
            ;;
    esac

    return 1
}

# validate_file_readable FILE -> Check if file exists and is readable
validate_file_readable() {
    local file=$1
    
    if [[ ! -e $file ]]; then
        return 1
    elif [[ ! -f $file ]]; then
        return 2
    elif [[ ! -r $file ]]; then
        return 3
    fi
    return 0
}

# get_file_size FILE -> Print file size in bytes (best-effort cross-platform)
get_file_size() {
    local file=$1
    local size

    if size=$(stat -c%s "$file" 2>/dev/null); then
        printf '%s' "$size"
        return 0
    fi

    if size=$(stat -f%z "$file" 2>/dev/null); then
        printf '%s' "$size"
        return 0
    fi

    return 1
}

# format_file_size BYTES -> Return human readable file size
format_file_size() {
    local bytes=$1
    local units=("B" "KB" "MB" "GB" "TB")
    local unit=0
    local size=$bytes

    while (( size > 1024 && unit < ${#units[@]}-1 )); do
        size=$((size / 1024))
        ((unit++))
    done

    printf "%d %s" "$size" "${units[$unit]}"
}

# compute_multiple_hashes FILE [QUIET] -> Compute common hashes for a file
compute_multiple_hashes() {
    local file=$1
    local quiet=${2:-false}
    local algos=("SHA256|sha256sum" "SHA1|sha1sum" "MD5|md5sum" "SHA512|sha512sum" "BLAKE2b|b2sum")
    local results=""
    
    for algo_desc in "${algos[@]}"; do
        IFS='|' read -r label algo <<< "$algo_desc"
        local hash
        if hash=$(compute_file_hash "$algo" "$label" "$file" "$quiet"); then
            results+="$label: $hash\n"
        fi
    done
    
    printf "%s" "$results"
}

# run_copy_mode -> Copy file hash to clipboard instead of comparing
run_copy_mode() {
    local file=$1
    local force_algo=${2:-}
    local multiple=${3:-false}
    local quiet=${4:-false}

    if [[ -n $force_algo ]]; then
        force_algo=${force_algo,,}
    fi

    case $(validate_file_readable "$file"; echo $?) in
        0)
            ;;
        1)
            notify error "File not found: $file"
            exit 1
            ;;
        2)
            notify error "Not a regular file: $file"
            exit 1
            ;;
        3)
            notify error "Permission denied: $file"
            exit 1
            ;;
        *)
            notify error "Unexpected error checking $file"
            exit 1
            ;;
    esac
    
    if [[ $multiple == true ]]; then
        local results
        results=$(compute_multiple_hashes "$file" "$quiet")
        if write_clipboard "$results"; then
            local raw_size formatted_size
            if raw_size=$(get_file_size "$file"); then
                formatted_size=$(format_file_size "$raw_size")
            else
                formatted_size="Unknown"
            fi
            notify info "Multiple hashes copied to clipboard!\n\nFile: $(basename "$file")\nSize: $formatted_size\n\n$results"
        else
            notify error "Failed to copy hashes to clipboard"
            exit 1
        fi
        return
    fi
    
    # If no algorithm specified, ask user
    if [[ -z $force_algo ]]; then
        force_algo=$(zenity --list --title="$APP_TITLE" --text="Choose hash algorithm for $(basename "$file"):" \
            --column="Algorithm" \
            "sha256" "sha1" "md5" "sha512" "sha384" "sha224" "sha3-256" "sha3-512" "blake2b" "blake2s" "blake3" "whirlpool" "ripemd160" \
            --height=400 --width=300 2>/dev/null || echo "sha256")
        force_algo=${force_algo,,}
    fi

    local descriptor algo label file_hash
    descriptor=$(determine_hash_algorithm "" "$force_algo")
    IFS='|' read -r label algo <<< "$descriptor"
    
    if ! file_hash=$(compute_file_hash "$algo" "$label" "$file" "$quiet"); then
        notify error "Failed to compute $label hash for $file"
        exit 1
    fi
    
    if write_clipboard "$file_hash"; then
        local raw_size formatted_size
        if raw_size=$(get_file_size "$file"); then
            formatted_size=$(format_file_size "$raw_size")
        else
            formatted_size="Unknown"
        fi
        notify info "$label hash copied to clipboard!\n\nFile: $(basename "$file")\nSize: $formatted_size\nHash: $file_hash"
    else
        notify error "Failed to copy hash to clipboard"
        exit 1
    fi
}

# save_results RESULTS [FILENAME] -> Save results to file
save_results() {
    local results=$1
    local filename=${2:-}
    
    if [[ -z $filename ]]; then
        filename=$(zenity --file-selection --save --title="Save Results" --filename="hash_comparison_$(date +%Y%m%d_%H%M%S).txt" 2>/dev/null || echo "")
    fi
    
    if [[ -n $filename ]]; then
        printf "%s\n" "$results" > "$filename"
        notify info "Results saved to: $filename"
    fi
}

# main ENTRY... -> Validate clipboard hash and compare against provided file paths.
main() {
    local copy_mode_requested=false
    local force_algo=""
    local multiple_mode=false
    local quiet_mode=false
    local save_mode=false
    local list_mode=false
    local files=()

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--version)
                printf '%s %s\n' "$(basename "$0")" "$VERSION"
                exit 0
                ;;
            -l|--list)
                list_mode=true
                shift
                ;;
            -c|--copy)
                copy_mode_requested=true
                shift
                ;;
            -m|--multiple)
                multiple_mode=true
                shift
                ;;
            -q|--quiet)
                quiet_mode=true
                shift
                ;;
            -s|--save)
                save_mode=true
                shift
                ;;
            -a|--algo)
                if [[ -n ${2:-} ]]; then
                    force_algo=$2
                    shift 2
                else
                    notify error "Algorithm option requires a value"
                    exit 1
                fi
                ;;
            -*)
                notify error "Unknown option: $1"
                exit 1
                ;;
            *)
                files+=("$1")
                shift
                ;;
        esac
    done

    # List algorithms mode
    if [[ $list_mode == true ]]; then
        list_algorithms
        return
    fi

    ensure_dependencies

    # Normalize algorithm flag to lowercase for user convenience
    if [[ -n $force_algo ]]; then
        force_algo=${force_algo,,}
    fi

    # Copy mode
    if [[ $copy_mode_requested == true ]]; then
        if [[ ${#files[@]} -ne 1 ]]; then
            notify error "Copy mode requires exactly one file"
            exit 1
        fi
        run_copy_mode "${files[0]}" "$force_algo" "$multiple_mode" "$quiet_mode"
        return
    fi

    # Compare mode
    if [[ ${#files[@]} -eq 0 ]]; then
        notify error "No files specified. Use --help for usage information."
        exit 1
    fi

    local clipboard_hash
    clipboard_hash=$(read_clipboard_hash)

    if [[ -z $clipboard_hash ]]; then
        notify error "Clipboard is empty or contains no valid hash."
        exit 1
    fi

    if [[ ! $clipboard_hash =~ ^[0-9a-f]+$ ]]; then
        notify error "Clipboard does not contain a valid hexadecimal hash."
        exit 1
    fi

    local descriptor algo label results status
    descriptor=$(determine_hash_algorithm "$clipboard_hash" "$force_algo")
    IFS='|' read -r label algo <<< "$descriptor"

    results="Hash Comparison Results - $(date)\n"
    results+="Comparing against $label hash:\n$clipboard_hash\n\n"
    status=0

    local file total_files=${#files[@]} current_file=0
    for file in "${files[@]}"; do
        ((current_file++))
        
        case $(validate_file_readable "$file"; echo $?) in
            1)
                results+="❌ Missing: $(basename "$file")\n"
                status=1
                continue
                ;;
            2)
                results+="❌ Not a file: $(basename "$file")\n"
                status=1
                continue
                ;;
            3)
                results+="❌ Permission denied: $(basename "$file")\n"
                status=1
                continue
                ;;
        esac

        local file_hash
        if ! file_hash=$(compute_file_hash "$algo" "$label" "$file" "$quiet_mode"); then
            if [[ $algo == sha3sum* ]] || [[ $algo == b2sum* ]] || [[ $algo == b3sum* ]] || [[ $algo == whirlpoolsum* ]]; then
                results+="❌ Missing tool: ${algo%% *} needed for $(basename "$file")\n"
            else
                results+="❌ Hash failed: $(basename "$file")\n"
            fi
            status=1
            continue
        fi

        if [[ $file_hash == "$clipboard_hash" ]]; then
            results+="✅ Match: $(basename "$file")\n"
        else
            results+="❌ Mismatch: $(basename "$file")\n"
            results+="   Expected: $clipboard_hash\n"
            results+="   Actual:   $file_hash\n\n"
            status=1
        fi
    done

    # Save results if requested
    if [[ $save_mode == true ]]; then
        save_results "$results"
    fi

    if [[ -z $results ]]; then
        notify info "No files processed."
    elif (( status )); then
        notify warn "$results"
    else
        notify info "$results"
    fi
}

main "$@"
