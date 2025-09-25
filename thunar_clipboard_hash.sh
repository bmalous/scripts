#!/bin/bash
set -euo pipefail
command -v zenity >/dev/null || { printf 'zenity required\n' >&2; exit 1; }
notify(){ case $1 in info) zenity --info --title="Hash Compare" --text="$2";; warn) zenity --warning --title="Hash Compare" --text="$2";; error) zenity --error --title="Hash Compare" --text="$2";; esac; }
declare -A PKG=([zenity]=zenity [xsel]=xsel [xclip]=xclip [md5sum]=coreutils [sha1sum]=coreutils [sha256sum]=coreutils [sha3sum]=coreutils [openssl]=openssl)
pm(){ for entry in "apt-get:sudo apt-get install -y" "dnf:sudo dnf install -y" "yum:sudo yum install -y" "pacman:sudo pacman -S --needed --noconfirm" "zypper:sudo zypper install -y" "emerge:sudo emerge"; do IFS=: read -r cmd line <<<"$entry"; if command -v "$cmd" >/dev/null; then echo "$line"; return 0; fi; done; return 1; }
need(){ local tools=("$@"); local mgr pkgs cmd
mgr=$(pm) || { notify error "Missing tools: ${tools[*]}\nInstall manually."; exit 1; }
mapfile -t pkgs < <(for t in "${tools[@]}"; do echo "${PKG[$t]:-$t}"; done | sort -u)
cmd="$mgr ${pkgs[*]}"
if zenity --question --title="Install Dependencies" --text="Install packages?\n$cmd"; then
    if command -v pkexec >/dev/null; then pkexec bash -lc "$cmd" || { notify error "Install failed:\n$cmd"; exit 1; }
    else notify warn "Run manually:\n$cmd"; exit 1; fi
else notify warn "Installation cancelled."; exit 1; fi }
clip_tool(){ if command -v xsel >/dev/null; then echo "xsel --clipboard"; return; fi; if command -v xclip >/dev/null; then echo "xclip -selection clipboard -o"; return; fi; need xsel xclip; if command -v xsel >/dev/null; then echo "xsel --clipboard"; return; fi; if command -v xclip >/dev/null; then echo "xclip -selection clipboard -o"; return; fi; notify error "Clipboard tool unavailable."; exit 1; }
clip=$($(clip_tool) | tr -d '\n\r\t ' | tr '[:upper:]' '[:lower:]')
[[ $clip ]] || { notify error "Clipboard is empty."; exit 1; }
case ${#clip} in 32) label=MD5; algo="md5sum";; 40) label=SHA1; algo="sha1sum";; 56) label=SHA3-224; algo="sha3sum -a 224";; 64) label=SHA256; algo="sha256sum";; 96) label=SHA3-384; algo="sha3sum -a 384";; 128) label=SHA3-512; algo="sha3sum -a 512";; *) notify error "Unsupported hash length ${#clip}."; exit 1;; esac
[[ $clip =~ ^[0-9a-f]+$ ]] || { notify error "Clipboard is not hexadecimal."; exit 1; }
results=""; status=0
for f in "$@"; do
    if [[ ! -f $f ]]; then results+="Missing file: $f\n"; status=1; continue; fi
    tool=${algo%% *}
    if command -v "$tool" >/dev/null; then file_hash=$($algo "$f" | awk '{print $1}')
    else
        need "$tool"
        if command -v "$tool" >/dev/null; then file_hash=$($algo "$f" | awk '{print $1}')
        elif [[ $algo == sha3sum* ]]; then
            command -v openssl >/dev/null || need openssl
            if command -v openssl >/dev/null; then file_hash=$(openssl dgst -${label,,} "$f" | awk '{print $2}')
            else results+="Need $tool or openssl for $f\n"; status=1; continue; fi
        else results+="Need $tool for $f\n"; status=1; continue; fi
    fi
    if [[ $file_hash == "$clip" ]]; then results+="$label match: $f\n"; else results+="$label mismatch: $f\nFile: $file_hash\nClipboard: $clip\n\n"; status=1; fi
done
if [[ -z $results ]]; then notify info "No files processed."; elif (( status )); then notify warn "$results"; else notify info "$results"; fi
