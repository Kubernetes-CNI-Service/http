#!/usr/bin/env bash
# Explicit manual preparation; never invoked by load/initial-setup/UFM.
set +x
set -u

usage() {
    echo "Usage: bash helper-prepare-eth-jump.sh [ib.csv] [publickey_dir] [--keys-only]"
    echo "Defaults: ./ib.csv, ./publickey, install keys AND repair PATH."
    echo "Only CSV type=eth_jump is selected; SSH user=cumulus."
    echo "Requires Ubuntu/Debian; installs missing sshpass using apt/root/sudo."
}
csv_file=./ib.csv



key_dir=./publickey
prepare_mode=all
positional=0
while (( $# )); do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        --keys-only) prepare_mode=keys ;;
        -*) echo "Unknown option: $1" >&2; usage; exit 1 ;;
        *)
            case "$positional" in
                0) csv_file=$1 ;;
                1) key_dir=$1 ;;
                *) usage; exit 1 ;;
            esac
            positional=$((positional + 1))
            ;;
    esac
    shift
done

for task_cmd in awk ssh ssh-keygen timeout; do
    command -v "$task_cmd" >/dev/null || {
        echo "Missing command: $task_cmd" >&2; exit 1;
    }
done
[[ -r "$csv_file" && -d "$key_dir" ]] || {
    echo "Cannot read CSV or publickey directory." >&2; exit 1;
}
public_keys=""
key_count=0
shopt -s nullglob
for task_pub in "$key_dir"/*.pub; do
    [[ -r "$task_pub" ]] || { echo "Unreadable key: $task_pub" >&2; exit 1; }
    [[ -s "$task_pub" ]] || { echo "[SKIP] Empty key: $task_pub"; continue; }
    ssh-keygen -lf "$task_pub" >/dev/null 2>&1 || {
        echo "Invalid public key: $task_pub" >&2; exit 1;
    }
    key=$(awk 'NF && $1 !~ /^#/ {n++; key=$0}
        END {if(n!=1) exit 1; sub(/\r$/, "", key); print key}' "$task_pub") || {
        echo "Expected one public key per file: $task_pub" >&2; exit 1;
    }
    public_keys+="$key"$'\n'
    key_count=$((key_count + 1))
done
(( key_count > 0 )) || { echo "No valid non-empty *.pub files." >&2; exit 1; }
targets=$(awk -F, 'NR>1 {
    gsub(/\r/, "")
    for(i=1;i<=4;i++) gsub(/^[ \t"]+|[ \t"]+$/, "", $i)
    if(tolower($2)=="eth_jump" && !seen[$4]++)
        print $1 "\t" $4
}' "$csv_file") || exit 1
[[ -n "$targets" ]] || { echo "No type=eth_jump device found."; exit 1; }

ensure_sshpass() {
    command -v sshpass >/dev/null 2>&1 && return 0
    command -v apt-get >/dev/null 2>&1 || {
        echo "[ERROR] Automatic sshpass installation requires apt-get." >&2
        return 1
    }
    local -a task_privilege=()
    if (( EUID != 0 )); then
        command -v sudo >/dev/null 2>&1 || {
            echo "[ERROR] sshpass installation requires root or sudo." >&2
            return 1
        }
        sudo -v || return 1
        task_privilege=(sudo)
    fi
    echo "[INFO] Installing sshpass..."
    if ! "${task_privilege[@]}" apt-get -q \
        -o DPkg::Lock::Timeout=60 install -y --no-install-recommends sshpass; then
        echo "[INFO] Refreshing APT indexes, then retrying once..."
        "${task_privilege[@]}" apt-get -q update || return 1
        "${task_privilege[@]}" apt-get -q \
            -o DPkg::Lock::Timeout=60 install -y --no-install-recommends sshpass ||
            return 1
    fi
    command -v sshpass >/dev/null 2>&1 || {
        echo "[ERROR] sshpass is still unavailable." >&2
        return 1
    }
}

ensure_sshpass || exit 1
echo "Loaded $key_count public-key file(s); mode=$prepare_mode"
ssh_opts=(-o ConnectTimeout=5 -o ConnectionAttempts=1
          -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR
          -o ControlMaster=no -o ControlPath=none)
key_opts=(-o BatchMode=yes -o PreferredAuthentications=publickey
          -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no)
verify_command=true
if [[ "$prepare_mode" == all ]]; then
    verify_command='command -v bridge && command -v ip && command -v ifquery'
fi

send_setup() {
    printf 'prepare_mode=%q\nkeys=%q\n' "$prepare_mode" "$public_keys"
    cat <<'REMOTE'
set -eu
# Session-only PATH is set for the preparation commands, even in --keys-only.
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH
umask 077

check_file() {
    [[ ! -L "$1" && ( ! -e "$1" || -f "$1" ) ]] || {
        echo "Refusing non-regular file or symlink: $1" >&2
        return 1
    }
}
backup_file() {
    local task_file=$1
    local task_backup="$task_file.prepare_eth_jump.bak"
    check_file "$task_backup"
    [[ ! -f "$task_file" || -f "$task_backup" ]] ||
        cp -p "$task_file" "$task_backup"
}
install_public_keys() {
    local auth="$HOME/.ssh/authorized_keys"
    local pub key_type key_blob added=0
    [[ ! -L "$HOME/.ssh" && ( ! -e "$HOME/.ssh" || -d "$HOME/.ssh" ) ]] ||
        { echo "Refusing invalid .ssh directory" >&2; return 1; }
    check_file "$auth"
    mkdir -p "$HOME/.ssh"
    backup_file "$auth"
    chmod 700 "$HOME/.ssh"
    touch "$auth"
    chmod 600 "$auth"
    while IFS= read -r pub; do
        [[ -n "$pub" ]] || continue
        read -r key_type key_blob _ <<< "$pub"
        if ! awk -v t="$key_type" -v b="$key_blob" '
            /^[[:space:]]*#/ {next}
            {for(i=1;i<NF;i++) if($i==t && $(i+1)==b) found=1}
            END {exit !found}' "$auth"; then
            [[ ! -s "$auth" ]] || printf '\n' >> "$auth"
            printf '%s\n' "$pub" >> "$auth"
            added=$((added + 1))
        fi
    done <<< "$keys"
    echo "Public keys added: $added"
}
repair_path() {
    local rc="$HOME/.bashrc" task_tmp
    local path_line='export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH'
    check_file "$rc"
    backup_file "$rc"
    touch "$rc"
    if [[ "$(head -n 1 "$rc")" != "$path_line" ]]; then
        task_tmp=$(mktemp "$HOME/.bashrc.prepare_eth_jump.XXXXXX")
        { printf '%s\n' "$path_line"; cat "$rc"; } > "$task_tmp"
        chmod --reference="$rc" "$task_tmp"
        mv "$task_tmp" "$rc"
    fi
    echo "PATH repaired."
}

install_public_keys
if [[ "$prepare_mode" == all ]]; then
    repair_path
fi
REMOTE
}

task_total=0
task_verified=0
task_incomplete=0
shared_answer=""
shared_password=""
while IFS=$'\t' read -r hostname ip; do
    task_total=$((task_total + 1))
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || {
        echo "[SKIP] $hostname: invalid IPv4"
        task_incomplete=$((task_incomplete + 1))
        continue
    }
    target="cumulus@$ip"
    echo "[$hostname $ip]"
    probe=$(timeout 5s ssh "${ssh_opts[@]}" "${key_opts[@]}" \
        -n "$target" true 2>&1)
    probe_rc=$?
    if (( probe_rc == 0 )); then
        send_setup | timeout 5s ssh "${ssh_opts[@]}" "${key_opts[@]}" \
            "$target" /bin/bash -s
        setup_rc=$?
    elif [[ "$probe" == *"Permission denied"* ||
            "$probe" == *"Too many authentication failures"* ]]; then
        if [[ -z "$shared_answer" ]]; then
            read -r -p 'All OOB-Leaf passwords the same? [Y/n]: ' \
                shared_answer </dev/tty || exit 1
            case "$shared_answer" in
                ""|[Yy]|[Yy][Ee][Ss]) shared_answer=y ;;
                [Nn]|[Nn][Oo]) shared_answer=n ;;
                *) echo "[ERROR] Please answer yes or no." >&2; exit 1 ;;
            esac
        fi
        if [[ "$shared_answer" == n || "$shared_answer" == N || "$shared_answer" == no || "$shared_answer" == NO ]]; then
            read -r -s -p "Password for $hostname: " password </dev/tty || exit 1
            printf '\n' >&2
        else
            if [[ -z "$shared_password" ]]; then
                read -r -s -p 'Shared OOB-Leaf password: ' \
                    shared_password </dev/tty || exit 1
                printf '\n' >&2
            fi
            password=$shared_password
        fi
        [[ -n "$password" ]] || {
            echo "[SKIP] Empty password"
            task_incomplete=$((task_incomplete + 1))
            continue
        }
        send_setup | timeout 5s sshpass -d 3 ssh "${ssh_opts[@]}" \
            -o BatchMode=no -o PubkeyAuthentication=no \
            -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1 \
            "$target" /bin/bash -s 3<<<"$password"
        setup_rc=$?
        unset password
    else
        printf '[SKIP] SSH failed or timed out: %s\n' "$probe"
        task_incomplete=$((task_incomplete + 1))
        continue
    fi
    if (( setup_rc != 0 )); then
        echo "[FAIL] Preparation failed/timed out (exit=$setup_rc); review before retry."
        task_incomplete=$((task_incomplete + 1))
    elif timeout 5s ssh "${ssh_opts[@]}" "${key_opts[@]}" -n "$target" "$verify_command"; then
        task_verified=$((task_verified + 1))
        if [[ "$prepare_mode" == keys ]]; then
            echo "[OK] Current-user key login verified; persistent PATH unchanged."
        else
            echo "[OK] Current-user key login and command PATH verified."
        fi
    else
        echo "[WARN] Preparation succeeded, but verification failed (mode=$prepare_mode)."
        task_incomplete=$((task_incomplete + 1))
    fi
done <<< "$targets"
unset shared_password
printf '[SUMMARY] targets=%d verified=%d incomplete=%d\n' \
    "$task_total" "$task_verified" "$task_incomplete"
(( task_incomplete == 0 ))
