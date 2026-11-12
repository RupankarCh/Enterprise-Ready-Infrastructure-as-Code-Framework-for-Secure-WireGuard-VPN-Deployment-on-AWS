#!/usr/bin/env bash

set -Eeuo pipefail

# ==========================================================
# CloudVPN Firewall - FORWARD + INPUT Protection
# ==========================================================

VPN_INTERFACE="${VPN_INTERFACE:-wg0}"
EXTERNAL_INTERFACE="${EXTERNAL_INTERFACE:-ens5}"
VPN_SUBNET="${VPN_SUBNET:-10.8.0.0/24}"

FIREWALL_CHAIN="${FIREWALL_CHAIN:-CLOUDVPN_FORWARD}"
STAGING_CHAIN="${FIREWALL_CHAIN}_STAGE"

INPUT_FIREWALL_ENABLED="${INPUT_FIREWALL_ENABLED:-true}"
INPUT_FIREWALL_CHAIN="${INPUT_FIREWALL_CHAIN:-CLOUDVPN_INPUT}"
INPUT_FIREWALL_STAGING_CHAIN="${INPUT_FIREWALL_STAGING_CHAIN:-CLOUDVPN_INPUT_STAGE}"

IPTABLES="${IPTABLES:-/usr/sbin/iptables}"
RULE_NORMALIZER="${RULE_NORMALIZER:-/usr/local/libexec/cloudvpn-firewall-rule-normalize.py}"
LOCK_FILE="${LOCK_FILE:-/run/lock/cloudvpn-firewall.lock}"

log() {
    echo "[CloudVPN Firewall] $*"
}

error() {
    echo "[CloudVPN Firewall ERROR] $*" >&2
    exit 1
}

# ==========================================================
# 1. Preflight
# ==========================================================

[[ "$EUID" -eq 0 ]] || error "Must run as root."
[[ -x "$IPTABLES" ]] || error "iptables executable unavailable."
[[ -x "$RULE_NORMALIZER" ]] || error "Firewall rule normalizer unavailable."

command -v ip >/dev/null || error "ip command unavailable."
command -v sysctl >/dev/null || error "sysctl unavailable."
command -v flock >/dev/null || error "flock unavailable."
command -v python3 >/dev/null || error "Python3 unavailable."

[[ "$INPUT_FIREWALL_ENABLED" == "true" ||
   "$INPUT_FIREWALL_ENABLED" == "false" ]] ||
    error "INPUT_FIREWALL_ENABLED must be true or false."

[[ "$FIREWALL_CHAIN" =~ ^[A-Za-z0-9_]{1,20}$ ]] ||
    error "Invalid FORWARD chain name."

[[ "$STAGING_CHAIN" =~ ^[A-Za-z0-9_]{1,28}$ ]] ||
    error "Invalid FORWARD staging chain name."

if [[ "$INPUT_FIREWALL_ENABLED" == "true" ]]; then

    [[ "$INPUT_FIREWALL_CHAIN" =~ ^[A-Za-z0-9_]{1,28}$ ]] ||
        error "Invalid INPUT chain name."

    [[ "$INPUT_FIREWALL_STAGING_CHAIN" =~ ^[A-Za-z0-9_]{1,28}$ ]] ||
        error "Invalid INPUT staging chain name."

    [[ "$FIREWALL_CHAIN" != "$STAGING_CHAIN" &&
       "$FIREWALL_CHAIN" != "$INPUT_FIREWALL_CHAIN" &&
       "$FIREWALL_CHAIN" != "$INPUT_FIREWALL_STAGING_CHAIN" &&
       "$STAGING_CHAIN" != "$INPUT_FIREWALL_CHAIN" &&
       "$STAGING_CHAIN" != "$INPUT_FIREWALL_STAGING_CHAIN" &&
       "$INPUT_FIREWALL_CHAIN" != "$INPUT_FIREWALL_STAGING_CHAIN" ]] ||
        error "All four CloudVPN firewall chain names must be unique."

fi

[[ "$VPN_SUBNET" =~ ^[0-9.]+/[0-9]+$ ]] ||
    error "Invalid VPN subnet format."

python3 -c '
import ipaddress
import sys

try:
    network = ipaddress.ip_network(sys.argv[1], strict=True)
    if network.version != 4:
        sys.exit(1)
except ValueError:
    sys.exit(1)
' "$VPN_SUBNET" ||
    error "Invalid IPv4 VPN subnet."

ip link show "$EXTERNAL_INTERFACE" >/dev/null 2>&1 ||
    error "External interface unavailable: $EXTERNAL_INTERFACE"

# ==========================================================
# 2. Lock
# ==========================================================

exec 9>"$LOCK_FILE"

flock -n 9 ||
    error "Another CloudVPN firewall operation is running."

log "Firewall operation lock acquired."

# ==========================================================
# 3. Reference detection
# ==========================================================

chain_exists() {

    local target="$1"
    local rules

    rules="$("$IPTABLES" -S)" || return 2

    awk -v target="$target" '
        $1 == "-N" && $2 == target {
            found = 1
        }
        END {
            exit(found ? 0 : 1)
        }
    ' <<< "$rules"
}

references_to_chain() {

    local target="$1"
    local rules

    rules="$("$IPTABLES" -S)" || return 2

    awk -v target="$target" '
        $1 == "-A" {
            for (i = 2; i < NF; i++) {
                if (($i == "-j" || $i == "--jump" ||
                     $i == "-g" || $i == "--goto") &&
                    $(i + 1) == target) {
                    print
                    break
                }
            }
        }
    ' <<< "$rules"
}

# ==========================================================
# 4. FORWARD policy
# ==========================================================

# shellcheck disable=SC2034
EXPECTED_FORWARD_RULES=(

    "-i $VPN_INTERFACE -s $VPN_SUBNET -d $VPN_SUBNET -j DROP"

    "-i $VPN_INTERFACE -s $VPN_SUBNET -d 10.0.0.0/8 -j DROP"
    "-i $VPN_INTERFACE -s $VPN_SUBNET -d 172.16.0.0/12 -j DROP"
    "-i $VPN_INTERFACE -s $VPN_SUBNET -d 192.168.0.0/16 -j DROP"

    "-i $VPN_INTERFACE -s $VPN_SUBNET -d 169.254.0.0/16 -j DROP"

    "-i $VPN_INTERFACE -s $VPN_SUBNET -o $EXTERNAL_INTERFACE -j ACCEPT"

    "-i $EXTERNAL_INTERFACE -o $VPN_INTERFACE -d $VPN_SUBNET -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"

    "-i $VPN_INTERFACE -j DROP"
    "-o $VPN_INTERFACE -j DROP"

    "-j RETURN"
)

# ==========================================================
# 5. INPUT policy
# ==========================================================

# shellcheck disable=SC2034
EXPECTED_INPUT_RULES=(

    "-i $VPN_INTERFACE ! -s $VPN_SUBNET -j DROP"

    "-i $VPN_INTERFACE -s $VPN_SUBNET -d 169.254.0.0/16 -j DROP"

    "-i $VPN_INTERFACE -j DROP"

    "-j RETURN"
)

# ==========================================================
# 6. Chain verification
# ==========================================================

verify_chain() {
    local chain="$1"
    local expected_name="$2"
    local -n expected_rules="$expected_name"
    local chain_dump

    chain_dump="$("$IPTABLES" -S "$chain")" || return 1

    if ! printf '%s\n' "$chain_dump" |
        "$RULE_NORMALIZER" exact "$chain" "${expected_rules[@]}"; then
        log "Production-chain verification failed: $chain"
        return 1
    fi

    return 0
}

verify_staging_prefix() {
    local chain="$1"
    local expected_name="$2"
    local -n expected_rules="$expected_name"
    local chain_dump

    chain_dump="$("$IPTABLES" -S "$chain")" || return 1

    if ! printf '%s\n' "$chain_dump" |
        "$RULE_NORMALIZER" prefix "$chain" "${expected_rules[@]}"; then
        log "Staging-chain verification failed: $chain"
        return 1
    fi

    return 0
}

# ==========================================================
# 7. Prepare and promote a chain
# ==========================================================

prepare_chain() {

    local production="$1"
    local staging="$2"
    local expected_name="$3"

    local -n expected_rules="$expected_name"

    local references
    local rule
    local -a RULE_ARGS

    local status

    if chain_exists "$production"; then

        log "Production chain exists: $production"

        verify_chain "$production" "$expected_name" ||
            error "Existing production chain has unexpected rules: $production"

        return 0

    else
        status=$?

        [[ "$status" -eq 1 ]] ||
            error "Unable to inspect production chain: $production"
    fi

    if chain_exists "$staging"; then

        log "Existing staging chain detected: $staging"

        references="$(references_to_chain "$staging")" ||
            error "Unable to inspect staging-chain references: $staging"

        [[ -z "$references" ]] ||
            error "Staging chain is referenced elsewhere: $staging"

        verify_staging_prefix "$staging" "$expected_name" ||
            error "Staging chain contains unexpected rules: $staging"

        error "Refusing to modify pre-existing staging chain: $staging. Inspect and recover it separately."

    else
        status=$?

        [[ "$status" -eq 1 ]] ||
            error "Unable to inspect staging chain: $staging"

        log "Creating staging chain: $staging"

        if "$IPTABLES" -N "$staging"; then

            # Successful creation establishes ownership.
            if [[ "$staging" == "$STAGING_CHAIN" ]]; then
                FORWARD_STAGING_CHAIN_CREATED=true
            elif [[ "$staging" == "$INPUT_FIREWALL_STAGING_CHAIN" ]]; then
                INPUT_STAGING_CHAIN_CREATED=true
            else
                error "Unknown staging-chain ownership: $staging"
            fi

        else

            # A failed command does not establish ownership,
            # even if a chain with this name now exists.
            log "ERROR: Staging-chain creation returned failure: $staging"

            if chain_exists "$staging"; then
                ROLLBACK_REQUIRES_MANUAL_INSPECTION=true
                error "A staging chain exists after failed creation; ownership is uncertain. Manual inspection required: $staging"
            else
                status=$?

                if [[ "$status" -ne 1 ]]; then
                    ROLLBACK_REQUIRES_MANUAL_INSPECTION=true
                    error "Unable to inspect staging chain after failed creation: $staging"
                fi
            fi

            error "Staging-chain creation failed: $staging"

        fi

    fi

    for rule in "${expected_rules[@]}"; do

        read -r -a RULE_ARGS <<< "$rule"

        "$IPTABLES" -A "$staging" "${RULE_ARGS[@]}"

    done

    verify_chain "$staging" "$expected_name" ||
        error "Staging chain verification failed: $staging"

    # A successful rename transfers ownership from staging
    # to production. A failed rename leaves ownership uncertain.

    if "$IPTABLES" -E "$staging" "$production"; then

        if [[ "$production" == "$FIREWALL_CHAIN" ]]; then
            FORWARD_CHAIN_CREATED=true
            FORWARD_STAGING_CHAIN_CREATED=false
        elif [[ "$production" == "$INPUT_FIREWALL_CHAIN" ]]; then
            INPUT_CHAIN_CREATED=true
            INPUT_STAGING_CHAIN_CREATED=false
        else
            error "Unknown production-chain ownership: $production"
        fi

    else

        log "ERROR: Chain promotion returned failure: $staging -> $production"

        ROLLBACK_REQUIRES_MANUAL_INSPECTION=true

        error "Chain promotion ownership is uncertain. Preserving resources for manual inspection: $staging -> $production"

    fi

    verify_chain "$production" "$expected_name" ||
        error "Production verification failed: $production"

    log "Production chain promoted: $production"
}

# ==========================================================
# 8. Validate existing hooks before modifications
# ==========================================================

validate_hook() {

    local parent="$1"
    local production="$2"

    local references
    local parent_rules
    local expected_reference
    local hook_count
    local first_rule

    references="$(references_to_chain "$production")" ||
        error "Unable to inspect references to $production."

    expected_reference="-A $parent -j $production"

    while IFS= read -r reference; do

        [[ -z "$reference" ]] && continue

        [[ "$reference" == "$expected_reference" ]] ||
            error "Unexpected reference to $production: $reference"

    done <<< "$references"

    parent_rules="$("$IPTABLES" -S "$parent")" ||
        error "Unable to inspect $parent rules."

    hook_count="$(
        awk -v expected="$expected_reference" '
            $0 == expected { count++ }
            END { print count + 0 }
        ' <<< "$parent_rules"
    )"

    [[ "$hook_count" -le 1 ]] ||
        error "Duplicate $parent hooks detected."

    if [[ "$hook_count" -eq 1 ]]; then

        first_rule="$(sed -n '2p' <<< "$parent_rules")"

        [[ "$first_rule" == "$expected_reference" ]] ||
            error "$production hook is not first in $parent."

    fi
}

validate_hook FORWARD "$FIREWALL_CHAIN"

if [[ "$INPUT_FIREWALL_ENABLED" == "true" ]]; then

    validate_hook INPUT "$INPUT_FIREWALL_CHAIN"

fi

# ==========================================================
# 8A. Validate all existing production chains before changes
# ==========================================================

log "Preflighting existing production chains."

if chain_exists "$FIREWALL_CHAIN"; then

    log "Validating existing FORWARD production chain."

    verify_chain "$FIREWALL_CHAIN" EXPECTED_FORWARD_RULES ||
        error "Existing FORWARD chain contains unexpected rules: $FIREWALL_CHAIN"

else
    status=$?

    [[ "$status" -eq 1 ]] ||
        error "Unable to inspect FORWARD production chain: $FIREWALL_CHAIN"

    log "FORWARD production chain does not exist yet."

fi

if [[ "$INPUT_FIREWALL_ENABLED" == "true" ]]; then

    if chain_exists "$INPUT_FIREWALL_CHAIN"; then

        log "Validating existing INPUT production chain."

        verify_chain "$INPUT_FIREWALL_CHAIN" EXPECTED_INPUT_RULES ||
            error "Existing INPUT chain contains unexpected rules: $INPUT_FIREWALL_CHAIN"

    else
        status=$?

        [[ "$status" -eq 1 ]] ||
            error "Unable to inspect INPUT production chain: $INPUT_FIREWALL_CHAIN"

        log "INPUT production chain does not exist yet."

    fi

fi

log "Production-chain preflight validation passed."

# ==========================================================
# 8B. Global staging-chain preflight
# ==========================================================

log "Preflighting all existing staging chains."

# ----------------------------------------------------------
# FORWARD staging chain
# ----------------------------------------------------------

if chain_exists "$STAGING_CHAIN"; then

    log "Validating FORWARD staging chain."

    references="$(references_to_chain "$STAGING_CHAIN")" ||
        error "Unable to inspect FORWARD staging-chain references."

    [[ -z "$references" ]] ||
        error "FORWARD staging chain has unexpected references."

    verify_staging_prefix "$STAGING_CHAIN" EXPECTED_FORWARD_RULES ||
        error "FORWARD staging chain contains unexpected rules."

else
    status=$?

    [[ "$status" -eq 1 ]] ||
        error "Unable to inspect FORWARD staging chain: $STAGING_CHAIN"

    log "FORWARD staging chain does not exist."

fi

# ----------------------------------------------------------
# INPUT staging chain
# ----------------------------------------------------------

if [[ "$INPUT_FIREWALL_ENABLED" == "true" ]]; then

    if chain_exists "$INPUT_FIREWALL_STAGING_CHAIN"; then

        log "Validating INPUT staging chain."

        references="$(references_to_chain "$INPUT_FIREWALL_STAGING_CHAIN")" ||
            error "Unable to inspect INPUT staging-chain references."

        [[ -z "$references" ]] ||
            error "INPUT staging chain has unexpected references."

        verify_staging_prefix "$INPUT_FIREWALL_STAGING_CHAIN" EXPECTED_INPUT_RULES ||
            error "INPUT staging chain contains unexpected rules."

    else
        status=$?

        [[ "$status" -eq 1 ]] ||
            error "Unable to inspect INPUT staging chain: $INPUT_FIREWALL_STAGING_CHAIN"

        log "INPUT staging chain does not exist."

    fi

fi

log "Global staging-chain preflight validation passed."

# ==========================================================
# Transaction compensation functions
# ==========================================================

remove_created_chain() {

    local chain="$1"
    local expected_name="$2"
    local references
    local status
    local ownership_flag

    # Never delete a chain that this execution did not create.
    if [[ "$chain" == "$FIREWALL_CHAIN" ]]; then
        ownership_flag="FORWARD_CHAIN_CREATED"
    elif [[ "$chain" == "$INPUT_FIREWALL_CHAIN" ]]; then
        ownership_flag="INPUT_CHAIN_CREATED"
    else
        log "ERROR: Unknown production-chain ownership: $chain"
        return 1
    fi

    [[ "${!ownership_flag}" == "true" ]] || return 0

    if chain_exists "$chain"; then
        :
    else
        status=$?

        if [[ "$status" -eq 1 ]]; then
            log "Owned production chain is already absent: $chain"
            printf -v "$ownership_flag" '%s' false
            return 0
        fi

        log "ERROR: Unable to inspect firewall chain: $chain"
        return 1
    fi

    references="$(references_to_chain "$chain")" || {
        log "ERROR: Unable to inspect references to $chain."
        return 1
    }

    if [[ -n "$references" ]]; then
        log "ERROR: Refusing to remove referenced chain: $chain"
        return 1
    fi

    if ! verify_chain "$chain" "$expected_name"; then
        log "ERROR: Refusing to remove modified chain: $chain"
        return 1
    fi

    log "Removing newly created production chain: $chain"

    "$IPTABLES" -F "$chain" || return 1

    if "$IPTABLES" -X "$chain"; then
        :
    else
        status=$?
        log "WARNING: Chain deletion returned status $status: $chain"
        log "Checking actual chain state before deciding cleanup status."
    fi

    if chain_exists "$chain"; then
        log "ERROR: Chain remains after cleanup: $chain"
        return 1
    else
        status=$?

        if [[ "$status" -ne 1 ]]; then
            log "ERROR: Unable to verify chain removal: $chain"
            return 1
        fi
    fi

    return 0
}

cleanup_created_staging_chain() {

    local chain="$1"
    local expected_name="$2"
    local ownership_flag="$3"

    local references
    local status

    # Only clean staging chains created by this execution.
    if [[ "${!ownership_flag}" != "true" ]]; then
        return 0
    fi

    if chain_exists "$chain"; then
        :
    else
        status=$?

        if [[ "$status" -eq 1 ]]; then
            log "Owned staging chain is already absent: $chain"
            printf -v "$ownership_flag" '%s' false
            return 0
        fi

        log "ERROR: Unable to inspect staging chain: $chain"
        return 1
    fi

    references="$(references_to_chain "$chain")" || {
        log "ERROR: Unable to inspect staging-chain references: $chain"
        return 1
    }

    if [[ -n "$references" ]]; then
        log "ERROR: Refusing to remove referenced staging chain: $chain"
        return 1
    fi

    if ! verify_staging_prefix "$chain" "$expected_name"; then
        log "ERROR: Refusing to remove modified staging chain: $chain"
        return 1
    fi

    log "Removing newly created staging chain: $chain"

    "$IPTABLES" -F "$chain" || return 1

    if "$IPTABLES" -X "$chain"; then
        :
    else
        status=$?
        log "WARNING: Staging-chain deletion returned status $status: $chain"
        log "Checking actual staging-chain state before deciding cleanup status."
    fi

    if chain_exists "$chain"; then
        log "ERROR: Staging chain remains after cleanup: $chain"
        return 1
    else
        status=$?

        if [[ "$status" -ne 1 ]]; then
            log "ERROR: Unable to verify staging-chain removal: $chain"
            return 1
        fi
    fi

    printf -v "$ownership_flag" '%s' false
    return 0
}

remove_owned_hook() {

    local parent="$1"
    local chain="$2"
    local ownership_flag="$3"

    local references
    local expected
    local count
    local delete_status

    [[ "${!ownership_flag}" == "true" ]] || return 0

    expected="-A $parent -j $chain"

    references="$(references_to_chain "$chain")" || {
        log "ERROR: Unable to inspect references to hook chain: $chain"
        return 1
    }

    while IFS= read -r reference; do
        [[ -z "$reference" ]] && continue

        if [[ "$reference" != "$expected" ]]; then
            log "ERROR: Unexpected reference prevents hook removal: $reference"
            return 1
        fi
    done <<< "$references"

    count="$(
        awk -v expected="$expected" '
            $0 == expected { count++ }
            END { print count + 0 }
        ' <<< "$references"
    )"

    if [[ "$count" -gt 1 ]]; then
        log "ERROR: Duplicate owned-hook references detected: $parent -> $chain"
        return 1
    fi

    if [[ "$count" -eq 1 ]]; then

        if "$IPTABLES" -D "$parent" -j "$chain"; then
            :
        else
            delete_status=$?
            log "WARNING: Hook deletion returned status $delete_status: $parent -> $chain"
        fi

    fi

    # Verify using a fresh global ruleset inspection.
    references="$(references_to_chain "$chain")" || {
        log "ERROR: Unable to verify hook removal: $chain"
        return 1
    }

    if [[ -n "$references" ]]; then
        log "ERROR: Hook reference remains after compensation: $chain"
        return 1
    fi

    printf -v "$ownership_flag" '%s' false

    log "Verified removal of owned hook: $parent -> $chain"
    return 0
}

rollback_activation() {

    local cleanup_failed="$ROLLBACK_REQUIRES_MANUAL_INSPECTION"

    if [[ "$cleanup_failed" == "true" ]]; then
        log "CRITICAL: Transaction contains resources with uncertain ownership."
        log "CRITICAL: Manual firewall inspection is required."
    fi

    if [[ "$ROLLBACK_STARTED" == "true" ]]; then
        log "Rollback has already been started; refusing duplicate compensation."
        [[ "$ROLLBACK_COMPLETED" == "true" &&
           "$ROLLBACK_FAILED" == "false" ]]
        return
    fi

    ROLLBACK_STARTED=true

    log "Rolling back newly inserted hooks and owned chains."

    # Remove only hooks inserted by this execution.
    if ! remove_owned_hook FORWARD "$FIREWALL_CHAIN" FORWARD_HOOK_ADDED; then
        log "ERROR: FORWARD hook compensation failed."
        cleanup_failed=true
    fi

    if [[ "$INPUT_FIREWALL_ENABLED" == "true" ]]; then
        if ! remove_owned_hook INPUT "$INPUT_FIREWALL_CHAIN" INPUT_HOOK_ADDED; then
            log "ERROR: INPUT hook compensation failed."
            cleanup_failed=true
        fi
    fi

    # Remove only production chains created by this execution.
    if [[ "$FORWARD_CHAIN_CREATED" == "true" ]]; then
        if ! remove_created_chain "$FIREWALL_CHAIN" EXPECTED_FORWARD_RULES; then
            log "ERROR: FORWARD production-chain cleanup failed."
            cleanup_failed=true
        fi
    fi

    if [[ "$INPUT_CHAIN_CREATED" == "true" ]]; then
        if ! remove_created_chain "$INPUT_FIREWALL_CHAIN" EXPECTED_INPUT_RULES; then
            log "ERROR: INPUT production-chain cleanup failed."
            cleanup_failed=true
        fi
    fi

    # Remove only staging chains created by this execution.
    if ! cleanup_created_staging_chain \
        "$STAGING_CHAIN" EXPECTED_FORWARD_RULES \
        FORWARD_STAGING_CHAIN_CREATED; then
        log "ERROR: FORWARD staging-chain cleanup failed."
        cleanup_failed=true
    fi

    if [[ "$INPUT_FIREWALL_ENABLED" == "true" ]]; then
        if ! cleanup_created_staging_chain \
            "$INPUT_FIREWALL_STAGING_CHAIN" EXPECTED_INPUT_RULES \
            INPUT_STAGING_CHAIN_CREATED; then
            log "ERROR: INPUT staging-chain cleanup failed."
            cleanup_failed=true
        fi
    fi

    if [[ "$cleanup_failed" == "true" ]]; then
        ROLLBACK_FAILED=true
        ROLLBACK_COMPLETED=false
        log "CRITICAL: Activation compensation was incomplete."
        return 1
    fi

    ROLLBACK_FAILED=false
    ROLLBACK_COMPLETED=true

    log "Activation compensation completed successfully."
    return 0
}

activation_failure() {

    local reason="$1"

    # The EXIT trap owns all transaction compensation.
    error "$reason"
}

transaction_exit() {

    local original_status=$?

    # Prevent recursive EXIT handling.
    trap - EXIT

    if [[ "$TRANSACTION_COMMITTED" == "true" ]]; then
        exit "$original_status"
    fi

    if [[ "$ROLLBACK_STARTED" == "true" ]]; then

        if [[ "$ROLLBACK_COMPLETED" == "true" &&
              "$ROLLBACK_FAILED" == "false" ]]; then
            log "Rollback was already completed successfully."
        else
            log "CRITICAL: Previous rollback attempt was incomplete."
            log "CRITICAL: Manual firewall inspection is required."
        fi

        exit "$original_status"
    fi

    if [[ "$original_status" -eq 0 ]]; then
        log "ERROR: Installer exited before transaction commit."
        original_status=1
    fi

    log "Transaction failed. Starting automatic compensation."

    if ! rollback_activation; then
        log "CRITICAL: Automatic compensation was incomplete."
        log "CRITICAL: Manual firewall inspection is required."
    fi

    exit "$original_status"
}

# ==========================================================
# 9. Prepare FORWARD chain
# ==========================================================

# Track resources created during this installer execution.
INPUT_HOOK_ADDED=false
FORWARD_HOOK_ADDED=false

INPUT_CHAIN_CREATED=false
FORWARD_CHAIN_CREATED=false

INPUT_STAGING_CHAIN_CREATED=false
FORWARD_STAGING_CHAIN_CREATED=false

TRANSACTION_COMMITTED=false
ROLLBACK_STARTED=false
ROLLBACK_COMPLETED=false
ROLLBACK_FAILED=false
ROLLBACK_REQUIRES_MANUAL_INSPECTION=false

# Install the trap before the first firewall modification.
trap transaction_exit EXIT

prepare_chain \
    "$FIREWALL_CHAIN" \
    "$STAGING_CHAIN" \
    EXPECTED_FORWARD_RULES

# ==========================================================
# 10. Prepare INPUT chain
# ==========================================================

if [[ "$INPUT_FIREWALL_ENABLED" == "true" ]]; then

    prepare_chain \
        "$INPUT_FIREWALL_CHAIN" \
        "$INPUT_FIREWALL_STAGING_CHAIN" \
        EXPECTED_INPUT_RULES

fi

# ==========================================================
# 11. Transactional firewall hook activation
# ==========================================================


ensure_hook() {

    local parent="$1"
    local chain="$2"
    local references
    local expected
    local count
    local first_rule
    local ownership_flag
    local insert_status

    case "$parent" in
        INPUT)
            ownership_flag="INPUT_HOOK_ADDED"
            ;;
        FORWARD)
            ownership_flag="FORWARD_HOOK_ADDED"
            ;;
        *)
            log "ERROR: Unsupported hook parent: $parent"
            return 1
            ;;
    esac

    expected="-A $parent -j $chain"

    # Inspect all references. Inspection failure is never
    # interpreted as an absent hook.
    references="$(references_to_chain "$chain")" || {
        log "ERROR: Unable to inspect hook references: $chain"
        return 1
    }

    # Reject unexpected references.
    while IFS= read -r reference; do
        [[ -z "$reference" ]] && continue

        if [[ "$reference" != "$expected" ]]; then
            log "ERROR: Unexpected hook reference: $reference"
            return 1
        fi
    done <<< "$references"

    count="$(
        awk -v expected="$expected" '
            $0 == expected { count++ }
            END { print count + 0 }
        ' <<< "$references"
    )"

    if [[ "$count" -gt 1 ]]; then
        log "ERROR: Duplicate hook references: $parent -> $chain"
        return 1
    fi

    if [[ "$count" -eq 1 ]]; then

        first_rule="$("$IPTABLES" -S "$parent" | sed -n '2p')" || {
            log "ERROR: Unable to verify existing hook ordering: $parent"
            return 1
        }

        if [[ "$first_rule" != "$expected" ]]; then
            log "ERROR: Existing hook is not first: $parent -> $chain"
            return 1
        fi

        log "$parent hook already exists and is correctly positioned: $chain"
        return 0

    fi

    log "Inserting $parent hook: $chain"

    if "$IPTABLES" -I "$parent" 1 -j "$chain"; then
        printf -v "$ownership_flag" '%s' true
    else
        insert_status=$?
        log "WARNING: Hook insertion returned status $insert_status."

        # Detect a possible side effect despite command failure.
        references="$(references_to_chain "$chain")" || {
            log "ERROR: Cannot determine whether hook insertion took effect."
            return 1
        }

        count="$(
            awk -v expected="$expected" '
                $0 == expected { count++ }
                END { print count + 0 }
            ' <<< "$references"
        )"

        if [[ "$count" -eq 1 ]]; then
            printf -v "$ownership_flag" '%s' true
            log "Detected hook insertion despite command failure."
        fi

        return 1
    fi

    # Verify the successful insertion.
    references="$(references_to_chain "$chain")" || {
        log "ERROR: Unable to verify inserted hook."
        return 1
    }

    if [[ "$references" != "$expected" ]]; then
        log "ERROR: Inserted hook references are unexpected."
        return 1
    fi

    first_rule="$("$IPTABLES" -S "$parent" | sed -n '2p')" || {
        log "ERROR: Unable to verify inserted hook ordering."
        return 1
    }

    if [[ "$first_rule" != "$expected" ]]; then
        log "ERROR: Inserted hook is not first: $parent -> $chain"
        return 1
    fi

    log "Verified newly inserted hook: $parent -> $chain"
    return 0
}

# ==========================================================
# 12. Activate INPUT hook
# ==========================================================

if [[ "$INPUT_FIREWALL_ENABLED" == "true" ]]; then

    ensure_hook INPUT "$INPUT_FIREWALL_CHAIN" ||
        activation_failure "INPUT hook activation failed."

fi

# ==========================================================
# 13. Activate FORWARD hook
# ==========================================================

ensure_hook FORWARD "$FIREWALL_CHAIN" ||
    activation_failure "FORWARD hook activation failed."

# ==========================================================
# 14. Final policy verification
# ==========================================================

verify_chain "$FIREWALL_CHAIN" EXPECTED_FORWARD_RULES ||
    activation_failure "Final FORWARD policy verification failed."

if [[ "$INPUT_FIREWALL_ENABLED" == "true" ]]; then

    verify_chain "$INPUT_FIREWALL_CHAIN" EXPECTED_INPUT_RULES ||
        activation_failure "Final INPUT policy verification failed."

    FIRST_INPUT_RULE="$("$IPTABLES" -S INPUT | sed -n '2p')" ||
        activation_failure "Unable to inspect INPUT hook ordering."

    [[ "$FIRST_INPUT_RULE" == "-A INPUT -j $INPUT_FIREWALL_CHAIN" ]] ||
        activation_failure "INPUT firewall hook is not first."

fi

FIRST_FORWARD_RULE="$("$IPTABLES" -S FORWARD | sed -n '2p')" ||
    activation_failure "Unable to inspect FORWARD hook ordering."

[[ "$FIRST_FORWARD_RULE" == "-A FORWARD -j $FIREWALL_CHAIN" ]] ||
    activation_failure "FORWARD firewall hook is not first."

# Commit only after all chain and hook verification succeeds.
TRANSACTION_COMMITTED=true

log "CloudVPN firewall successfully activated."

exit 0
