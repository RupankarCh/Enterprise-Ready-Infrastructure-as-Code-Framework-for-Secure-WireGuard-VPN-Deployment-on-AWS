#!/usr/bin/env bash

set -Eeuo pipefail

# ==========================================================
# CloudVPN - Safe Dual-Chain Firewall Rollback
# ==========================================================

FIREWALL_CHAIN="${FIREWALL_CHAIN:-CLOUDVPN_FORWARD}"
STAGING_CHAIN="${STAGING_CHAIN:-${FIREWALL_CHAIN}_STAGE}"

INPUT_FIREWALL_CHAIN="${INPUT_FIREWALL_CHAIN:-CLOUDVPN_INPUT}"
INPUT_FIREWALL_STAGING_CHAIN="${INPUT_FIREWALL_STAGING_CHAIN:-CLOUDVPN_INPUT_STAGE}"

IPTABLES="${IPTABLES:-/usr/sbin/iptables}"
RULE_NORMALIZER="${RULE_NORMALIZER:-/usr/local/libexec/cloudvpn-firewall-rule-normalize.py}"
LOCK_FILE="${LOCK_FILE:-/run/lock/cloudvpn-firewall.lock}"
VPN_INTERFACE="${VPN_INTERFACE:-wg0}"
EXTERNAL_INTERFACE="${EXTERNAL_INTERFACE:-ens5}"
VPN_SUBNET="${VPN_SUBNET:-10.8.0.0/24}"

log() {
    echo "[CloudVPN Rollback] $*"
}

error() {
    echo "[CloudVPN Rollback ERROR] $*" >&2
    exit 1
}

# ==========================================================
# 1. Preflight checks
# ==========================================================

[[ "$EUID" -eq 0 ]] || error "Must run as root."

[[ -x "$IPTABLES" ]] ||
    error "iptables executable unavailable."

[[ -x "$RULE_NORMALIZER" ]] ||
    error "Firewall rule normalizer unavailable."

command -v python3 >/dev/null ||
    error "Python3 unavailable."

command -v flock >/dev/null ||
    error "flock command unavailable."

for chain in \
    "$FIREWALL_CHAIN" \
    "$STAGING_CHAIN" \
    "$INPUT_FIREWALL_CHAIN" \
    "$INPUT_FIREWALL_STAGING_CHAIN"
do
    [[ "$chain" =~ ^[A-Za-z0-9_]{1,28}$ ]] ||
        error "Invalid chain name: $chain"
done

[[ "$FIREWALL_CHAIN" != "$STAGING_CHAIN" ]] ||
    error "FORWARD production and staging chains must differ."

[[ "$INPUT_FIREWALL_CHAIN" != "$INPUT_FIREWALL_STAGING_CHAIN" ]] ||
    error "INPUT production and staging chains must differ."

[[ "$FIREWALL_CHAIN" != "$INPUT_FIREWALL_CHAIN" &&
   "$FIREWALL_CHAIN" != "$INPUT_FIREWALL_STAGING_CHAIN" &&
   "$STAGING_CHAIN" != "$INPUT_FIREWALL_CHAIN" &&
   "$STAGING_CHAIN" != "$INPUT_FIREWALL_STAGING_CHAIN" ]] ||
    error "FORWARD and INPUT chain names must be unique."

# ==========================================================
# Expected CloudVPN firewall rules
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

# shellcheck disable=SC2034
EXPECTED_INPUT_RULES=(

    "-i $VPN_INTERFACE ! -s $VPN_SUBNET -j DROP"

    "-i $VPN_INTERFACE -s $VPN_SUBNET -d 169.254.0.0/16 -j DROP"

    "-i $VPN_INTERFACE -j DROP"

    "-j RETURN"
)

# ==========================================================
# 2. Prevent concurrent firewall operations
# ==========================================================

exec 9>"$LOCK_FILE"

flock -n 9 ||
    error "Another CloudVPN firewall operation is running."

log "Rollback lock acquired."

# ==========================================================
# 3. Chain reference detection
# ==========================================================

chain_exists() {

    local target="$1"
    local rules

    rules="$("$IPTABLES" -S)" || {
        log "ERROR: Unable to inspect firewall chains."
        return 2
    }

    awk -v target="$target" '
        $1 == "-N" && $2 == target { found = 1 }
        END { exit(found ? 0 : 1) }
    ' <<< "$rules"
}

references_to_chain() {

    local target="$1"
    local rules

    rules="$("$IPTABLES" -S)" || {
        log "ERROR: Unable to inspect references to $target."
        return 2
    }

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
# Verify exact production-chain contents
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
# 4. Validate all references before changing anything
# ==========================================================

validate_production_references() {

    local chain="$1"
    local parent="$2"

    local references
    local reference
    local expected_reference

    references="$(references_to_chain "$chain")" ||
        error "Unable to inspect references to production chain: $chain"

    expected_reference="-A $parent -j $chain"

    while IFS= read -r reference; do

        [[ -z "$reference" ]] && continue

        [[ "$reference" == "$expected_reference" ]] ||
            error "Unexpected reference to $chain: $reference"

    done <<< "$references"

}

validate_staging_references() {

    local chain="$1"

    local references

    references="$(references_to_chain "$chain")" ||
        error "Unable to inspect references to staging chain: $chain"

    [[ -z "$references" ]] ||
        error "Staging chain is referenced elsewhere: $chain"

}

log "Validating all chain references."

validate_production_references "$FIREWALL_CHAIN" FORWARD

validate_production_references "$INPUT_FIREWALL_CHAIN" INPUT

validate_staging_references "$STAGING_CHAIN"

validate_staging_references "$INPUT_FIREWALL_STAGING_CHAIN"

log "All chain references passed preflight validation."

# ==========================================================
# Validate all existing chain contents before rollback
# ==========================================================

log "Validating all existing CloudVPN chain contents."

validate_existing_chain() {

    local chain="$1"
    local expected_name="$2"
    local chain_type="$3"
    local status

    if chain_exists "$chain"; then

        if [[ "$chain_type" == "production" ]]; then
            verify_chain "$chain" "$expected_name" ||
                error "Refusing to remove unexpected production chain: $chain"
        elif [[ "$chain_type" == "staging" ]]; then
            verify_staging_prefix "$chain" "$expected_name" ||
                error "Refusing to remove unexpected staging chain: $chain"
        else
            error "Unknown chain type: $chain_type"
        fi

    else
        status=$?

        [[ "$status" -eq 1 ]] ||
            error "Cannot determine whether chain exists: $chain"

        log "Chain confirmed absent: $chain"
    fi
}

validate_existing_chain "$FIREWALL_CHAIN" EXPECTED_FORWARD_RULES production
validate_existing_chain "$INPUT_FIREWALL_CHAIN" EXPECTED_INPUT_RULES production
validate_existing_chain "$STAGING_CHAIN" EXPECTED_FORWARD_RULES staging
validate_existing_chain "$INPUT_FIREWALL_STAGING_CHAIN" EXPECTED_INPUT_RULES staging

log "All existing CloudVPN chain contents passed validation."

# ==========================================================
# 5. Remove production hooks
# ==========================================================

remove_production_hook() {

    local parent="$1"
    local chain="$2"

    local references
    local reference

    while true; do

        references="$(references_to_chain "$chain")" ||
            error "Unable to inspect references before hook removal: $chain"

        [[ -n "$references" ]] || break

        while IFS= read -r reference; do

            [[ -z "$reference" ]] && continue

            [[ "$reference" == "-A $parent -j $chain" ]] ||
                error "Unexpected reference while removing $chain: $reference"

        done <<< "$references"

        log "Removing $parent hook for $chain."

        "$IPTABLES" -D "$parent" -j "$chain" ||
            error "Failed to remove $parent hook for $chain."

    done

    references="$(references_to_chain "$chain")" ||
        error "Unable to verify hook removal for $chain"

    [[ -z "$references" ]] ||
        error "References remain for production chain: $chain"

}

remove_production_hook FORWARD "$FIREWALL_CHAIN"

remove_production_hook INPUT "$INPUT_FIREWALL_CHAIN"

# ==========================================================
# 6. Remove production chains
# ==========================================================

remove_chain() {

    local chain="$1"
    local expected_name="$2"
    local chain_type="$3"

    local status
    local references

    if chain_exists "$chain"; then

        # Recheck references immediately before deletion.
        references="$(references_to_chain "$chain")" ||
            error "Unable to inspect references before chain deletion: $chain"

        [[ -z "$references" ]] ||
            error "Cannot remove referenced chain: $chain"

        # Revalidate ownership immediately before flushing.
        if [[ "$chain_type" == "production" ]]; then

            verify_chain "$chain" "$expected_name" ||
                error "Refusing to flush modified production chain: $chain"

        elif [[ "$chain_type" == "staging" ]]; then

            verify_staging_prefix "$chain" "$expected_name" ||
                error "Refusing to flush modified staging chain: $chain"

        else

            error "Unknown chain type: $chain_type"

        fi

        log "Flushing validated chain: $chain"

        "$IPTABLES" -F "$chain"

        log "Deleting chain: $chain"

        "$IPTABLES" -X "$chain"

    else

        status=$?

        [[ "$status" -eq 1 ]] ||
            error "Cannot determine whether chain exists before deletion: $chain"

        log "Chain confirmed absent: $chain"

    fi

}

remove_chain "$FIREWALL_CHAIN" EXPECTED_FORWARD_RULES production

remove_chain "$INPUT_FIREWALL_CHAIN" EXPECTED_INPUT_RULES production

remove_chain "$STAGING_CHAIN" EXPECTED_FORWARD_RULES staging

remove_chain "$INPUT_FIREWALL_STAGING_CHAIN" EXPECTED_INPUT_RULES staging


# ==========================================================
# 8. Final verification
# ==========================================================

log "Performing final rollback verification."

for chain in \
    "$FIREWALL_CHAIN" \
    "$STAGING_CHAIN" \
    "$INPUT_FIREWALL_CHAIN" \
    "$INPUT_FIREWALL_STAGING_CHAIN"
do

    if chain_exists "$chain"; then
        error "Chain still exists after rollback: $chain"
    else
        status=$?

        [[ "$status" -eq 1 ]] ||
            error "Final chain inspection failed: $chain"
    fi

    references="$(references_to_chain "$chain")" ||
        error "Unable to verify references after rollback: $chain"

    [[ -z "$references" ]] ||
        error "References remain after rollback: $chain"

    log "Verified chain removal: $chain"

done

log "All CloudVPN chains and hooks removed successfully."

log "Unrelated firewall rules and policies were not intentionally modified."

exit 0
