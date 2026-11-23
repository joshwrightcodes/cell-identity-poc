#!/usr/bin/env bash
# Cut and heal the traffic between two kind clusters with tagged firewall rules on the node container of one of them.
#
# Usage:
#   partition.sh cut --from <cluster> --to <cluster> [--direction both|out|in] --hold <minutes> [--tag <tag>]
#   partition.sh heal --tag <tag>
#   partition.sh heal --all
#   partition.sh list
#
# cut puts DROP rules in the node <from>-control-plane for each address of <to>-control-plane on the network kind: the IPv4 address
# through iptables and the IPv6 address through ip6tables. A peer with no IPv6 address gets IPv4 rules only. Direction out drops
# packets to the peer in FORWARD and OUTPUT. Direction in drops packets from the peer in FORWARD and INPUT. Direction both does
# both. Each rule carries the comment gate-m9-cut-<8 hex> and goes in at position 1. The hold is 1 to 600 minutes. Before the first
# rule goes in, the script arms one removal timer in the node for each rule. A timer sleeps for the hold plus 15 minutes, then
# deletes its rule when the rule is still there. The script prints one JSON line with tag, node, peers, direction, ipv6 and until.
# heal deletes the rules of one tag, or every rule of the tool, on every existing cluster. It finds the rules by their comment and
# not by the address, so it also deletes a rule that a crash left behind. list prints one JSON line for each rule. The script
# never reads or changes a rule whose comment does not start with gate-m9-cut-.
export CELL=dev-cp
source "$(dirname "$0")/lib.sh"

PREFIX=gate-m9-cut-

usage() {
  die "usage: partition cut --from <cluster> --to <cluster> [--direction both|out|in] --hold <minutes> [--tag <tag>] | heal --tag <tag> | heal --all | list"
}

# check_tag <tag> stops the script unless the tag has the form gate-m9-cut- and 8 hex digits.
check_tag() {
  [[ "$1" =~ ^${PREFIX}[0-9a-f]{8}$ ]] || die "the tag '$1' is not of the form ${PREFIX}<8 hex>"
}

# check_cluster <name> stops the script unless the name is a plain cluster name.
check_cluster() {
  [[ "$1" =~ ^[a-z0-9][a-z0-9-]*$ ]] || die "'$1' is not a cluster name"
}

# nodes prints the node container of each existing cluster.
nodes() {
  local clusters c
  clusters="$(existing_clusters)" || die "could not list the clusters"
  for c in $clusters; do printf '%s-control-plane\n' "$c"; done
}

# heal_nodes [tag] deletes the rules of the tool, or of the tag, in each node and checks that none is left. A node that fails does not
# stop the walk: the script records it, goes on with the next node, prints one JSON line, and returns 1 with the names of the failed nodes.
heal_nodes() {
  local tag="${1:-}" node rules rule left healed=0 touched=() failed=() parts bad
  for node in $(nodes); do
    if ! rules="$(partition_rules "$node" ${tag:+"$tag"})"; then
      echo "error: the node $node does not answer, so its rules are unchecked" >&2
      failed+=("$node")
      continue
    fi
    [[ -n "$rules" ]] || continue
    touched+=("$node")
    bad=0
    while IFS= read -r rule; do
      [[ -n "$rule" ]] || continue
      read -r -a parts <<<"$rule"
      log "deleting on $node: $rule"
      if docker exec "$node" "${parts[@]}"; then
        healed=$((healed + 1))
      else
        echo "error: could not delete the rule '$rule' on $node" >&2
        bad=1
      fi
    done <<<"$rules"
    if left="$(partition_rules "$node" ${tag:+"$tag"})"; then
      [[ -z "$left" ]] || { echo "error: the node $node still holds the rules: ${left//$'\n'/; }" >&2; bad=1; }
    else
      echo "error: the node $node does not answer after the delete" >&2
      bad=1
    fi
    ((bad == 0)) || failed+=("$node")
  done
  jq -nc --arg tag "${tag:-all}" --argjson healed "$healed" --args '{tag: $tag, healed: $healed, nodes: $ARGS.positional}' ${touched[@]+"${touched[@]}"}
  if ((${#failed[@]} > 0)); then
    echo "error: the heal failed on: ${failed[*]}. Run again: mise run partition -- heal --all" >&2
    return 1
  fi
}

# cut_failed <message> heals the tag of the cut in progress and stops. The message says that the rules are deleted only when the heal worked.
cut_failed() {
  if (heal_nodes "$CUT_TAG") >/dev/null 2>&1; then
    die "$1, and the rules of $CUT_TAG are deleted"
  fi
  die "$1, and the heal of $CUT_TAG failed. Run: mise run partition -- heal --all"
}

cmd_cut() {
  local from="" to="" direction=both hold="" tag="" node peer v4 v6 now secs until existing
  local peers=() rules=() r fam addr mask tool pairs pair chain flag spec
  while (($#)); do
    case "$1" in
      --from) from="${2:-}"; shift 2 ;;
      --to) to="${2:-}"; shift 2 ;;
      --direction) direction="${2:-}"; shift 2 ;;
      --hold) hold="${2:-}"; shift 2 ;;
      --tag) tag="${2:-}"; shift 2 ;;
      *) usage ;;
    esac
  done
  [[ -n "$from" && -n "$to" && -n "$hold" ]] || usage
  check_cluster "$from"
  check_cluster "$to"
  [[ "$from" != "$to" ]] || die "cannot cut $from from itself: --from and --to name the same cluster"
  case "$direction" in both | out | in) ;; *) die "the direction is both, out or in, not '$direction'" ;; esac
  if ! [[ "$hold" =~ ^[1-9][0-9]{0,2}$ ]] || ((hold > 600)); then die "the hold is 1 to 600 minutes, not '$hold'"; fi
  if [[ -z "$tag" ]]; then
    tag="$PREFIX$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
  fi
  check_tag "$tag"
  CUT_TAG="$tag"

  existing="$(existing_clusters)" || die "could not list the clusters"
  for r in "$from" "$to"; do
    grep -qx -- "$r" <<<"$existing" || die "'$r' is not a cluster of the topology that exists now. The clusters are: ${existing//$'\n'/ }"
  done

  node="$from-control-plane"
  peer="$to-control-plane"
  v4="$(partition_peer_ip "$peer" 4)" || die "could not read the address of $peer"
  v6="$(partition_peer_ip "$peer" 6)" || die "could not read the address of $peer"
  [[ "$v4" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "$peer has no IPv4 address on the network kind"
  [[ -z "$v6" || "$v6" =~ ^[0-9a-fA-F]{0,4}(:[0-9a-fA-F]{0,4}){2,7}$ ]] || die "$peer reports the IPv6 address '$v6', which is no IPv6 address"
  now="$(docker exec "$node" date +%s)" || die "the node $node does not answer"
  [[ "$now" =~ ^[0-9]+$ ]] || die "the node $node reports the time '$now'"
  r="$(partition_rules "$node" "$tag")" || die "the node $node does not answer"
  [[ -z "$r" ]] || die "the node $node holds rules of the tag $tag already"

  case "$direction" in
    both) pairs="FORWARD:-d OUTPUT:-d FORWARD:-s INPUT:-s" ;;
    out) pairs="FORWARD:-d OUTPUT:-d" ;;
    in) pairs="FORWARD:-s INPUT:-s" ;;
  esac
  peers=("$v4")
  [[ -z "$v6" ]] || peers+=("$v6")
  for fam in 4 6; do
    if [[ "$fam" == 4 ]]; then tool=iptables addr="$v4" mask=32; else tool=ip6tables addr="$v6" mask=128; fi
    [[ -n "$addr" ]] || continue
    for pair in $pairs; do
      chain="${pair%%:*}" flag="${pair#*:}"
      rules+=("$tool $chain $flag $addr/$mask -m comment --comment $tag -j DROP")
    done
  done

  # Every timer is armed before the first rule goes in, so no rule exists without its removal. docker exec -d keeps the timer
  # alive after the exec session ends.
  secs=$(((hold + 15) * 60))
  for r in "${rules[@]}"; do
    read -r tool chain spec <<<"$r"
    docker exec -d "$node" sh -c "sleep $secs; $tool -C $chain $spec && $tool -D $chain $spec" \
      || cut_failed "could not arm a removal timer in $node"
  done
  for r in "${rules[@]}"; do
    read -r tool chain spec <<<"$r"
    # shellcheck disable=SC2086 # the spec is a list of words
    docker exec "$node" "$tool" -I "$chain" 1 $spec || cut_failed "could not insert the rule '$r' in $node"
  done
  until="$(jq -nr --argjson t "$((now + hold * 60))" '$t | todate')"
  jq -nc --arg tag "$tag" --arg node "$node" --arg direction "$direction" --arg until "$until" \
    --argjson v6 "$([[ -n "$v6" ]] && echo true || echo false)" --args \
    '{tag: $tag, node: $node, peers: $ARGS.positional, direction: $direction, ipv6: $v6, until: $until}
     + (if $v6 then {} else {note: "the peer has no IPv6 address, so the rules cover IPv4 only"} end)' "${peers[@]}"
}

cmd_heal() {
  local tag="" all=0
  while (($#)); do
    case "$1" in
      --tag) tag="${2:-}"; shift 2 ;;
      --all) all=1; shift ;;
      *) usage ;;
    esac
  done
  if ((all)); then
    [[ -z "$tag" ]] || usage
    heal_nodes
  else
    [[ -n "$tag" ]] || usage
    check_tag "$tag"
    heal_nodes "$tag"
  fi
}

cmd_list() {
  local node rules rule parts tag
  (($# == 0)) || usage
  for node in $(nodes); do
    rules="$(partition_rules "$node")" || die "the node $node does not answer, so its rules are unchecked"
    while IFS= read -r rule; do
      [[ -n "$rule" ]] || continue
      read -r -a parts <<<"$rule"
      tag=""
      [[ "$rule" =~ (${PREFIX}[0-9a-f]{8}) ]] && tag="${BASH_REMATCH[1]}"
      jq -nc --arg node "$node" --arg tool "${parts[0]}" --arg chain "${parts[2]}" --arg tag "$tag" --arg rule "$rule" \
        '{node: $node, tool: $tool, chain: $chain, tag: $tag, rule: $rule}'
    done <<<"$rules"
  done
}

sub="${1:-}"
(($#)) && shift
case "$sub" in
  cut) cmd_cut "$@" ;;
  heal) cmd_heal "$@" ;;
  list) cmd_list "$@" ;;
  *) usage ;;
esac
