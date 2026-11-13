# Address checks for render scripts. Source this file.

# ipv4_list <variable> prints the IPv4 addresses in the named variable, one for each line. It fails
# with the reason on standard error when the variable holds no address, or a value that is not an
# IPv4 address. A render then stops, so no NetworkPolicy rule gets an empty peer list, which would
# admit every peer.
ipv4_list() {
  local name="$1" ip ips=()
  read -r -a ips <<<"${!name:-}"
  if ((${#ips[@]} == 0)); then
    printf 'error: %s holds no address\n' "$name" >&2
    return 1
  fi
  for ip in "${ips[@]}"; do
    if [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
      printf "error: %s '%s' holds an address that is not IPv4: %s\n" "$name" "${!name}" "$ip" >&2
      return 1
    fi
  done
  printf '%s\n' "${ips[@]}"
}
