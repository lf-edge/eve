#!/usr/bin/env bash
# Host-side CPU placement report for an EVE node running a pinned workload.
#
#   ./cpu-assignment-report.sh [node-ip] [app-ip]
#
# Everything is parsed on THIS machine. The node is only asked for small file
# reads -- no log scraping, no zcat, no grep -r. That matters: EVE's whole
# control plane is confined to CPU 0, sshd included, so heavy work over ssh
# starves zedbox and the watchdog reboots the node.
#
# Env overrides: NODE_IP APP_IP SSH_KEY GUEST_USER GUEST_PASS NO_COLOR=1
#
# The guest section needs a password for the app's sshd; it is deliberately not
# defaulted here, so it never lands in git:
#
#   GUEST_PASS=<password> ./cpu-assignment-report.sh

set -uo pipefail

NODE_IP="${1:-${NODE_IP:-10.208.13.74}}"
APP_IP_ARG="${2:-${APP_IP:-}}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/ztest_key}"
GUEST_USER="${GUEST_USER:-pocuser}"
GUEST_PASS="${GUEST_PASS:-}"   # no default: do not bake a credential into the repo

SSH_OPTS=(-o ConnectTimeout=10 -o StrictHostKeyChecking=no
          -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o LogLevel=ERROR)

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  B=$(printf '\033[1m'); R=$(printf '\033[0m')
  GRN=$(printf '\033[32m'); RED=$(printf '\033[31m'); YEL=$(printf '\033[33m')
  DIM=$(printf '\033[2m')
else
  B=""; R=""; GRN=""; RED=""; YEL=""; DIM=""
fi

PASS_N=0; FAIL_N=0; WARN_N=0
ok()   { PASS_N=$((PASS_N+1)); printf '  %sPASS%s  %s\n' "$GRN" "$R" "$1"; }
bad()  { FAIL_N=$((FAIL_N+1)); printf '  %sFAIL%s  %s\n' "$RED" "$R" "$1"; }
warn() { WARN_N=$((WARN_N+1)); printf '  %sWARN%s  %s\n' "$YEL" "$R" "$1"; }
hdr()  { printf '\n%s=== %s%s\n' "$B" "$1" "$R"; }

have_jq=0; command -v jq >/dev/null 2>&1 && have_jq=1

# ---------------------------------------------------------------- collect (node)
RAW=$(ssh -i "$SSH_KEY" "${SSH_OPTS[@]}" "root@${NODE_IP}" sh -s <<'REMOTE' 2>/dev/null
echo "@@release";  cat /run/eve-release 2>/dev/null; echo
echo "@@uptime";   uptime 2>/dev/null
echo "@@cmdline";  cat /proc/cmdline 2>/dev/null
echo "@@online";   cat /sys/devices/system/cpu/online 2>/dev/null
echo "@@isolated"; cat /sys/devices/system/cpu/isolated 2>/dev/null
echo "@@smt";      cat /sys/devices/system/cpu/smt/control 2>/dev/null
echo "@@siblings"
for c in /sys/devices/system/cpu/cpu[0-9]*; do
  n=${c##*/cpu}
  echo "$n $(cat $c/topology/core_id 2>/dev/null) $(cat $c/topology/thread_siblings_list 2>/dev/null)"
done
echo "@@pools";    cat /run/domainmgr/CPUPoolStatus/global.json 2>/dev/null; echo
echo "@@evecpuset"; cat /sys/fs/cgroup/cpuset/eve/cpuset.cpus 2>/dev/null; echo
echo "@@appcpusets"
for f in /sys/fs/cgroup/cpuset/eve-user-apps/*/cpuset.cpus; do
  [ -f "$f" ] || continue
  d=${f%/cpuset.cpus}; echo "${d##*/} $(cat $f 2>/dev/null)"
done
echo "@@appips"
for f in /run/zedrouter/AppNetworkStatus/*.json; do
  [ -f "$f" ] || continue
  u=${f##*/}; u=${u%.json}
  ip=$(grep -oE '"Address":"[0-9.]+"' "$f" | head -1 | cut -d'"' -f4)
  echo "$u ${ip:-none}"
done
echo "@@domains"
for f in /run/domainmgr/DomainStatus/*.json; do
  [ -f "$f" ] || continue
  u=${f##*/}; u=${u%.json}
  echo "--- $u"
  cat "$f"
  echo
done
echo "@@userspace"
for d in /proc/[0-9]*; do
  [ -r "$d/status" ] || continue
  [ -s "$d/cmdline" ] || [ -n "$(tr -d '\0' < $d/cmdline 2>/dev/null)" ] || continue
  echo "$(cat $d/comm 2>/dev/null) $(awk '/Cpus_allowed_list/{print $2}' $d/status 2>/dev/null) $(grep -oE 'cpuset:[^ ]*' $d/cgroup 2>/dev/null | head -1)"
done
echo "@@threads"
for d in /run/hypervisor/kvm/*/; do
  [ -f "$d/pid" ] || continue
  dom=${d%/}; dom=${dom##*/}
  p=$(cat "$d/pid" 2>/dev/null)
  echo "--- $dom $p"
  for t in /proc/$p/task/[0-9]*; do
    [ -r "$t/status" ] || continue
    echo "$(basename $t) $(cat $t/comm 2>/dev/null) $(awk '/Cpus_allowed_list/{print $2}' $t/status 2>/dev/null)"
  done
done
echo "@@end"
REMOTE
)

if [ -z "$RAW" ]; then
  printf '%sCannot reach node %s over ssh (key %s).%s\n' "$RED" "$NODE_IP" "$SSH_KEY" "$R"
  exit 1
fi

sect() { awk -v s="@@$1" '$0==s{f=1;next} /^@@/{f=0} f' <<<"$RAW"; }

RELEASE=$(sect release | head -1)
UPTIME=$(sect uptime | head -1)
CMDLINE=$(sect cmdline | head -1)
ONLINE=$(sect isolated >/dev/null; sect online | head -1)
ISOLATED=$(sect isolated | head -1)
SMT=$(sect smt | head -1)
SIBLINGS=$(sect siblings)
POOLS=$(sect pools | head -1)
EVECPUSET=$(sect evecpuset | head -1)
APPCPUSETS=$(sect appcpusets)
APPIPS=$(sect appips)
DOMAINS=$(sect domains)
THREADS=$(sect threads)
USERSPACE=$(sect userspace)

# expand a kernel cpu list ("1-4,9-12") into a sorted space-separated set
expand() {
  local spec="${1:-}" out="" part a b i
  [ -z "$spec" ] && { echo ""; return; }
  local IFS=,
  for part in $spec; do
    case "$part" in
      *-*) a=${part%%-*}; b=${part##*-}
           i=$a; while [ "$i" -le "$b" ]; do out="$out $i"; i=$((i+1)); done ;;
      "")  ;;
      *)   out="$out $part" ;;
    esac
  done
  echo $(printf '%s\n' $out | sort -n -u)
}

in_set() { local n="$1"; shift; for x in "$@"; do [ "$x" = "$n" ] && return 0; done; return 1; }

# core_id for a host cpu, and the sibling set of a host cpu
core_of() { awk -v c="$1" '$1==c{print $2; exit}' <<<"$SIBLINGS"; }
sibs_of() { awk -v c="$1" '$1==c{print $3; exit}' <<<"$SIBLINGS"; }

ISO_SET=$(expand "$ISOLATED")
ONLINE_SET=$(expand "$ONLINE")

# ---------------------------------------------------------------------- node
hdr "NODE  ${NODE_IP}"
printf '  EVE      : %s\n' "${RELEASE:-?}"
printf '  uptime   : %s\n' "${UPTIME:-?}"
printf '  SMT      : %s\n' "${SMT:-?}"
printf '  online   : %s (%s CPUs)\n' "${ONLINE:-?}" "$(wc -w <<<"$ONLINE_SET")"
printf '  isolated : %s\n' "${ISOLATED:-<none>}"
printf '  eve cpuset (EVE services): %s\n' "${EVECPUSET:-?}"
printf '  %skernel knobs:%s\n' "$DIM" "$R"
for k in isolcpus nohz_full rcu_nocbs irqaffinity eve_max_vcpus dom0_max_vcpus ctrd_max_vcpus; do
  v=$(grep -oE "(^| )$k=[^ ]*" <<<"$CMDLINE" | tail -1 | sed 's/^ //')
  printf '    %s\n' "${v:-$k=<unset>}"
done

hdr "HOST TOPOLOGY  (physical core -> logical CPUs)"
for c in $(awk '$2!=""{print $2}' <<<"$SIBLINGS" | sort -n -u); do
  printf '  core %-3s : %s\n' "$c" "$(awk -v k="$c" '$2==k{print $1}' <<<"$SIBLINGS" | sort -n | tr '\n' ' ')"
done

# isolated set sibling-completeness
if [ -n "$ISO_SET" ]; then
  hdr "KERNEL ISOLATION alignment"
  partial=""
  for c in $ISO_SET; do
    for s in $(expand "$(sibs_of "$c")"); do
      in_set "$s" $ISO_SET || partial="$partial $(core_of "$c")"
    done
  done
  partial=$(printf '%s\n' $partial | sort -n -u | tr '\n' ' ')
  if [ -n "${partial// /}" ]; then
    bad "isolcpus is NOT sibling-complete: core(s)${partial% } have only some threads isolated."
    printf '        %sSuch cores are usable by NO workload: withheld from ordinary requests\n' "$DIM"
    printf '        (they touch isolated) yet not fully isolated, so they cannot serve the\n'
    printf '        hard tier either. Add the missing siblings to isolcpus.%s\n' "$R"
  else
    ok "isolcpus is sibling-complete ($(wc -w <<<"$ISO_SET") CPUs = $(( $(wc -w <<<"$ISO_SET") / 2 )) whole cores)"
  fi
fi

# ---------------------------------------------------------------------- pools
hdr "EVE CPU POOLS  (what the controller is told)"
if [ -n "$POOLS" ] && [ "$have_jq" = 1 ]; then
  jq -r '.Pools[] | "  \(["?","housekeeping","dedicated","isolated"][.Kind] // "kind\(.Kind)")
    cpus=\(.CPUs // [] | tostring)
    free=\(.FreeCPUs // [] | tostring)
    threads \(.AllocatedThreads)/\(.TotalThreads) alloc  cores \(.TotalCores) total, \(.FreeWholeCores) free whole"' <<<"$POOLS" \
    | sed 'N;N;N;s/\n\s*/ /g'
else
  printf '  %s\n' "${POOLS:-<no pool report>}"
fi

# ------------------------------------------------------------------- per app
hdr "WORKLOADS"
APP_UUIDS=$(awk '/^--- /{print $2}' <<<"$DOMAINS")
[ -z "$APP_UUIDS" ] && printf '  %s(no DomainStatus -- no workload placed)%s\n' "$YEL" "$R"

for u in $APP_UUIDS; do
  JSON=$(awk -v u="--- $u" '$0==u{f=1;next} /^--- /{f=0} f' <<<"$DOMAINS")
  get() { grep -oE "\"$1\":$2" <<<"$JSON" | head -1 | sed "s/\"$1\"://"; }
  NAME=$(grep -oE '"DisplayName":"[^"]*"' <<<"$JSON" | head -1 | cut -d'"' -f4)
  VCPUS=$(get VCpus '[0-9]*')
  PINNED=$(get CPUsPinned '(true|false)')
  ORDERED=$(get OrderedCPUs '(\[[0-9,]*\]|null)')
  ALLCPUS=$(get CPUs '\[[0-9,]*\]')
  TOPO=$(grep -oE '"VMTopology":\{[^}]*\}' <<<"$JSON" | head -1 | sed 's/"VMTopology"://')
  QUAL=$(get PlacementQuality '[0-9]*')
  POL=$(get Policy '[0-9]*'); FPC=$(get FullPCPUsOnly '(true|false)')
  TPC=$(get ThreadsPerCore '[0-9]*'); TIER=$(get IsolationTier '[0-9]*')
  EMU=$(get EmulatorCPUs '(\[[0-9,]*\]|null)')

  SOCK=$(grep -oE '"Sockets":[0-9]*' <<<"$TOPO" | cut -d: -f2)
  CORES=$(grep -oE '"Cores":[0-9]*' <<<"$TOPO" | cut -d: -f2)
  THR=$(grep -oE '"Threads":[0-9]*' <<<"$TOPO" | cut -d: -f2)

  ORD_SET=$(tr -d '[]' <<<"${ORDERED:-}" | tr ',' ' ')
  case "$QUAL" in 1) QNAME="optimal";; 2) QNAME="needs-repack";; *) QNAME="unspecified";; esac

  printf '\n  %s%s%s  (%s)\n' "$B" "${NAME:-?}" "$R" "$u"
  printf '    vCPUs        : %s\n' "${VCPUS:-?}"
  printf '    pinned       : %s\n' "${PINNED:-?}"
  printf '    host CPUs    : %s\n' "${ORDERED:-null}"
  printf '    all CPUs     : %s   emulator: %s\n' "${ALLCPUS:-?}" "${EMU:-null}"
  printf '    guest topo   : sockets=%s cores=%s threads=%s\n' "${SOCK:-?}" "${CORES:-?}" "${THR:-?}"
  printf '    quality      : %s\n' "$QNAME"
  printf '    %scontroller intent: cpu_policy=%s full_pcpus_only=%s threads_per_core=%s isolation_tier=%s%s\n' \
         "$DIM" "${POL:-0}" "${FPC:-false}" "${TPC:-0}" "${TIER:-0}" "$R"
  if [ "${POL:-0}" = "0" ] && [ "${FPC:-false}" = "false" ] && [ "${TPC:-0}" = "0" ]; then
    printf '    %s-> no policy on the wire: whole-core placement came from the device default%s\n' "$DIM" "$R"
  fi
  [ "${TIER:-0}" = "0" ] && [ -n "$ISO_SET" ] && \
    printf '    %s-> isolation_tier unset: any isolated placement is the node-wide switch%s\n' "$DIM" "$R"

  printf '\n    %sPROOFS%s\n' "$B" "$R"

  # P1 vCPU count
  n_ord=$(wc -w <<<"$ORD_SET")
  if [ "${PINNED:-false}" != "true" ]; then
    warn "not pinned -- shares the housekeeping pool; per-core proofs do not apply"
  else
    [ "$n_ord" = "${VCPUS:-0}" ] \
      && ok "one host CPU per vCPU ($n_ord = $VCPUS)" \
      || bad "vCPU/CPU count mismatch: $n_ord host CPUs for ${VCPUS:-?} vCPUs"

    # P2 guest topology consistency
    want=$(( ${SOCK:-0} * ${CORES:-0} * ${THR:-0} ))
    [ "$want" = "${VCPUS:-0}" ] \
      && ok "guest topology multiplies out to the vCPU count (${SOCK}x${CORES}x${THR} = $VCPUS)" \
      || bad "guest topology ${SOCK}x${CORES}x${THR} = $want but vCPUs = ${VCPUS:-?}"

    # P3 sibling pairing / distinct cores
    if [ "${THR:-1}" = "2" ]; then
      i=0; pair_bad=""; set -- $ORD_SET
      while [ $# -ge 2 ]; do
        a=$1; b=$2; shift 2
        sa=$(expand "$(sibs_of "$a")")
        if in_set "$b" $sa; then :; else pair_bad="$pair_bad ($a,$b)"; fi
        i=$((i+1))
      done
      [ -z "${pair_bad// /}" ] \
        && ok "every vCPU pair sits on the two SMT siblings of one physical core ($i pairs)" \
        || bad "vCPU pair(s) NOT on sibling threads:${pair_bad}"
      # cores are whole and exclusive
      ncore=$(for c in $ORD_SET; do core_of "$c"; done | sort -n -u | wc -l)
      [ "$ncore" = "${CORES:-0}" ] \
        && ok "occupies exactly $ncore physical core(s), matching guest cores=$CORES" \
        || bad "spans $ncore physical cores but guest is told cores=$CORES"
    else
      ncore=$(for c in $ORD_SET; do core_of "$c"; done | sort -n -u | wc -l)
      [ "$ncore" = "$n_ord" ] \
        && ok "one vCPU per distinct physical core ($ncore cores)" \
        || bad "$n_ord vCPUs spread over only $ncore cores (expected one each)"
    fi

    # P4 strict 1:1 pinning from /proc
    DOMTHREADS=$(awk -v u="$u" 'index($0,"--- ")==1 { f=(index($0,u)>0); next } f' <<<"$THREADS")
    single=$(awk '$3 !~ /[,-]/ && $3 != "" {print $3}' <<<"$DOMTHREADS" | sort -n | tr '\n' ' ')
    single_uniq=$(printf '%s\n' $single | sort -n -u | tr '\n' ' ')
    ord_sorted=$(printf '%s\n' $ORD_SET | sort -n | tr '\n' ' ')
    if [ -z "$DOMTHREADS" ]; then
      warn "no qemu thread data (domain not running?) -- cannot prove 1:1 pinning"
    elif [ "$single_uniq" = "$ord_sorted" ]; then
      ok "each vCPU thread is pinned to exactly one host CPU, and the set == host CPUs"
    else
      # allow extra kernel workers that are not qemu vCPU threads
      missing=""
      for c in $ORD_SET; do in_set "$c" $single_uniq || missing="$missing $c"; done
      [ -z "${missing// /}" ] \
        && ok "each host CPU has a single-CPU-affinity thread (plus kernel workers)" \
        || bad "no single-CPU thread found for host CPU(s):${missing}"
    fi

    # P5 exclusivity vs other workloads and EVE
    clash=""
    while read -r nm cs; do
      [ -z "$nm" ] && continue
      case "$nm" in "$u"*) continue;; esac
      for c in $(expand "$cs"); do in_set "$c" $ORD_SET && clash="$clash $nm:$c"; done
    done <<<"$APPCPUSETS"
    [ -z "${clash// /}" ] \
      && ok "no other workload cpuset overlaps these CPUs" \
      || bad "another workload can run here:${clash}"
    eclash=""
    for c in $(expand "$EVECPUSET"); do in_set "$c" $ORD_SET && eclash="$eclash $c"; done
    [ -z "${eclash// /}" ] \
      && ok "EVE's own services (cpuset $EVECPUSET) are disjoint from these CPUs" \
      || bad "EVE services share CPU(s):${eclash}"

    # P7 no unconfined user-space process can reach these CPUs
    intruders=""
    while read -r nm mask cg; do
      [ -z "${nm:-}" ] && continue
      case "${cg:-}" in *eve-user-apps*) continue;; esac
      for c in $(expand "${mask:-}"); do
        if in_set "$c" $ORD_SET; then intruders="$intruders ${nm}(${mask})"; break; fi
      done
    done <<<"$USERSPACE"
    intruders=$(printf '%s\n' $intruders | sort -u | tr '\n' ' ')
    [ -z "${intruders// /}" ] \
      && ok "no user-space process outside this workload may run on these CPUs" \
      || bad "user-space process(es) permitted on these CPUs:${intruders}"

    # P6 isolation
    if [ -n "$ISO_SET" ]; then
      inside=0; outside=0
      for c in $ORD_SET; do in_set "$c" $ISO_SET && inside=$((inside+1)) || outside=$((outside+1)); done
      if [ "$outside" = "0" ]; then
        ok "all $inside CPUs are kernel-isolated (isolcpus) -- hard isolation in force"
      elif [ "$inside" = "0" ]; then
        ok "no CPU is kernel-isolated: soft isolation, isolated pool untouched and reserved"
      else
        bad "straddles the isolated set: $inside isolated + $outside not -- placement is inconsistent"
      fi
    fi
  fi
done

# ------------------------------------------------------------- guest topology
APP_IP="$APP_IP_ARG"
if [ -z "$APP_IP" ]; then
  APP_IP=$(awk '$2!="none"{print $2; exit}' <<<"$APPIPS")
fi

hdr "GUEST VIEW  (${APP_IP:-unknown})"
if [ -z "$APP_IP" ]; then
  printf '  %sno app IP found; pass one as the 2nd argument%s\n' "$YEL" "$R"
elif [ -z "$GUEST_PASS" ]; then
  printf '  %sGUEST_PASS is unset -- skipping the guest view.%s\n' "$YEL" "$R"
  printf '  %sre-run as: GUEST_PASS=<password> %s %s%s\n' "$DIM" "$0" "$NODE_IP" "$R"
elif ! command -v sshpass >/dev/null 2>&1; then
  printf '  %ssshpass not installed; cannot log into the guest%s\n' "$YEL" "$R"
else
  GUEST_OPTS=(-o ConnectTimeout=10 -o StrictHostKeyChecking=no
              -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR
              -o PreferredAuthentications=password -o PubkeyAuthentication=no)
  GRAW=$(sshpass -p "$GUEST_PASS" ssh "${GUEST_OPTS[@]}" \
          "${GUEST_USER}@${APP_IP}" sh -s <<'GUEST' 2>/dev/null
echo "@@lscpu"
lscpu 2>/dev/null | grep -iE "^CPU\(s\):|^Thread\(s\) per core|^Core\(s\) per socket|^Socket\(s\)|^NUMA node\(s\)|^Model name"
echo "@@sibs"
for c in /sys/devices/system/cpu/cpu[0-9]*; do
  n=${c##*/cpu}
  echo "$n $(cat $c/topology/core_id 2>/dev/null) $(cat $c/topology/thread_siblings_list 2>/dev/null)"
done
echo "@@end"
GUEST
)
  if [ -z "$GRAW" ]; then
    printf '  %scannot log into the guest as %s@%s%s\n' "$YEL" "$GUEST_USER" "$APP_IP" "$R"
  else
    gsect() { awk -v s="@@$1" '$0==s{f=1;next} /^@@/{f=0} f' <<<"$GRAW"; }
    gsect lscpu | sed 's/^/  /'
    GSIBS=$(gsect sibs)
    printf '\n  guest core -> guest CPUs:\n'
    awk '{ if ($2!="") p[$2]=p[$2]" "$1 } END { for (c in p) printf "    core %-3s :%s\n", c, p[c] }' <<<"$GSIBS" | sort -k2 -n

    # cross-map: guest sibling pair -> host CPUs -> host core
    printf '\n  %sguest pair -> host CPUs -> host core%s\n' "$B" "$R"
    FIRST_UUID=$(awk 'NR==1{print $2}' <<<"$(awk "/^--- /" <<<"$DOMAINS")")
    JSON=$(awk -v u="--- $FIRST_UUID" '$0==u{f=1;next} /^--- /{f=0} f' <<<"$DOMAINS")
    ORDERED=$(grep -oE '"OrderedCPUs":(\[[0-9,]*\]|null)' <<<"$JSON" | head -1 | sed 's/"OrderedCPUs"://')
    ORD_SET=$(tr -d '[]' <<<"$ORDERED" | tr ',' ' ')
    set -- $ORD_SET
    gmismatch=""
    for gc in $(awk '{print $2}' <<<"$GSIBS" | sort -n -u); do
      gcpus=$(awk -v c="$gc" '$2==c{printf "%s ", $1}' <<<"$GSIBS")
      hcpus=""; hcores=""
      for g in $gcpus; do
        # guest cpu index N maps to OrderedCPUs[N]
        h=$(awk -v i="$g" '{ for(j=1;j<=NF;j++) if (j-1==i) print $j }' <<<"$ORD_SET")
        hcpus="$hcpus $h"; hcores="$hcores $(core_of "$h")"
      done
      uniqcore=$(printf '%s\n' $hcores | sort -n -u | tr '\n' ' ')
      nuc=$(wc -w <<<"$uniqcore")
      if [ "$nuc" = "1" ]; then
        printf '    guest core %-3s cpus[%s ] -> host[%s ] -> host core %s %sOK%s\n' \
               "$gc" "$(tr -s ' ' <<<"$gcpus")" "$(tr -s ' ' <<<"$hcpus")" "${uniqcore% }" "$GRN" "$R"
      else
        printf '    guest core %-3s cpus[%s ] -> host[%s ] -> host cores %s %sMISMATCH%s\n' \
               "$gc" "$(tr -s ' ' <<<"$gcpus")" "$(tr -s ' ' <<<"$hcpus")" "$uniqcore" "$RED" "$R"
        gmismatch="yes"
      fi
    done
    printf '\n'
    [ -z "$gmismatch" ] \
      && ok "every core the GUEST believes it has is one real physical host core" \
      || bad "guest core(s) span more than one host core -- guest SMT topology is a lie"
  fi
fi

hdr "SUMMARY"
printf '  %s%d passed%s, %s%d failed%s, %s%d warnings%s\n' \
       "$GRN" "$PASS_N" "$R" "$RED" "$FAIL_N" "$R" "$YEL" "$WARN_N" "$R"
[ "$FAIL_N" -gt 0 ] && exit 1
exit 0
