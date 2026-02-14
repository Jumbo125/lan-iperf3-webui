#!/usr/bin/env bash
set -euo pipefail

# ------------------------------------------------------------
# ip_setup.sh - Linux/Bash Port (IPv4 only)
# - Adapter wählen (Pflicht beim Menüstart)
# - Backup JSON + Restore (via portable python)
# - DHCP
# - Static PC A / PC B
# - UFW Regeln (iperf TCP/UDP 5201 + ICMP Echo via before.rules Block)
# - Start PC A/B via FIX vorhandene Scripts:
#     Start_PC_A_Linux.sh / Start_PC_B_Linux.sh  (neues Terminal wenn möglich)
#
# Fixes:
# - run_safe: Menü bricht nicht mehr durch set -e ab
# - set_static/set_dhcp: nmcli Fehler -> Fallback statt Exit
# - Warnung bei SSH (IP-Änderung kann Verbindung trennen)
#
# Änderung (dein Wunsch):
# - KEIN Erstellen von Start-Scripts mehr (die existieren fix)
# ------------------------------------------------------------

# ---------------------------
# DEFAULTS
# ---------------------------
IPERF_PORT=5201

IP_PC_A="192.168.10.1"
IP_PC_B="192.168.10.2"
PREFIXLEN=24

FW_IPS=("$IP_PC_A" "$IP_PC_B")

# UFW ICMP Block Marker
UFW_BEFORE_RULES="/etc/ufw/before.rules"
UFW_ICMP_BEGIN="# LAN_TOOL_BEGIN"
UFW_ICMP_END="# LAN_TOOL_END"

# ---------------------------
# PATHS
# ---------------------------
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

START_PC_A="$SCRIPT_DIR/Setup_IP/Start_PC_A_Linux.sh"
START_PC_B="$SCRIPT_DIR/Setup_IP/Start_PC_B_Linux.sh"

# ------------------------------------------------------------
# 1) Portable Python chmod fix (wie gewünscht)
# ------------------------------------------------------------
(
  cd "$SCRIPT_DIR" || exit 0
  chmod +x PORTABLE_linux_amd/python/bin/python3 2>/dev/null || true
  chmod +x PORTABLE_linux_aarch64/python/bin/python3 2>/dev/null || true
  chmod +x PORTABLE_linux_amd/python/bin/python 2>/dev/null || true
  chmod +x PORTABLE_linux_aarch64/python/bin/python 2>/dev/null || true

  # Optional: falls Ordner eine Ebene höher liegen:
  chmod +x ../PORTABLE_linux_amd/python/bin/python3 2>/dev/null || true
  chmod +x ../PORTABLE_linux_aarch64/python/bin/python3 2>/dev/null || true
  chmod +x ../PORTABLE_linux_amd/python/bin/python 2>/dev/null || true
  chmod +x ../PORTABLE_linux_aarch64/python/bin/python 2>/dev/null || true

  # Start-Scripts existieren fix -> nur executable-bit setzen (kein Erstellen!)
  chmod +x "$START_PC_A" 2>/dev/null || true
  chmod +x "$START_PC_B" 2>/dev/null || true
) >/dev/null 2>&1 || true

# ---------------------------
# ARG PARSING
# ---------------------------
ACTION="${1:-menu}"
shift || true

INTERFACE_ALIAS=""
NO_RESTART=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    -i|--iface)
      INTERFACE_ALIAS="${2:-}"
      shift 2
      ;;
    --no-restart)
      NO_RESTART=1
      shift
      ;;
    menu|pcA|pcB|backup|restore|dhcp|fw|fw-remove)
      ACTION="$1"
      shift
      ;;
    *)
      echo "[WARN] Unbekanntes Argument: $1"
      shift
      ;;
  esac
done

# ---------------------------
# ADMIN CHECK
# ---------------------------
if [[ "$(id -u)" -ne 0 ]]; then
  echo "Administratorrechte erforderlich! Bitte mit sudo starten."
  exit 1
fi

# ---------------------------
# HELPERS
# ---------------------------
have_cmd() { command -v "$1" >/dev/null 2>&1; }

pause() {
  read -r -p "Weiter mit Enter..." _
}

# Damit set -e das Menü nicht beendet, wenn z.B. nmcli/ dhclient/ ip einen Fehler liefert
run_safe() {
  set +e
  "$@"
  local rc=$?
  set -e
  if [[ $rc -ne 0 ]]; then
    echo "[FEHLER] Aktion fehlgeschlagen (rc=$rc): $*"
  fi
  return 0
}

backup_path() {
  local iface="$1"
  local safe="${iface// /_}"
  echo "$SCRIPT_DIR/lan_backup_${safe}.json"
}

list_adapters() {
  ip -o link show | awk -F': ' '{print $2}' | awk '{print $1}' | grep -v '^lo$' || true
}

adapter_state() {
  local iface="$1"
  ip -br link show dev "$iface" 2>/dev/null | awk '{print $2}' || echo "UNKNOWN"
}

resolve_iface_noninteractive() {
  local candidate="$1"

  if [[ -n "${candidate}" ]]; then
    if ip link show dev "$candidate" >/dev/null 2>&1; then
      echo "$candidate"
      return
    fi
  fi

  if [[ -n "${LAN_TOOL_IFACE:-}" ]] && ip link show dev "${LAN_TOOL_IFACE}" >/dev/null 2>&1; then
    echo "${LAN_TOOL_IFACE}"
    return
  fi

  local up_iface
  up_iface="$(ip -br link show | awk '$1!="lo" && $2=="UP"{print $1; exit}')"
  if [[ -n "${up_iface}" ]]; then
    echo "${up_iface}"
    return
  fi

  local first
  first="$(list_adapters | head -n1 || true)"
  if [[ -n "${first}" ]]; then
    echo "${first}"
    return
  fi

  echo ""
  return 1
}

select_adapter_interactive() {
  local current="${1:-}"
  while true; do
    clear
    echo "============================================================"
    echo "  Adapter wählen"
    echo "============================================================"
    echo

    mapfile -t ifaces < <(list_adapters)
    if [[ "${#ifaces[@]}" -eq 0 ]]; then
      echo "Keine Netzwerkadapter gefunden."
      pause
      return 1
    fi

    local def_idx=0
    if [[ -n "$current" ]]; then
      for i in "${!ifaces[@]}"; do
        if [[ "${ifaces[$i]}" == "$current" ]]; then
          def_idx="$i"
          break
        fi
      done
    fi

    for i in "${!ifaces[@]}"; do
      local mark=" "
      [[ "$i" -eq "$def_idx" ]] && mark="*"
      local st
      st="$(adapter_state "${ifaces[$i]}")"
      printf " %s%2d) %-20s [%s]\n" "$mark" "$((i+1))" "${ifaces[$i]}" "$st"
    done

    echo
    read -r -p "Nummer wählen (1..${#ifaces[@]}): " sel
    if [[ "$sel" =~ ^[0-9]+$ ]] && (( sel>=1 && sel<=${#ifaces[@]} )); then
      echo "${ifaces[$((sel-1))]}"
      return 0
    fi

    echo
    echo "[FEHLER] Ungültige Nummer."
    pause
  done
}

restart_iface_safe() {
  local iface="$1"
  [[ "$NO_RESTART" -eq 1 ]] && return 0

  if have_cmd nmcli; then
    local con
    con="$(nmcli -t -f DEVICE,CONNECTION dev status | awk -F: -v d="$iface" '$1==d{print $2; exit}')"
    if [[ -n "$con" && "$con" != "--" ]]; then
      nmcli con down "$con" >/dev/null 2>&1 || true
      nmcli con up "$con"   >/dev/null 2>&1 || true
      sleep 1
      return 0
    fi
  fi

  ip link set dev "$iface" down >/dev/null 2>&1 || true
  ip link set dev "$iface" up   >/dev/null 2>&1 || true
  sleep 1
}

nmcli_con_for_iface() {
  local iface="$1"
  have_cmd nmcli || return 1
  local con
  con="$(nmcli -t -f DEVICE,CONNECTION dev status | awk -F: -v d="$iface" '$1==d{print $2; exit}')"
  [[ -n "$con" && "$con" != "--" ]] || return 1
  echo "$con"
}

get_ipv4_cidr() {
  local iface="$1"
  ip -4 -o addr show dev "$iface" scope global 2>/dev/null | awk '{print $4}' | head -n1 || true
}

get_gateway() {
  local iface="$1"
  ip -4 route show dev "$iface" default 2>/dev/null | awk '/default/ {print $3; exit}' || true
}

get_dns_csv() {
  local iface="$1"

  if have_cmd nmcli; then
    local con
    con="$(nmcli_con_for_iface "$iface" 2>/dev/null || true)"
    if [[ -n "$con" ]]; then
      local dns
      dns="$(nmcli -g ipv4.dns con show "$con" 2>/dev/null || true)"
      dns="${dns//;/,}"
      dns="${dns//$'\n'/,}"
      dns="${dns%,}"
      [[ -n "$dns" ]] && { echo "$dns"; return 0; }
    fi
  fi

  if have_cmd resolvectl; then
    local line
    line="$(resolvectl dns "$iface" 2>/dev/null | sed -n 's/.*DNS Servers:\s*//p' | head -n1 || true)"
    if [[ -n "$line" ]]; then
      echo "$line" | tr ' ' ',' | sed 's/,,*/,/g; s/^,//; s/,$//'
      return 0
    fi
  fi

  if [[ -r /etc/resolv.conf ]]; then
    awk '/^nameserver[ \t]+/ {print $2}' /etc/resolv.conf | paste -sd, - || true
    return 0
  fi

  echo ""
}

is_dhcp_enabled_guess() {
  local iface="$1"

  if have_cmd nmcli; then
    local con
    con="$(nmcli_con_for_iface "$iface" 2>/dev/null || true)"
    if [[ -n "$con" ]]; then
      local method
      method="$(nmcli -g ipv4.method con show "$con" 2>/dev/null || true)"
      [[ "$method" == "auto" ]] && { echo "true"; return 0; }
      [[ "$method" == "manual" ]] && { echo "false"; return 0; }
    fi
  fi

  if ip -4 -o addr show dev "$iface" 2>/dev/null | grep -qw dynamic; then
    echo "true"
  else
    echo "false"
  fi
}

# ---------------------------
# PORTABLE PYTHON RESOLVER
# ---------------------------
resolve_python_bin() {
  local here="$SCRIPT_DIR"
  local up
  up="$(cd -- "$SCRIPT_DIR/.." && pwd)"

  local candidates=()

  case "$(uname -m)" in
    aarch64|arm64)
      candidates+=(
        "$here/PORTABLE_linux_aarch64/python/bin/python3"
        "$here/PORTABLE_linux_aarch64/python/bin/python"
        "$up/PORTABLE_linux_aarch64/python/bin/python3"
        "$up/PORTABLE_linux_aarch64/python/bin/python"
      )
      ;;
    x86_64|amd64)
      candidates+=(
        "$here/PORTABLE_linux_amd/python/bin/python3"
        "$here/PORTABLE_linux_amd/python/bin/python"
        "$up/PORTABLE_linux_amd/python/bin/python3"
        "$up/PORTABLE_linux_amd/python/bin/python"
      )
      ;;
    *)
      candidates+=(
        "$here/PORTABLE_linux_amd/python/bin/python3"
        "$here/PORTABLE_linux_amd/python/bin/python"
        "$here/PORTABLE_linux_aarch64/python/bin/python3"
        "$here/PORTABLE_linux_aarch64/python/bin/python"
        "$up/PORTABLE_linux_amd/python/bin/python3"
        "$up/PORTABLE_linux_amd/python/bin/python"
        "$up/PORTABLE_linux_aarch64/python/bin/python3"
        "$up/PORTABLE_linux_aarch64/python/bin/python"
      )
      ;;
  esac

  for p in "${candidates[@]}"; do
    if [[ -x "$p" ]]; then
      echo "$p"
      return 0
    fi
  done

  if command -v python3 >/dev/null 2>&1; then
    command -v python3
    return 0
  fi

  echo ""
  return 1
}

PYTHON_BIN="$(resolve_python_bin || true)"

# ---------------------------
# BACKUP / RESTORE (JSON via portable python)
# ---------------------------
backup_config() {
  local iface="$1"
  local path
  path="$(backup_path "$iface")"

  local dhcp ip prefix gw dns
  dhcp="$(is_dhcp_enabled_guess "$iface")"
  local cidr
  cidr="$(get_ipv4_cidr "$iface")"
  if [[ -n "$cidr" ]]; then
    ip="${cidr%/*}"
    prefix="${cidr#*/}"
  else
    ip=""
    prefix=""
  fi
  gw="$(get_gateway "$iface")"
  dns="$(get_dns_csv "$iface")"

  if [[ -z "${PYTHON_BIN:-}" ]]; then
    echo "[FEHLER] python3 fehlt – weder portable noch systemweit gefunden."
    echo "Erwartet z.B.:"
    echo "  PORTABLE_linux_amd/python/bin/python3"
    echo "  PORTABLE_linux_aarch64/python/bin/python3"
    return 1
  fi

  "$PYTHON_BIN" - "$path" "$iface" "$dhcp" "$ip" "$prefix" "$gw" "$dns" <<'PY'
import json, sys, datetime

path, iface, dhcp, ip, prefix, gw, dns = sys.argv[1:]
obj = {
  "Date": datetime.datetime.now(datetime.timezone.utc).astimezone().isoformat(timespec="seconds"),
  "Interface": iface,
  "DHCP": True if str(dhcp).lower()=="true" else False,
  "IP": ip or None,
  "Prefix": int(prefix) if str(prefix).isdigit() else None,
  "Gateway": gw or None,
  "DNS": [x for x in (dns.split(",") if dns else []) if x]
}
with open(path, "w", encoding="utf-8") as f:
  json.dump(obj, f, indent=2, ensure_ascii=False)
print(path)
PY

  echo "[OK] Backup gespeichert: $path"
}

read_backup_fields() {
  local path="$1"

  if [[ -z "${PYTHON_BIN:-}" ]]; then
    echo "[FEHLER] python3 fehlt – weder portable noch systemweit gefunden."
    return 1
  fi

  "$PYTHON_BIN" - "$path" <<'PY'
import json, sys
p=sys.argv[1]
with open(p,"r",encoding="utf-8") as f:
  d=json.load(f)

def out(k, v):
  if v is None:
    v=""
  print(f"{k}={v}")

out("DHCP", str(bool(d.get("DHCP"))).lower())
out("IP", d.get("IP"))
out("PREFIX", d.get("Prefix"))
PY
}

restore_config() {
  local iface="$1"
  local path
  path="$(backup_path "$iface")"

  if [[ ! -f "$path" ]]; then
    echo "[FEHLER] Kein Backup gefunden: $path"
    return 1
  fi

  local DHCP IP PREFIX
  # shellcheck disable=SC1090
  source <(read_backup_fields "$path")

  if [[ "${DHCP:-false}" == "true" ]]; then
    set_dhcp "$iface"
  else
    if [[ -z "${IP:-}" || -z "${PREFIX:-}" ]]; then
      echo "[FEHLER] Backup enthält keine statische IP/Prefix."
      return 1
    fi
    set_static "$iface" "$IP" "$PREFIX"
  fi

  echo "[OK] Restore abgeschlossen."
}

# ---------------------------
# DHCP / STATIC (robust: nmcli fail => fallback)
# ---------------------------
set_dhcp() {
  local iface="$1"

  if [[ -n "${SSH_CONNECTION:-}" ]]; then
    echo "[WARN] Du bist per SSH verbunden. IP-Änderungen können die Verbindung trennen."
  fi

  if have_cmd nmcli; then
    local con
    con="$(nmcli_con_for_iface "$iface" 2>/dev/null || true)"
    if [[ -n "$con" ]]; then
      if nmcli con mod "$con" ipv4.method auto ipv4.addresses "" ipv4.gateway "" ipv4.dns "" ipv4.ignore-auto-dns no >/dev/null 2>&1; then
        restart_iface_safe "$iface"
        echo "[OK] DHCP aktiviert (nmcli)."
        return 0
      else
        echo "[WARN] nmcli konnte DHCP nicht setzen – Fallback auf dhclient/ip."
      fi
    fi
  fi

  ip -4 addr flush dev "$iface" >/dev/null 2>&1 || true
  ip link set dev "$iface" up >/dev/null 2>&1 || true

  if have_cmd dhclient; then
    dhclient -r "$iface" >/dev/null 2>&1 || true
    dhclient "$iface"   >/dev/null 2>&1 || true
    echo "[OK] DHCP aktiviert (dhclient)."
    return 0
  fi

  echo "[WARN] dhclient nicht gefunden – DHCP konnte evtl. nicht gestartet werden."
  return 1
}

set_static() {
  local iface="$1"
  local ip="$2"
  local prefix="$3"

  if [[ -n "${SSH_CONNECTION:-}" ]]; then
    echo "[WARN] Du bist per SSH verbunden. IP-Änderungen können die Verbindung trennen."
  fi

  if have_cmd nmcli; then
    local con
    con="$(nmcli_con_for_iface "$iface" 2>/dev/null || true)"
    if [[ -n "$con" ]]; then
      if nmcli con mod "$con" ipv4.method manual ipv4.addresses "${ip}/${prefix}" ipv4.gateway "" ipv4.dns "" ipv4.ignore-auto-dns yes >/dev/null 2>&1; then
        restart_iface_safe "$iface"
        echo "[OK] Static IP gesetzt (nmcli): ${ip}/${prefix}"
        return 0
      else
        echo "[WARN] nmcli konnte Static nicht setzen – Fallback auf ip."
      fi
    fi
  fi

  if have_cmd dhclient; then
    dhclient -r "$iface" >/dev/null 2>&1 || true
  fi

  ip -4 addr flush dev "$iface" >/dev/null 2>&1 || true
  ip -4 addr add "${ip}/${prefix}" dev "$iface"
  ip link set dev "$iface" up >/dev/null 2>&1 || true

  echo "[OK] Static IP gesetzt (ip): ${ip}/${prefix}"
  return 0
}

# ---------------------------
# UFW FIREWALL
# ---------------------------
ufw_missing_msg() { echo "ufw nicht installiert."; }

ufw_is_active() {
  have_cmd ufw || return 1
  ufw status 2>/dev/null | head -n1 | grep -qi "Status: active"
}

write_ufw_icmp_block() {
  local iface="$1" # iface currently unused (kept for symmetry)

  if [[ ! -f "$UFW_BEFORE_RULES" ]]; then
    echo "[FEHLER] $UFW_BEFORE_RULES nicht gefunden."
    return 1
  fi

  if [[ ! -f "${UFW_BEFORE_RULES}.lan_tool.bak" ]]; then
    cp -a "$UFW_BEFORE_RULES" "${UFW_BEFORE_RULES}.lan_tool.bak"
  fi

  local block=""
  block+="${UFW_ICMP_BEGIN}"$'\n'
  block+="# Allow ICMP echo-request (ping) from specific hosts (IPv4)"$'\n'
  for ip in "${FW_IPS[@]}"; do
    block+="-A ufw-before-input -p icmp --icmp-type echo-request -s ${ip} -j ACCEPT"$'\n'
  done
  block+="${UFW_ICMP_END}"$'\n'

  local tmp
  tmp="$(mktemp)"

  awk -v begin="$UFW_ICMP_BEGIN" -v end="$UFW_ICMP_END" -v block="$block" '
    BEGIN {inblk=0; inserted=0}
    $0==begin {inblk=1; next}
    inblk && $0==end {inblk=0; next}
    inblk {next}
    {
      print
      if (!inserted && $0 ~ /^\*filter/) {
        print block
        inserted=1
      }
    }
  ' "$UFW_BEFORE_RULES" > "$tmp"

  cp -a "$tmp" "$UFW_BEFORE_RULES"
  rm -f "$tmp"
}

remove_ufw_icmp_block() {
  [[ -f "$UFW_BEFORE_RULES" ]] || return 0

  local tmp
  tmp="$(mktemp)"

  awk -v begin="$UFW_ICMP_BEGIN" -v end="$UFW_ICMP_END" '
    BEGIN {inblk=0}
    $0==begin {inblk=1; next}
    inblk && $0==end {inblk=0; next}
    inblk {next}
    {print}
  ' "$UFW_BEFORE_RULES" > "$tmp"

  cp -a "$tmp" "$UFW_BEFORE_RULES"
  rm -f "$tmp"
}

set_firewall_ufw() {
  local iface="$1"
  if ! have_cmd ufw; then
    ufw_missing_msg
    return 0
  fi

  write_ufw_icmp_block "$iface"

  for ip in "${FW_IPS[@]}"; do
    ufw allow in on "$iface" from "$ip" to any port "$IPERF_PORT" proto tcp >/dev/null || true
    ufw allow in on "$iface" from "$ip" to any port "$IPERF_PORT" proto udp >/dev/null || true
  done

  if ufw_is_active; then
    ufw reload >/dev/null || true
    echo "[OK] UFW Regeln gesetzt + UFW reload."
  else
    echo "[OK] UFW Regeln gesetzt. (UFW ist derzeit nicht aktiv – ggf. 'ufw enable' ausführen.)"
  fi
}

remove_firewall_ufw() {
  local iface="$1"
  if ! have_cmd ufw; then
    ufw_missing_msg
    return 0
  fi

  remove_ufw_icmp_block

  for ip in "${FW_IPS[@]}"; do
    yes | ufw delete allow in on "$iface" from "$ip" to any port "$IPERF_PORT" proto tcp >/dev/null 2>&1 || true
    yes | ufw delete allow in on "$iface" from "$ip" to any port "$IPERF_PORT" proto udp >/dev/null 2>&1 || true
  done

  if ufw_is_active; then
    ufw reload >/dev/null || true
    echo "[OK] UFW Regeln gelöscht + UFW reload."
  else
    echo "[OK] UFW Regeln gelöscht."
  fi
}

# ---------------------------
# START IN NEW TERMINAL
# ---------------------------
start_in_new_terminal() {
  local script="$1"
  shift || true

  if [[ ! -x "$script" ]]; then
    echo "[FEHLER] Script nicht gefunden/ausführbar: $script"
    return 1
  fi

  # sichere Argument-Quote für "bash -c"
  local cmd
  cmd="$(printf '%q ' "$script" "$@")"
  cmd="${cmd% }"

  if have_cmd gnome-terminal; then
    gnome-terminal -- bash -lc "$cmd; echo; read -r -p 'Enter zum Schließen...' _"
  elif have_cmd konsole; then
    konsole -e bash -lc "$cmd; echo; read -r -p 'Enter zum Schließen...' _"
  elif have_cmd xfce4-terminal; then
    xfce4-terminal -e "bash -lc '$cmd; echo; read -r -p \"Enter zum Schließen...\" _'"
  elif have_cmd mate-terminal; then
    mate-terminal -- bash -lc "$cmd; echo; read -r -p 'Enter zum Schließen...' _"
  elif have_cmd lxterminal; then
    lxterminal -e bash -lc "$cmd; echo; read -r -p 'Enter zum Schließen...' _"
  elif have_cmd xterm; then
    xterm -e bash -lc "$cmd; echo; read -r -p 'Enter zum Schließen...' _"
  else
    # Kein GUI-Terminal gefunden -> im aktuellen Kontext starten
    bash "$script" "$@"
  fi
}

# ---------------------------
# NON-INTERACTIVE ACTIONS
# ---------------------------
if [[ "$ACTION" != "menu" ]]; then
  IFACE="$(resolve_iface_noninteractive "$INTERFACE_ALIAS")"
  if [[ -z "$IFACE" ]]; then
    echo "[FEHLER] Kein geeigneter Netzwerkadapter gefunden."
    exit 1
  fi

  case "$ACTION" in
    pcA)       set_static "$IFACE" "$IP_PC_A" "$PREFIXLEN" ;;
    pcB)       set_static "$IFACE" "$IP_PC_B" "$PREFIXLEN" ;;
    backup)    backup_config "$IFACE" ;;
    restore)   restore_config "$IFACE" ;;
    dhcp)      set_dhcp "$IFACE" ;;
    fw)        set_firewall_ufw "$IFACE" ;;
    fw-remove) remove_firewall_ufw "$IFACE" ;;
    *)         echo "[FEHLER] Unbekannte Aktion: $ACTION"; exit 1 ;;
  esac
  exit 0
fi

# ---------------------------
# MENU - Pflicht-Adapterwahl beim Start
# ---------------------------
IFACE="$(select_adapter_interactive "$(resolve_iface_noninteractive "$INTERFACE_ALIAS" || true)")"
export LAN_TOOL_IFACE="$IFACE"

while true; do
  clear
  echo "LAN TOOL – Linux (Bash)"
  echo "Adapter: $IFACE"
  echo
  echo "1) Backup schreiben (JSON)"
  echo "2) Wiederherstellen (Backup -> DHCP oder Static)"
  echo "3) DHCP aktivieren"
  echo "4) PC A setzen (Static ${IP_PC_A}/${PREFIXLEN})"
  echo "5) PC B setzen (Static ${IP_PC_B}/${PREFIXLEN})"
  echo
  echo "6) UFW Regeln setzen (Ping + iPerf TCP/UDP ${IPERF_PORT})"
  echo "7) UFW Regeln löschen"
  echo
  echo "8) Adapter wechseln"
  echo "9) PC A starten -> neues Terminal (Start_PC_A_Linux.sh)"
  echo "10) PC B starten -> neues Terminal (Start_PC_B_Linux.sh)"
  echo
  echo "0) Exit"
  echo
  read -r -p "Auswahl: " c

  case "$c" in
    1)  run_safe backup_config "$IFACE"; pause ;;
    2)  run_safe restore_config "$IFACE"; pause ;;
    3)  run_safe set_dhcp "$IFACE"; pause ;;
    4)  run_safe set_static "$IFACE" "$IP_PC_A" "$PREFIXLEN"; pause ;;
    5)  run_safe set_static "$IFACE" "$IP_PC_B" "$PREFIXLEN"; pause ;;
    6)  run_safe set_firewall_ufw "$IFACE"; pause ;;
    7)  run_safe remove_firewall_ufw "$IFACE"; pause ;;
    8)
      IFACE="$(select_adapter_interactive "$IFACE")"
      export LAN_TOOL_IFACE="$IFACE"
      ;;
    9)  run_safe start_in_new_terminal "$START_PC_A" ;;
    10) run_safe start_in_new_terminal "$START_PC_B" ;;
    0)  break ;;
    *)  ;;
  esac
done
