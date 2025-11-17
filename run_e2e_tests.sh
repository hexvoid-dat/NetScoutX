#!/bin/bash

# Zakończ skrypt, jeśli którekolwiek polecenie zwróci błąd
set -e

# --- Zmienne Konfiguracyjne ---
DOCKER_COMPOSE_FILE="docker-compose.yml"
SUBNET="172.28.0.0/24"
OUTPUT_FILE="test_results.json"
NET_SCOUT_BINARY="net-scout"

# --- Funkcja do sprzątania ---
cleanup() {
  echo "[INFO] Zatrzymywanie i usuwanie kontenerów testowych..."
  docker compose -f "$DOCKER_COMPOSE_FILE" down
  rm -f "$OUTPUT_FILE"
}

# Ustaw pułapkę, aby funkcja cleanup() została wywołana przy wyjściu ze skryptu
trap cleanup EXIT

# --- Główna Logika Testu ---
echo "[ETAP 1/5] Uruchamianie środowiska testowego Docker..."
docker compose -f "$DOCKER_COMPOSE_FILE" up -d
# Dajmy chwilę kontenerom na pełne uruchomienie usług
sleep 5

echo "[ETAP 2/5] Kompilowanie narzędzia net-scout..."
go build -o "$NET_SCOUT_BINARY" ./cmd/net-scout

echo "[ETAP 3/5] Uruchamianie skanowania w izolowanej sieci..."
# Uruchomienie bez sudo (uproszczona wersja)
./"$NET_SCOUT_BINARY" -subnet="$SUBNET" -output="$OUTPUT_FILE"

echo "[ETAP 4/5] Weryfikacja wyników skanowania..."

# Sprawdzenie 1: Czy znaleziono co najmniej 3 hosty (3 kontenery + brama)?
host_count=$(jq '.hosts | length' "$OUTPUT_FILE")
if [ "$host_count" -lt 3 ]; then
  echo "[FAIL] Oczekiwano co najmniej 3 hostów, znaleziono: $host_count"
  exit 1
fi
echo "[PASS] Znaleziono $host_count hostów."

# Sprawdzenie 2: Czy serwer FTP (172.28.0.10) ma podatność CVE-2011-2523?
ftp_vuln=$(jq -r '.hosts[] | select(.ip == "172.28.0.10") | .open_ports[] | select(.number == 21) | .vulnerabilities[] | select(.cve_id == "CVE-2011-2523") | .cve_id' "$OUTPUT_FILE")
if [ "$ftp_vuln" != "CVE-2011-2523" ]; then
  echo "[FAIL] Nie znaleziono oczekiwanej podatności CVE-2011-2523 na serwerze FTP."
  exit 1
fi
echo "[PASS] Poprawnie zidentyfikowano podatność na serwerze FTP."

# Sprawdzenie 3: Czy serwer SSH (172.28.0.20) ma podatność CVE-2018-15473?
ssh_vuln=$(jq -r '.hosts[] | select(.ip == "172.28.0.20") | .open_ports[] | select(.number == 22) | .vulnerabilities[] | select(.cve_id == "CVE-2018-15473") | .cve_id' "$OUTPUT_FILE")
if [ "$ssh_vuln" != "CVE-2018-15473" ]; then
  echo "[FAIL] Nie znaleziono oczekiwanej podatności CVE-2018-15473 na serwerze SSH."
  exit 1
fi
echo "[PASS] Poprawnie zidentyfikowano podatność na serwerze SSH."

# Sprawdzenie 4: Czy serwer Apache (172.28.0.30) ma podatność CVE-2018-1312?
apache_vuln=$(jq -r '.hosts[] | select(.ip == "172.28.0.30") | .open_ports[] | select(.number == 80) | .vulnerabilities[] | select(.cve_id == "CVE-2018-1312") | .cve_id' "$OUTPUT_FILE")
if [ "$apache_vuln" != "CVE-2018-1312" ]; then
  echo "[FAIL] Nie znaleziono oczekiwanej podatności CVE-2018-1312 na serwerze Apache."
  exit 1
fi
echo "[PASS] Poprawnie zidentyfikowano podatność na serwerze Apache."


echo "[ETAP 5/5] Wszystkie testy E2E zakończone pomyślnie!"
echo "✅ Testy zdane!"
exit 0