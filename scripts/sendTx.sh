#!/usr/bin/env bash
set -euo pipefail

# --- Chain config (genesis 기반) ---
CHAIN_ID="babylon-dev-1"
NODE="tcp://localhost:26657"
DENOM="ubbn"

# testnet --v 1 기본 경로/키링
HOME_DIR="${HOME_DIR:-./.babylond/node0/babylond}"
KEYRING="${KEYRING:-test}"

# 기본 송신 키는 genesis에서 자금이 있는 node0
FROM_NAME="${FROM_NAME:-node0}"

# Usage: ./scripts/sendTx.sh <to_addr> [amount] [fees]
if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <to_addr> [amount(default: 100000${DENOM})] [fees(default: 2000${DENOM})]"
  exit 1
fi

TO_ADDR="$1"
AMOUNT="${2:-100000${DENOM}}"
FEES="${3:-2000${DENOM}}"

# --- 준비 체크 ---
if ! ./build/babylond keys show "${FROM_NAME}" --home "${HOME_DIR}" --keyring-backend "${KEYRING}" >/dev/null 2>&1; then
  echo "ERROR: key '${FROM_NAME}' not found in --home ${HOME_DIR} --keyring-backend ${KEYRING}"
  echo "       Keys available:"
  ./build/babylond keys list --home "${HOME_DIR}" --keyring-backend "${KEYRING}" || true
  exit 1
fi

FROM_ADDR="$(./build/babylond keys show "${FROM_NAME}" --home "${HOME_DIR}" --keyring-backend "${KEYRING}" --address)"
echo "FROM: ${FROM_NAME} (${FROM_ADDR})"
echo "TO  : ${TO_ADDR}"
echo "AMT : ${AMOUNT} (fees: ${FEES})"
echo "NODE: ${NODE} | CHAIN_ID: ${CHAIN_ID}"
echo

# --- 사전 잔액 조회(선택) ---
echo "[Before] From balance:"
./build/babylond q bank balances "${FROM_ADDR}" --node "${NODE}" || true
echo

# --- 전송 ---
./build/babylond tx bank send "${FROM_NAME}" "${TO_ADDR}" "${AMOUNT}" \
  --home "${HOME_DIR}" \
  --keyring-backend "${KEYRING}" \
  --chain-id "${CHAIN_ID}" \
  --node "${NODE}" \
  --gas auto --gas-adjustment 1.3 \
  --fees "${FEES}" \
  -y --broadcast-mode sync

echo
echo "[After] From balance:"
./build/babylond q bank balances "${FROM_ADDR}" --node "${NODE}" || true
echo "[After] To balance:"
./build/babylond q bank balances "${TO_ADDR}" --node "${NODE}" || true
