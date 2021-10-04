#!/bin/bash
#set -eo pipefail

#usage() {
#    echo Usage:
#    echo "$0 <node-binary>"
#    echo "$1 <chain-id>"
#    exit 1
#}

# This creates and extended weight file that contains:
# * `WeightInfo` trait declaration
# * `WeightInfo` implementation for an `IntegriteeRuntimeWeight` struct
# * `WeightInfo` implementation for `()` used in testing.
#
# The output file is intended to be used in the `pallet_teerex` internally for development only. It contains more
# information than needed for the actual node.

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
PROJ_ROOT="$(dirname "$SCRIPT_DIR")"

# use absolute path for the output file
TEEREX_SRC_DIR="$PROJ_ROOT/src"

echo "SCRIPT_DIR:     ${SCRIPT_DIR}"
echo "PROJ_ROOT:      ${PROJ_ROOT}"
echo "TEEREX_SRC_DIR: ${TEEREX_SRC_DIR}"

NODE_BINARY=${0}
CHAIN_SPEC=${1}

echo "Creating weight definitinos for pallet_teerex"
echo "node:   ${NODE_BINARY}"
echo "chain:  ${CHAIN_SPEC}"

#$NODE_BINARY \
#  benchmark \
#  --chain="$CHAIN_SPEC" \
#  --steps=50 \
#  --repeat=20 \
#  --pallet=pallet_teerex \
#  --extrinsic="*" \
#  --execution=wasm \
#  --wasm-execution=compiled \
#  --heap-pages=4096 \
#  --output="$TEEREX_SRC_DIR/weights.rs" \
#  --template="$SCRIPT_DIR"/frame-weight-template-full-info.hbs
#
