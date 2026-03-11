#!/usr/bin/env bash
# Clone zkemail.nr and zk-regex at the branches needed for this circuit, so path deps in Nargo.toml resolve.
set -e
cd "$(dirname "$0")"
PARENT="$(pwd)/.."

if [[ ! -d "$PARENT/zkemail.nr" ]]; then
  git clone https://github.com/zkemail/zkemail.nr "$PARENT/zkemail.nr"
fi
git -C "$PARENT/zkemail.nr" fetch origin zkfriendly/sol-230-make-zkemailnr-work-with-beta-11
git -C "$PARENT/zkemail.nr" checkout zkfriendly/sol-230-make-zkemailnr-work-with-beta-11

if [[ ! -d "$PARENT/zk-regex" ]]; then
  git clone https://github.com/zkemail/zk-regex "$PARENT/zk-regex"
fi
git -C "$PARENT/zk-regex" fetch origin zkfriendly/sol-231-make-zk-regex-noir-to-work-with-beta-11
git -C "$PARENT/zk-regex" checkout zkfriendly/sol-231-make-zk-regex-noir-to-work-with-beta-11

echo "Done. You can run nargo compile from $(pwd)."
