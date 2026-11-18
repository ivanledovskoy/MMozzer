#!/bin/bash
# extract_closed_mm.sh - pull StandaloneMM modules (PE32) out of a UEFI image
# with UEFIExtract and prepare them for the integrate stage.
#
#   usage: scripts/extract_closed_mm.sh [image]      (default: <root>/socfw.cap)
#
# Output:
#   closed_mm/modules/<FFS-GUID>.efi   - raw PE32 of each vendor MM module
#   closed_mm/modules.txt              - manifest: ffs_guid,name,file
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"

IMG="${1:-$ROOT/socfw.cap}"
UEFIEXTRACT="$ROOT/uefiextract"
OUT="$ROOT/closed_mm/modules"
MANIFEST="$ROOT/closed_mm/modules.txt"

# Modules our stand already provides / infra we must NOT embed as duplicates.
# (StandaloneMmCpu = root dispatcher; embedding the vendor one would break us.)
EXCLUDE_GUIDS="58F7A62B-6280-42A7-BC38-10535A64A92C"

DUMP="${IMG}.dump"
if [ ! -d "$DUMP" ]; then
  # Need to (re)generate the dump - the image and tool are required only here.
  [ -x "$UEFIEXTRACT" ] || { echo "!! uefiextract not found at $UEFIEXTRACT" >&2; exit 1; }
  [ -f "$IMG" ]        || { echo "!! image not found: $IMG (and no dump at $DUMP)" >&2; exit 1; }
  echo "==> UEFIExtract $IMG all"
  "$UEFIEXTRACT" "$IMG" all >/dev/null
else
  echo "==> reusing existing dump: $DUMP"
fi

mkdir -p "$OUT"
printf '# ffs_guid,name,file\n' > "$MANIFEST"

n=0 skipped=0
while IFS= read -r info; do
  node="$(dirname "$info")"
  guid="$(grep -m1 '^File GUID:' "$info" | awk '{print $NF}')"
  name="$(grep -m1 '^Text:' "$info" | sed 's/^Text: *//')"
  [ -n "$guid" ] || continue
  [ -n "$name" ] || name="$guid"

  case " $EXCLUDE_GUIDS " in
    *" $guid "*) echo "   skip (infra)   : $name  $guid"; skipped=$((skipped+1)); continue;;
  esac

  pe32dir="$(find "$node" -maxdepth 1 -type d -iname '*PE32 image section*' | head -1)"
  if [ -z "$pe32dir" ] || [ ! -f "$pe32dir/body.bin" ]; then
    echo "   no PE32        : $name  $guid"; continue
  fi

  cp "$pe32dir/body.bin" "$OUT/$guid.efi"
  printf '%s,%s,%s.efi\n' "$guid" "$name" "$guid" >> "$MANIFEST"
  echo "   extracted      : $name  $guid"

  # Report the vendor module's ORIGINAL depex that we drop in favour of our TRUE
  # stub (06 08). Integrate rebuilds the FFS with SECTION SMM_DEPEX = closed_mm/
  # closed_mm_true.depex, so whatever dependency the module had is overridden.
  dpxdir="$(find "$node" -maxdepth 1 -type d -iname '*dependency section*' | head -1)"
  if [ -n "$dpxdir" ] && [ -f "$dpxdir/body.bin" ]; then
    orig="$(xxd -p "$dpxdir/body.bin" | tr -d '\n' | sed 's/\(..\)/\1 /g; s/ *$//')"
    parsed="$(sed -n '/^Parsed expression:/,$p' "$dpxdir/info.txt" | tail -n +2 \
              | sed 's/^[[:space:]]*//' | paste -sd';' - | sed 's/;/; /g')"
    echo "     depex deleted: [$orig]  (${parsed:-?})  ->  stub [06 08] (TRUE)"
  else
    echo "     depex deleted: (vendor module had no depex)  ->  stub [06 08] (TRUE)"
  fi
  n=$((n+1))
done < <(grep -rl 'Subtype: MM standalone module' "$DUMP" --include=info.txt | sort)

echo "==> extracted $n module(s), skipped $skipped -> $OUT"
echo "==> manifest: $MANIFEST"
