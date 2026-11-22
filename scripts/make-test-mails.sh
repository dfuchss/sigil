#!/usr/bin/env bash
# Generates .eml fixtures for manually testing Sigil's receiving side in Mail (output: TestMails/, not committed).
#
# The messages are signed by THROWAWAY keys made in temporary GnuPG homes, which are deleted at the end. The
# encrypted ones are encrypted to the owner's real PUBLIC key: it is exported read-only from the real keyring
# (gpg --export) and imported into the temporary home only. Nothing is ever written to the real keyring, and the
# owner's secret key is never used.
#
# Usage: scripts/make-test-mails.sh [owner-fingerprint]
#   Without a fingerprint, the first usable secret key that can encrypt and has an email user ID is chosen
#   (only its public key is exported). Set OWNER_EMAIL to pick the key by address instead.
set -euo pipefail

GPG=${GPG:-$(command -v gpg)}
GPGCONF=${GPGCONF:-$(dirname "$GPG")/gpgconf}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT="$ROOT/TestMails"
OWNER_EMAIL=${OWNER_EMAIL:-}
SENDER_UID='Sigil Test Sender <sigil-test-sender@example.invalid>'
SENDER_EMAIL='sigil-test-sender@example.invalid'
STRANGER_UID='Unknown Signer <unknown-signer@example.invalid>'
STRANGER_EMAIL='unknown-signer@example.invalid'

# --- owner's public key (read-only access to the real keyring) ---------------------------------------------------
OWNER_FPR=${1:-}
if [ -z "$OWNER_FPR" ]; then
  # sec record (field 2 validity, 12 capabilities), then fpr, then uid lines.
  # sec record (field 2 validity, 12 capabilities), then fpr, then uid lines. With OWNER_EMAIL set, only a user ID
  # with that address counts; otherwise any user ID with an email address.
  OWNER_FPR=$("$GPG" --batch --with-colons --list-secret-keys 2>/dev/null | awk -F: -v want="$(printf '%s' "$OWNER_EMAIL" | tr '[:upper:]' '[:lower:]')" '
    $1 == "sec" { usable = ($2 != "r" && $2 != "e" && $2 != "i" && $12 ~ /E/); fpr = ""; next }
    $1 == "fpr" && fpr == "" { fpr = $10; next }
    $1 == "uid" && usable && fpr != "" && match(tolower($10), /<[^<>@ ]+@[^<> ]+>/) {
      addr = substr(tolower($10), RSTART + 1, RLENGTH - 2)
      if (want == "" || addr == want) { print fpr; exit } }')
fi
if [ -z "$OWNER_FPR" ]; then
  echo "No usable secret key with an email user ID${OWNER_EMAIL:+ <$OWNER_EMAIL>} found; pass the owner fingerprint." >&2
  exit 1
fi
# Recipient address and name for the test mails: the key's matching (or first) email user ID.
OWNER_UID=$("$GPG" --batch --with-colons --list-keys "$OWNER_FPR" | awk -F: -v want="$(printf '%s' "$OWNER_EMAIL" | tr '[:upper:]' '[:lower:]')" '
  $1 == "uid" && match(tolower($10), /<[^<>@ ]+@[^<> ]+>/) {
    addr = substr(tolower($10), RSTART + 1, RLENGTH - 2)
    if (want == "" || addr == want) { print $10; exit } }')
OWNER_EMAIL=$(printf '%s' "$OWNER_UID" | sed -E 's/.*<([^>]*)>.*/\1/')
OWNER_NAME=$(printf '%s' "$OWNER_UID" | sed -E 's/[[:space:]]*<[^>]*>.*//')

# --- temporary homes -----------------------------------------------------------------------------------------------
# Short paths under /tmp: gpg-agent socket paths have a length limit.
SENDER_HOME=$(mktemp -d /tmp/sigil-mails-XXXXXX)
STRANGER_HOME=$(mktemp -d /tmp/sigil-mails-XXXXXX)
WORK=$(mktemp -d /tmp/sigil-mails-XXXXXX)
cleanup() {
  for home in "$SENDER_HOME" "$STRANGER_HOME"; do "$GPGCONF" --homedir "$home" --kill all >/dev/null 2>&1 || true; done
  rm -rf "$SENDER_HOME" "$STRANGER_HOME" "$WORK"
}
trap cleanup EXIT

tgpg() { "$GPG" --homedir "$SENDER_HOME" --batch --no-tty --quiet --yes "$@"; }
sgpg() { "$GPG" --homedir "$STRANGER_HOME" --batch --no-tty --quiet --yes "$@"; }
newkey() { "$GPG" --homedir "$1" --batch --no-tty --quiet --pinentry-mode loopback --passphrase '' \
  --quick-gen-key "$2" ed25519 sign never 2>/dev/null; }

newkey "$SENDER_HOME" "$SENDER_UID"
newkey "$STRANGER_HOME" "$STRANGER_UID"
SENDER_FPR=$(tgpg --with-colons --list-keys "$SENDER_EMAIL" | awk -F: '$1 == "fpr" { print $10; exit }')
STRANGER_FPR=$(sgpg --with-colons --list-keys "$STRANGER_EMAIL" | awk -F: '$1 == "fpr" { print $10; exit }')

"$GPG" --batch --export "$OWNER_FPR" > "$WORK/owner.pub"
tgpg --import "$WORK/owner.pub" 2>/dev/null
# Only the public key is in the temporary home; it has unknown validity there, so encrypt with --trust-model always.
encrypt_to_owner() { tgpg --armor --trust-model always --recipient "$OWNER_FPR" "$@"; }

rm -rf "$OUT"
mkdir -p "$OUT"
tgpg --armor --export "$SENDER_FPR" > "$OUT/sigil-test-sender.asc"

# --- MIME helpers (CRLF line endings throughout) ------------------------------------------------------------------
crlf() { perl -pe 's/\r?\n/\r\n/'; }

headers() { # from subject [extra headers...]
  local from=$1 subject=$2
  shift 2
  printf 'From: %s\nTo: %s <%s>\nSubject: [Sigil test] %s\nDate: %s\nMessage-ID: <%s@sigil.example.invalid>\nMIME-Version: 1.0\n' \
    "$from" "${OWNER_NAME:-Test Recipient}" "$OWNER_EMAIL" "$subject" "$(LC_ALL=C date -R)" "$(uuidgen)"
  for h in "$@"; do printf '%s\n' "$h"; done
}

text_entity() { # body text
  printf 'Content-Type: text/plain; charset=us-ascii\nContent-Transfer-Encoding: 7bit\n\n%s\n' "$1" | crlf
}

# multipart/signed around an entity, detached signature made with the given gpg function.
pgp_mime_signed() { # gpgfn entity-file
  local gpgfn=$1 entity=$2
  $gpgfn --armor --detach-sign --digest-algo SHA256 --output "$WORK/sig.asc" "$entity"
  printf '%s\r\n' 'Content-Type: multipart/signed; micalg=pgp-sha256; protocol="application/pgp-signature"; boundary="sigil-signed"'
  printf '\r\nThis is an OpenPGP/MIME signed message (RFC 4880 and 3156)\r\n--sigil-signed\r\n'
  cat "$entity"
  printf '\r\n--sigil-signed\r\n'
  printf 'Content-Type: application/pgp-signature; name="signature.asc"\nContent-Description: OpenPGP digital signature\nContent-Disposition: attachment; filename="signature.asc"\n\n' | crlf
  crlf < "$WORK/sig.asc"
  printf '\r\n--sigil-signed--\r\n'
}

pgp_mime_encrypted() { # armored-ciphertext-file
  printf '%s\r\n' 'Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary="sigil-encrypted"'
  printf '\r\nThis is an OpenPGP/MIME encrypted message (RFC 4880 and 3156)\r\n'
  printf -- '--sigil-encrypted\nContent-Type: application/pgp-encrypted\nContent-Description: PGP/MIME version identification\n\nVersion: 1\n\n--sigil-encrypted\nContent-Type: application/octet-stream; name="encrypted.asc"\nContent-Description: OpenPGP encrypted message\nContent-Disposition: inline; filename="encrypted.asc"\n\n' | crlf
  crlf < "$1"
  printf '\r\n--sigil-encrypted--\r\n'
}

SENDER="Sigil Test Sender <$SENDER_EMAIL>"

# 01: PGP/MIME signed, good signature.
text_entity "This message is signed with PGP/MIME by the Sigil throwaway test key.
Expected: a valid signature (after importing sigil-test-sender.asc), shown as unverified key." > "$WORK/e01"
{ headers "$SENDER" "PGP/MIME signed (good)" | crlf; pgp_mime_signed tgpg "$WORK/e01"; } > "$OUT/01-pgpmime-signed-good.eml"

# 02: same, but the body is changed after signing.
text_entity "This message was signed, and then this sentence was changed after signing.
Expected: an invalid signature." > "$WORK/e02"
{ headers "$SENDER" "PGP/MIME signed, tampered body" | crlf; pgp_mime_signed tgpg "$WORK/e02"; } > "$WORK/m02"
perl -pe 's/then this sentence was changed/then THIS sentence was changed/' "$WORK/m02" > "$OUT/02-pgpmime-signed-tampered.eml"

# 03: signed by a key nobody will ever import.
text_entity "This message is signed by a throwaway key whose public key is never published.
Expected: signature by an unknown key (NO_PUBKEY)." > "$WORK/e03"
{ headers "Unknown Signer <$STRANGER_EMAIL>" "PGP/MIME signed by an unknown key" | crlf; pgp_mime_signed sgpg "$WORK/e03"; } \
  > "$OUT/03-pgpmime-signed-unknown-key.eml"

# 04: inline (cleartext) signed.
printf 'This message is clearsigned inline by the Sigil throwaway test key.\nExpected: a valid signature (after importing sigil-test-sender.asc).\n' \
  | tgpg --clearsign --digest-algo SHA256 > "$WORK/clear.asc"
{ headers "$SENDER" "Inline clearsigned" 'Content-Type: text/plain; charset=us-ascii' 'Content-Transfer-Encoding: 7bit' | crlf
  printf '\r\n'; crlf < "$WORK/clear.asc"; } > "$OUT/04-inline-clearsigned.eml"

# 05: PGP/MIME encrypted to the owner and signed by the throwaway key; HTML part with a remote image (EFAIL check).
{ printf 'Content-Type: multipart/alternative; boundary="sigil-alt"\n\n--sigil-alt\n'
  printf 'Content-Type: text/plain; charset=us-ascii\nContent-Transfer-Encoding: 7bit\n\nThis message is PGP/MIME encrypted to you and signed by the Sigil throwaway test key.\nExpected: decrypted, signed, remote content blocked.\n\n'
  printf -- '--sigil-alt\nContent-Type: text/html; charset=us-ascii\nContent-Transfer-Encoding: 7bit\n\n'
  printf '<html><body><p>This message is PGP/MIME <b>encrypted</b> to you and signed by the Sigil throwaway test key.</p>\n<p>Expected: decrypted, signed, and the remote image below is <b>blocked</b>:</p>\n<img src="https://example.org/sigil-efail-check.png" alt="remote image (should be blocked)">\n</body></html>\n'
  printf -- '--sigil-alt--\n'; } | crlf > "$WORK/e05"
encrypt_to_owner --sign --local-user "$SENDER_FPR" --encrypt --output "$WORK/c05.asc" "$WORK/e05"
{ headers "$SENDER" "PGP/MIME encrypted and signed" | crlf; pgp_mime_encrypted "$WORK/c05.asc"; } \
  > "$OUT/05-pgpmime-encrypted-signed.eml"

# 06: inline encrypted (armored block in a text/plain body), not signed.
printf 'This message is inline PGP encrypted to you (not signed).\nExpected: decrypted, remote content blocked.\n' \
  | encrypt_to_owner --encrypt > "$WORK/c06.asc"
{ headers "$SENDER" "Inline encrypted" 'Content-Type: text/plain; charset=us-ascii' 'Content-Transfer-Encoding: 7bit' | crlf
  printf '\r\n'; crlf < "$WORK/c06.asc"; } > "$OUT/06-inline-encrypted.eml"

# 07: PGP/MIME encrypted to the owner, then one byte of the encrypted data flipped (after the session key packet,
# so the passphrase is still asked for and the integrity check then fails). Re-armored with a valid checksum.
text_entity "If you can read this, Sigil showed plaintext from tampered ciphertext. It must not." > "$WORK/e07"
encrypt_to_owner --encrypt --output "$WORK/c07.asc" "$WORK/e07"
tgpg --dearmor < "$WORK/c07.asc" > "$WORK/c07.bin"
python3 -I - "$WORK/c07.bin" "$WORK/c07-tampered.asc" <<'PY'
import base64, sys
data = bytearray(open(sys.argv[1], "rb").read())
data[len(data) - 30] ^= 0x01
def crc24(b):
    crc = 0xB704CE
    for byte in b:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF
body = base64.b64encode(bytes(data)).decode()
lines = [body[i:i + 64] for i in range(0, len(body), 64)]
checksum = base64.b64encode(crc24(data).to_bytes(3, "big")).decode()
with open(sys.argv[2], "w") as out:
    out.write("-----BEGIN PGP MESSAGE-----\n\n" + "\n".join(lines) + "\n=" + checksum + "\n-----END PGP MESSAGE-----\n")
PY
{ headers "$SENDER" "PGP/MIME encrypted, tampered ciphertext" | crlf; pgp_mime_encrypted "$WORK/c07-tampered.asc"; } \
  > "$OUT/07-pgpmime-encrypted-tampered.eml"

# mbox for File > Import Mailboxes. Mail caches how it decodes a message, so every run gets a new
# mailbox name and new Message-IDs (above) instead of re-importing old copies.
rm -rf "$OUT"/*.mbox
MBOX_DIR="$OUT/Sigil Test $(date +%H%M%S).mbox"
mkdir -p "$MBOX_DIR"
for f in "$OUT"/0*.eml; do
  printf 'From sigil-test@example.org %s\n' "$(LC_ALL=C date '+%a %b %e %H:%M:%S %Y')"
  tr -d '\r' < "$f" | sed -E 's/^(>*From )/>\1/'
  printf '\n'
done > "$MBOX_DIR/mbox"

cat <<EOF
Mailbox to import (File > Import Mailboxes > Files in mbox format): $MBOX_DIR
Wrote $(find "$OUT" -maxdepth 1 -name "*.eml" | wc -l | tr -d ' ') test mails to $OUT
  owner key (public key only, encrypted to): $OWNER_FPR <$OWNER_EMAIL>
  throwaway sender key:                      $SENDER_FPR <$SENDER_EMAIL>
  unknown signer key (never exported):       $STRANGER_FPR <$STRANGER_EMAIL>

The throwaway keys' secret halves are deleted with the temporary homes when this script exits.

Signatures by the throwaway sender (01, 02, 04, 05) only verify once you import its public key into your keyring.
Without it, they show up like 03 (unknown key). To import it:

  gpg --import "$OUT/sigil-test-sender.asc"

It then shows as an unverified key; to see the verified state, certify it locally:  gpg --lsign-key $SENDER_FPR
Remove it again afterwards with:  gpg --batch --yes --delete-keys $SENDER_FPR
EOF
