#!/usr/bin/env bash
# Make Cowrie's captured samples readable by the API user.
#
# Cowrie writes captured payloads two different ways, and only one of them is
# readable by anyone else:
#
#   core/artifact.py  (wget/curl downloads)  renames its mkstemp file into the
#                     downloads directory and then chmods it to 0666 & ~umask,
#                     which lands at 0644.
#   shell/fs.py       (SFTP/SCP uploads)     does the same rename with no chmod
#                     at all, so the sample keeps mkstemp's 0600.
#
# Cowrie runs in a container as its own user, so those 0600 samples cannot be
# opened by the API — static analysis and VirusTotal upload both fail on them,
# and on this host that was roughly two thirds of everything captured. Neither
# path is configurable, so the directory is normalised from outside instead.
#
# Target is 0640 owned by group $SAMPLE_GROUP: the API gets read access through
# the group, and the world loses the read access the 0644 half currently has —
# these are live malware samples. Cowrie stays the owner and keeps read/write.
#
# Runs on a timer rather than on a watch because nothing is urgent: the static
# analysis worker leaves unreadable samples pending and picks them up on its
# next pass, so a sample is analyzed at worst one cycle late.
set -euo pipefail

DOWNLOADS=${1:?usage: sample-perms.sh <cowrie-downloads-dir>}
SAMPLE_GROUP=${SAMPLE_GROUP:-jopi}

[[ -d "$DOWNLOADS" ]] || exit 0

# -type f matches regular files only, never symlinks, so a link planted in this
# world-writable directory cannot redirect the chgrp/chmod at a file outside
# it. The unit's ProtectSystem=strict + ReadWritePaths closes the remaining
# race, where a file is swapped for a symlink between find and exec.
find "$DOWNLOADS" -maxdepth 1 -type f \
  \( ! -perm 0640 -o ! -group "$SAMPLE_GROUP" \) \
  -exec chgrp "$SAMPLE_GROUP" {} + \
  -exec chmod 0640 {} +
