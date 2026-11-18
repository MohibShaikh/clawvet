# Extract a downloaded benchmark archive into its own folder, refusing paths
# that leave it and symlinks. Only writes files; nothing in it is run.
# Usage: python3 -I extract-zip.py <archive.zip> <out dir>
import os, stat, sys, zipfile
z = zipfile.ZipFile(sys.argv[1]); out = os.path.realpath(sys.argv[2]); n = bad = links = 0
for info in z.infolist():
    p = os.path.realpath(os.path.join(out, info.filename))
    if not p.startswith(out + os.sep): bad += 1; continue
    if stat.S_ISLNK(info.external_attr >> 16): links += 1; continue
    if info.is_dir(): os.makedirs(p, exist_ok=True); continue
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with z.open(info) as src, open(p, "wb") as dst: dst.write(src.read())
    n += 1
print(n, "files;", bad, "unsafe paths and", links, "symlinks skipped")
