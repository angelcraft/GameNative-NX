#!/usr/bin/env bash
set -euo pipefail
FILE="third_party/libsolder/source/loader.c"
test -f "$FILE"
python3 - <<'PY'
from pathlib import Path
p = Path("third_party/libsolder/source/loader.c")
s = p.read_text()
old = """      if (dso_relocate_and_init(mod, 0)) {
        solder_dso_unload(mod);
        if (handle)
          return NULL;
        else
          continue;
      }"""
new = """      if (dso_relocate_and_init(mod, 0)) {
        // A failed dlsym() relocation must not free the caller's module
        // handle. Leave it loaded and report the relocation failure.
        if (handle)
          return NULL;
        else {
          dynmod_t *next = mod->next;
          dso_unlink(mod);
          solder_dso_unload(mod);
          mod = next;
          if (!mod)
            break;
          continue;
        }
      }"""
if old not in s:
    raise SystemExit("dlsym block not found; libsolder source changed")
s = s.replace(old, new, 1)
old2 = """    if (dso_relocate_and_init(mod, 0)) {
      solder_dso_unload(mod);
      return NULL;
    }"""
new2 = """    if (dso_relocate_and_init(mod, 0)) {
      // Keep the module list consistent before discarding a failed dlopen.
      dso_unlink(mod);
      solder_dso_unload(mod);
      return NULL;
    }"""
if old2 not in s:
    raise SystemExit("dlopen block not found; libsolder source changed")
s = s.replace(old2, new2, 1)
p.write_text(s)
PY
chmod +x /mnt/data/fix_libsolder_reloc_safety.sh
python3 - <<'PY'
from pathlib import Path
s=Path('/mnt/data/main_dependency_preload_v6.cpp').read_text()
print('main count',s.count('int main('),'dlclose calls',s.count('solder_dlclose('),'skip close', 'CLOSE: skipped' in s)
print('script size',Path('/mnt/data/fix_libsolder_reloc_safety.sh').stat().st_size)
PY
