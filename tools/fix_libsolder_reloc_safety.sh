#!/usr/bin/env bash
set -euo pipefail

FILE="third_party/libsolder/source/loader.c"
RELOC="third_party/libsolder/source/reloc.c"
test -f "$FILE"
test -f "$RELOC"

python3 - <<'PY'
from pathlib import Path

# --- loader.c: make failed dlsym/dlopen relocation safe ---
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
if old in s and new not in s:
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
if old2 in s and new2 not in s:
    s = s.replace(old2, new2, 1)

# Add opaque bulk diagnostic API once.
needle = "int solder_dso_unload(dynmod_t *mod) {"
func = """/*
 * Diagnostic helper: relocate a module while ignoring unresolved imports,
 * but do not run its constructors. reloc.c logs each unresolved symbol.
 * The module is diagnostic-only after this call because unresolved GOT/PLT
 * entries may have been written as zero.
 */
int solder_debug_relocate_all(void *handle) {
  dynmod_t *mod = handle ? (dynmod_t *)handle : &solder_dsolist;
  if (!mod) return -1;
  if (!(mod->flags & MOD_MAPPED) && dso_map(mod))
    return -2;
  return solder_relocate(mod, 1, 0);
}

"""
if 'int solder_debug_relocate_all(void *handle)' not in s:
    if needle not in s:
        raise SystemExit('loader insertion point not found')
    s = s.replace(needle, func + needle, 1)
p.write_text(s)

# --- reloc.c: make bulk unresolved lines easy to parse ---
p = Path("third_party/libsolder/source/reloc.c")
s = p.read_text()
old3 = '            DEBUG_PRINTF("`%s`: resolution failed for `%s`%s\\n", mod->name, symname, weak ? " (weak)" : "");'
new3 = '            DEBUG_PRINTF("BULK_UNRESOLVED `%s`: `%s`%s\\n", mod->name, symname, weak ? " (weak)" : "");'
if old3 in s and 'BULK_UNRESOLVED' not in s:
    s = s.replace(old3, new3, 1)
p.write_text(s)
PY

echo "libsolder bulk diagnostic patch applied"
