from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
from typing import Any

from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r8_preimport_source_supervisor_v2.contract import (
    PINNED_VENV_PYTHON,
    PROJECT_ROOT,
    SUPERVISOR_RAW_SHA256,
    SUPERVISOR_RELATIVE,
)


SUPERVISOR_PATH = PROJECT_ROOT / SUPERVISOR_RELATIVE


def _load_supervisor() -> Any:
    spec = importlib.util.spec_from_file_location(
        "r8r8_preimport_supervisor_v2_owner_rights_audit",
        SUPERVISOR_PATH,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _clean_environment() -> dict[str, str]:
    return {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith("PYTHON")
    }


ACL_TAMPER_CHILD = r'''import ctypes,json,sys
from ctypes import wintypes
p=sys.argv[1]
GENERIC_READ=0x80000000
WRITE_DAC=0x00040000
WRITE_OWNER=0x00080000
READ_CONTROL=0x00020000
FILE_SHARE_READ=1
OPEN_EXISTING=3
FILE_FLAG_BACKUP_SEMANTICS=0x02000000
FILE_FLAG_OPEN_REPARSE_POINT=0x00200000
DACL_SECURITY_INFORMATION=4
PROTECTED_DACL_SECURITY_INFORMATION=0x80000000
SDDL_REVISION_1=1
SE_FILE_OBJECT=1
INVALID=ctypes.c_void_p(-1).value
k=ctypes.WinDLL("kernel32",use_last_error=True)
a=ctypes.WinDLL("advapi32",use_last_error=True)
k.CreateFileW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,wintypes.LPVOID,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE]
k.CreateFileW.restype=wintypes.HANDLE
k.CloseHandle.argtypes=[wintypes.HANDLE]
k.CloseHandle.restype=wintypes.BOOL
k.LocalFree.argtypes=[wintypes.HLOCAL]
k.LocalFree.restype=wintypes.HLOCAL
a.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,ctypes.POINTER(ctypes.c_void_p),ctypes.POINTER(wintypes.ULONG)]
a.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype=wintypes.BOOL
a.GetSecurityDescriptorDacl.argtypes=[ctypes.c_void_p,ctypes.POINTER(wintypes.BOOL),ctypes.POINTER(ctypes.c_void_p),ctypes.POINTER(wintypes.BOOL)]
a.GetSecurityDescriptorDacl.restype=wintypes.BOOL
a.SetNamedSecurityInfoW.argtypes=[wintypes.LPWSTR,ctypes.c_int,wintypes.DWORD,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p]
a.SetNamedSecurityInfoW.restype=wintypes.DWORD
a.SetFileSecurityW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,ctypes.c_void_p]
a.SetFileSecurityW.restype=wintypes.BOOL
out={}
for label,access in (("open_write_dac",WRITE_DAC|READ_CONTROL),("open_write_owner",WRITE_OWNER|READ_CONTROL),("open_read",GENERIC_READ|READ_CONTROL)):
 ctypes.set_last_error(0)
 h=k.CreateFileW(p,access,FILE_SHARE_READ,None,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,None)
 out[label]={"opened":h!=INVALID,"last_error":ctypes.get_last_error()}
 if h!=INVALID:
  out[label]["close_ok"]=bool(k.CloseHandle(h))
sd=ctypes.c_void_p();size=wintypes.ULONG()
if not a.ConvertStringSecurityDescriptorToSecurityDescriptorW("D:P(A;OICI;FA;;;OW)",SDDL_REVISION_1,ctypes.byref(sd),ctypes.byref(size)):
 raise RuntimeError("ConvertStringSecurityDescriptor")
try:
 present=wintypes.BOOL();dacl=ctypes.c_void_p();defaulted=wintypes.BOOL()
 if not a.GetSecurityDescriptorDacl(sd,ctypes.byref(present),ctypes.byref(dacl),ctypes.byref(defaulted)) or not present.value or not dacl.value:
  raise RuntimeError("GetSecurityDescriptorDacl")
 out["set_named_dacl_result"]=int(a.SetNamedSecurityInfoW(p,SE_FILE_OBJECT,DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,None,None,dacl,None))
 ctypes.set_last_error(0)
 out["set_file_security_ok"]=bool(a.SetFileSecurityW(p,DACL_SECURITY_INFORMATION,sd))
 out["set_file_security_last_error"]=ctypes.get_last_error()
finally:
 if k.LocalFree(sd): raise RuntimeError("LocalFree")
print(json.dumps(out,sort_keys=True,separators=(",",":")))
'''


def test_v2_source_is_unchanged_and_uses_owner_rights_sid() -> None:
    raw = SUPERVISOR_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == SUPERVISOR_RAW_SHA256
    supervisor = _load_supervisor()
    # OW is SDDL_OWNER_RIGHTS (S-1-3-4), not the concrete current-user SID.
    assert supervisor.PROTECTED_READ_ONLY_SDDL == (
        "D:P(A;OICI;GRGX;;;OW)(A;OICI;GRGX;;;SY)(A;OICI;GRGX;;;BA)"
    )
    assert "WD" not in supervisor.PROTECTED_READ_ONLY_SDDL
    assert "WO" not in supervisor.PROTECTED_READ_ONLY_SDDL


def test_same_principal_cannot_reopen_or_replace_owner_rights_dacl(
    tmp_path: Path,
) -> None:
    supervisor = _load_supervisor()
    held = supervisor._HeldCreatedDirectory(
        parent=tmp_path,
        child_name="owner_rights_acl_tamper_probe",
    )
    before = dict(held.verify()["protected_read_list_only_dacl"])
    try:
        completed = subprocess.run(
            (
                str(PINNED_VENV_PYTHON),
                "-I",
                "-B",
                "-E",
                "-c",
                ACL_TAMPER_CHILD,
                str(held.path),
            ),
            env=_clean_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
            text=True,
        )
        assert completed.returncode == 0
        assert completed.stderr == ""
        result = json.loads(completed.stdout)
        assert result["open_read"]["opened"] is True
        assert result["open_read"]["close_ok"] is True
        assert result["open_write_dac"]["opened"] is False
        assert result["open_write_dac"]["last_error"] == 5
        assert result["open_write_owner"]["opened"] is False
        assert result["open_write_owner"]["last_error"] == 5
        assert result["set_named_dacl_result"] == 5
        assert result["set_file_security_ok"] is False
        assert result["set_file_security_last_error"] == 5
        after = held.verify()["protected_read_list_only_dacl"]
        assert after == before
    finally:
        held.restore_test_cleanup_dacl()
        held.close()
    held.path.rmdir()
