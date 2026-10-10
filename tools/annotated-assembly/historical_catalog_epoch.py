"""Frozen metadata assertions; semantic tests still execute current algorithms.

The Pass44 checkpoint already passed these older catalog assertions. Later
bounded extensions are independently proved. Reconstruct that immutable epoch
only after checking that every changed current entry is explicitly documented.
This is a test helper, not an evidence/procedure schema or execution change.
"""
import json,subprocess
from functools import lru_cache
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
CHECKPOINT='430b75bb82187216731f26588b3bfb48e6fed435'
@lru_cache(maxsize=None)
def _checkpoint(commit=CHECKPOINT):
 return {p['id']:p for p in json.loads(subprocess.check_output(['git','show',commit+':research/annotated-assembly/procedures.json'],cwd=ROOT,text=True))['procedures']}
def frozen_catalog(current, *, checkpoint=CHECKPOINT):
 old=_checkpoint(checkpoint);allowed=set()
 for file in ['pass-45/before.json','pass-46/before.json','pass-47/contract-laws-PLI1.OVL.json','pass-47/contract-laws-PLI.COM.json','pass-49/contract-laws-PLI1.OVL.json','pass-50/contract-laws-PLI1.OVL.json','pass-51/contract-laws-PLI.COM.json','pass-52/contract-laws-PLI.COM.json','pass-53/contract-laws-PLI2.OVL.json','pass-54/contract-laws-PLI2.OVL.json','pass-55/contract-laws-PLI2.OVL.json','pass-56/contract-laws-PLI2.OVL.json','pass-57/contract-laws-PLI2.OVL.json','pass-58/contract-laws-PLI2.OVL.json','pass-59/contract-laws-PLI2.OVL.json','pass-60/contract-laws-PLI2.OVL.json']:
  allowed.update(json.loads((ROOT/'research/host-compiler'/file).read_text()))
 changed={k for k in set(old)|set(current)if old.get(k)!=current.get(k)}
 assert changed<=allowed, 'Undocumented catalog change: '+repr(sorted(changed-allowed))
 return dict(old)
