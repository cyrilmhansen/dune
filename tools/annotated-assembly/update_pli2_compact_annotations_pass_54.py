"""Reuse the byte-preserving annotation generator at the explicit Pass54 epoch."""
import os,runpy
from pathlib import Path
os.environ['RUNES_ANNOTATION_PASS']='54'
os.environ['RUNES_ANNOTATION_BASE']='3ea8fa04b3aee725a772f1365763306ea4ee4f62'
runpy.run_path(str(Path(__file__).with_name('update_buffered_rel_annotations_pass_52.py')),run_name='__main__')

from decompilation_annotations import render
render(Path('research/annotated-assembly'))
