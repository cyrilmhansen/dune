"""Reuse the byte-preserving annotation generator at the explicit Pass53 epoch."""
import os,runpy
from pathlib import Path
os.environ['RUNES_ANNOTATION_PASS']='53'
os.environ['RUNES_ANNOTATION_BASE']='9a119ea41243d57da42233de92e1d5358d120e15'
runpy.run_path(str(Path(__file__).with_name('update_buffered_rel_annotations_pass_52.py')),run_name='__main__')

from decompilation_annotations import render
render(Path('research/annotated-assembly'))
