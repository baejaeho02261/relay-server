"""Compatibility command: the flat-layout suite replaces the old nested layout."""
from pathlib import Path
import runpy
runpy.run_path(str(Path(__file__).with_name('test-overlay-flat-build.py')), run_name='__main__')
