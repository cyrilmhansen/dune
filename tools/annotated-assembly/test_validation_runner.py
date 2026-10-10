#!/usr/bin/env python3
"""Cheap selection, provenance, progress and worker-accounting tests; no toolchain."""
import concurrent.futures,contextlib,io,json,os,subprocess,sys,tempfile,threading,unittest
from pathlib import Path
from unittest import mock
import run_host_compiler_regressions as runner
ROOT=runner.ROOT
POLICY=json.loads(runner.POLICY.read_text())
AVAILABLE=runner.commands('/home/john/pli/cpm/pli80/DISK1',ROOT/'_build/profile-test-unused')

class FlushedBuffer(io.StringIO):
 def __init__(self):super().__init__();self.flushes=0
 def flush(self):self.flushes+=1;super().flush()

class Profiles(unittest.TestCase):
 def select(self,**kwargs):return runner.select_categories(AVAILABLE,POLICY,**kwargs)
 def test_historical_full_preserves_every_certified_category(self):
  old=json.loads((ROOT/POLICY['current_full_epoch']['receipt']).read_text())
  names=set(self.select(profile='historical-full')[1]);self.assertEqual(len(old['categories']),92)
  self.assertTrue(set(old['categories'])<=names);self.assertEqual(names,set(AVAILABLE));self.assertIn('validation-runner-tests',names-set(old['categories']))
 def test_plain_invocation_remains_exhaustive(self):self.assertEqual(self.select(),self.select(profile='historical-full'))
 def test_active_global_and_unit_core(self):
  names=set(self.select(profile='active')[1]);required={'build','project','baseline','V1','roundtrip','roundtrip-tests','packet-continuation','dynamic-progress','diff-check','historical-leaf-queries','validation-runner-tests'}
  units={k for k in AVAILABLE if k.endswith('-unit')};self.assertTrue(required|units<=names)
 def test_active_excludes_archived_expensive_passes(self):
  names=set(self.select(profile='active')[1]);self.assertTrue(names.isdisjoint({'pass49','pass50','pass59','pass60','pass61','pass62'}))
 def test_explicit_extras_and_duplicates(self):
  profile,names,extras=self.select(profile='active',extras='pass53,pass62,pass53')
  self.assertEqual(profile,'active');self.assertEqual(extras,['pass53','pass62']);self.assertTrue({'pass53','pass62'}<=set(names));self.assertEqual(len(names),len(set(names)))
 def test_legacy_categories_selection(self):
  profile,names,extras=self.select(categories='pass53,pass62,pass53');self.assertEqual((profile,names,extras),('legacy-categories',['build','pass53','pass62','project'],[]))
  with self.assertRaises(ValueError):self.select(categories='build') # historically mandatory, not a selectable legacy name
 def test_unknown_and_ambiguous_requests_fail_before_execution(self):
  for kw in [dict(categories='unknown'),dict(profile='active',extras='unknown'),dict(profile='active',categories='pass62'),dict(extras='pass62'),dict(profile='historical-full',extras='pass62')]:
   with self.subTest(kw=kw),self.assertRaises(ValueError):self.select(**kw)
  with mock.patch.object(runner.subprocess,'run')as run,contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):runner.main(['--profile','active','--extra-categories','no-such-category'])
  run.assert_not_called()
 def test_listing_requires_no_execution_paths_and_creates_no_output(self):
  with mock.patch.object(runner,'execute')as execute,contextlib.redirect_stdout(io.StringIO())as out:
   self.assertEqual(runner.main(['--profile','active','--extra-categories','pass62','--list-categories']),0)
  execute.assert_not_called();data=json.loads(out.getvalue());self.assertEqual(data['profile'],'active');self.assertIn('pass62',data['selected_categories']);self.assertEqual(data['validation_tier'],'ACTIVE/INCREMENTAL')
 def test_metadata_never_labels_active_or_legacy_FULL(self):
  for args,tier in[(dict(profile='active'),'ACTIVE/INCREMENTAL'),(dict(categories='pass62'),'INCREMENTAL'),(dict(profile='historical-full'),'FULL')]:
   profile,names,extras=self.select(**args);data=runner.selection_metadata(profile,names,extras,4,POLICY)
   self.assertEqual(data['validation_tier'],tier);self.assertEqual(data['selected_category_count'],len(names));self.assertEqual(data['last_certified_full_epoch']['name'],'Pass62')
 def test_legacy_command_bodies_are_unchanged(self):
  receipt=json.loads((ROOT/POLICY['current_full_epoch']['receipt']).read_text())
  for name,row in receipt['categories'].items():
   if name=='dynamic-progress':continue # only task-specific output path differs
   cmd=AVAILABLE[name]
   if cmd[:2]==['dune','exec']:cmd=['_build/default/'+cmd[2]]
   if name=='project':cmd=cmd+['-j','4']
   self.assertEqual(cmd,row['command'],name)

class Execution(unittest.TestCase):
 def test_progress_lines_are_flushed_and_tail_is_retained(self):
  out=FlushedBuffer();clock=[0];p=runner.Progress(2,45,out,lambda:clock[0]);p.start('build');clock[0]=46;p.heartbeat();p.done('build',46,True);p.start('broken');p.done('broken',1,False,'useful failure tail')
  text=out.getvalue();self.assertIn('[START   0/2] build',text);self.assertIn('[HEARTBEAT   0/2] active=build:00m46s',text);self.assertIn('broken FAILED 1.000s',text);self.assertIn('useful failure tail',text);self.assertGreaterEqual(out.flushes,6)
 def test_heartbeat_excludes_queued_future_and_finished_jobs(self):
  out=FlushedBuffer();clock=[0];p=runner.Progress(2,45,out,lambda:clock[0]);started=threading.Event();release=threading.Event()
  def job(name):
   p.start(name)
   if name=='running':started.set();release.wait(5)
   p.done(name,1,True)
  with concurrent.futures.ThreadPoolExecutor(max_workers=1)as pool:
   first=pool.submit(job,'running');self.assertTrue(started.wait(5));second=pool.submit(job,'queued');clock[0]=46
   self.assertTrue(p.heartbeat());heartbeat=out.getvalue().splitlines()[-1];self.assertIn('running:',heartbeat);self.assertNotIn('queued',heartbeat)
   release.set();first.result();second.result()
  self.assertFalse(p.heartbeat());self.assertEqual(p.active,{})
 def test_no_heartbeat_immediately_after_completion(self):
  out=FlushedBuffer();clock=[0];p=runner.Progress(2,45,out,lambda:clock[0]);p.start('one');p.start('two');clock[0]=45;p.done('one',45,True);clock[0]=60;self.assertFalse(p.heartbeat());clock[0]=91;self.assertTrue(p.heartbeat());self.assertNotIn('one:',out.getvalue().splitlines()[-1]);clock[0]=92;self.assertFalse(p.heartbeat())
 def test_background_heartbeat_runs_and_stops(self):
  out=FlushedBuffer()
  with runner.Progress(1,0.02,out)as p:
   p.start('tiny');self.assertTrue(p.stop_event.wait(0.07) is False);p.done('tiny',0.07,True)
  self.assertIn('HEARTBEAT',out.getvalue());self.assertFalse(p.thread.is_alive())
 def test_tiny_execution_records_profile_logs_and_failure(self):
  (ROOT/'_build').mkdir(exist_ok=True)
  with tempfile.TemporaryDirectory(prefix='validation-runner-test-',dir=ROOT/'_build')as tmp:
   root=Path(tmp);(root/'bin').mkdir();(root/'bin/dune').write_text('')
   cmds={name:[sys.executable,'-c',script]for name,script in [('build','pass'),('project','pass'),('tiny','print("Ran 2 tests in 0.001s")'),('broken','raise SystemExit(3)')]}
   meta=runner.selection_metadata('active',sorted(cmds),['tiny'],2,POLICY)
   with contextlib.redirect_stdout(FlushedBuffer())as out:
    result=runner.execute(cmds,root/'results',dict(os.environ),meta,workers=2,heartbeat_seconds=0.02,root=root)
   self.assertFalse(result['all_passed']);self.assertEqual(result['profile'],'active');self.assertEqual(result['validation_tier'],'ACTIVE/INCREMENTAL');self.assertEqual(result['category_count'],4);self.assertEqual(result['python_test_count'],2);self.assertEqual(result['workers'],2)
   self.assertEqual(json.loads((root/'results/results.json').read_text()),result);self.assertTrue((root/'results/tiny.log').exists());self.assertIn('broken FAILED',out.getvalue())
 def test_serial_failure_stops_workers_and_writes_incomplete_receipt(self):
  with tempfile.TemporaryDirectory(prefix='validation-runner-test-',dir=ROOT/'_build')as tmp:
   cmds={'build':[sys.executable,'-c','raise SystemExit(1)'],'project':['never'],'queued':['never']};meta=runner.selection_metadata('historical-full',sorted(cmds),[],1,POLICY)
   with contextlib.redirect_stdout(io.StringIO()):r=runner.execute(cmds,Path(tmp),dict(os.environ),meta,workers=1)
   self.assertFalse(r['all_passed']);self.assertEqual(r['category_count'],1);self.assertEqual(r['not_run_categories'],['project','queued'])
 def test_missing_timing_hint_is_safe(self):
  self.assertEqual(runner.timing_hints({'current_full_epoch':{'receipt':'_build/does-not-exist.json'}}),{})

if __name__=='__main__':unittest.main()
