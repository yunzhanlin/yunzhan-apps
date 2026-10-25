import time
def wait_job(client,job,timeout=1500):
 deadline=time.monotonic()+timeout
 while job.get('state') in ('queued','running') and time.monotonic()<deadline:
  time.sleep(2);job=client.api('/docker/jobs/'+job['job_id'])
 if job.get('state')!='succeeded':raise AssertionError(job.get('error','Docker job timed out'))
 return job
