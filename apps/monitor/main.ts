import { githubApi, monitor, MONITOR_REPOSITORY } from './monitor';
const mode = process.env.TWB_MONITOR_MODE || 'normal';
if (!['normal', 'drill-outage', 'drill-recovery'].includes(mode)) throw new Error('Invalid monitor mode');
if (process.env.GITHUB_REPOSITORY !== MONITOR_REPOSITORY || process.env.GITHUB_REF !== 'refs/heads/main') throw new Error('Monitor is restricted to the dedicated main branch');
if (mode !== 'normal' && process.env.GITHUB_EVENT_NAME !== 'workflow_dispatch') throw new Error('Alert drills require explicit dispatch');
try {
  const result = await monitor({ api: githubApi(process.env.GITHUB_TOKEN ?? ''), mode: mode as 'normal' | 'drill-outage' | 'drill-recovery' });
  console.log(JSON.stringify({ checkedAt: new Date().toISOString(), ...result }));
} catch {
  // Never echo HTTP bodies, environment variables, tokens or raw exception causes.
  console.error('Availability monitor failed. Review its configuration and GitHub access.'); process.exitCode = 1;
}
