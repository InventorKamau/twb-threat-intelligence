import {build} from 'esbuild';
await build({entryPoints:['apps/worker/cloud-publish.ts'],outfile:'dist/cloud-publish.js',platform:'node',target:'node24',format:'esm',bundle:true,packages:'external'});
await build({entryPoints:['apps/monitor/main.ts'],outfile:'dist/monitor.js',platform:'node',target:'node24',format:'esm',bundle:true,packages:'external'});
