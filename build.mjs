import {build} from 'esbuild';
await build({entryPoints:['apps/worker/cloud-publish.ts'],outfile:'dist/cloud-publish.js',platform:'node',target:'node24',format:'esm',bundle:true,packages:'external'});
