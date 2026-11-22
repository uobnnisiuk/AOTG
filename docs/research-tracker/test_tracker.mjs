// Run: node docs/research-tracker/test_tracker.mjs
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {dirname,join} from 'node:path';
const root=dirname(fileURLToPath(import.meta.url));
const template=readFileSync(join(root,'template.html'),'utf8');
const seed=JSON.parse(readFileSync(join(root,'seed.json'),'utf8'));
const index=readFileSync(join(root,'index.html'),'utf8');
const begin=template.indexOf('/* tracker-core-helpers begin */');
const end=template.indexOf('/* tracker-core-helpers end */');
assert.ok(begin>=0&&end>begin);
const api=new Function('SEED',template.slice(begin,end)+';return {deep,validDataset,reconcileSeed,metricLines,mergeEditorRecord,applyMetricEdit,mergeImported,csvCell}')(seed);
const {deep,validDataset,reconcileSeed,metricLines,mergeEditorRecord,applyMetricEdit,mergeImported,csvCell}=api;
assert.ok(validDataset(seed));assert.equal(seed.records.length,40);
const saved=deep(seed);saved.records=saved.records.slice(0,27);
saved.records[0].name='manual edit';saved.records[0].metrics[0].extra={valid:true};
saved.audit=[{at:'2026-11-18',text:'preserve'}];
const migrated=reconcileSeed(saved,seed);
assert.equal(migrated.records.length,40);assert.equal(migrated.records[0].name,'manual edit');
assert.deepEqual(migrated.records[0].metrics[0].extra,{valid:true});
assert.deepEqual(migrated.audit,saved.audit);
assert.equal(reconcileSeed(migrated,seed).records.length,40);
const r=deep(seed.records.find(r=>r.id==='SPD-0033'));
r.metrics[0].unknown={a:1};const before=deep(r.metrics);
const edited=mergeEditorRecord(r,{id:r.id,name:'edited title',category:r.category},metricLines(r.metrics),r.tags.join(','),r.sourceRefs.join('\n'));
assert.deepEqual(edited.metrics,before);
const adjusted=applyMetricEdit(r.metrics,metricLines(r.metrics).replace('47.0→86.4','47.1→86.4'));
assert.equal(adjusted[0].note,before[0].note);assert.deepEqual(adjusted[0].unknown,before[0].unknown);
const imported=mergeImported(seed,{schemaVersion:1,records:[edited]},'2026-11-22').next;
assert.deepEqual(imported.records.find(x=>x.id===r.id).metrics,before);
assert.deepEqual(JSON.parse(JSON.stringify(imported)).records.find(x=>x.id===r.id).metrics,before);
const snapshot=JSON.stringify(imported);
for(const bad of [
 {schemaVersion:1,records:[{id:'BAD',name:'bad',category:'c',metrics:'oops'}]},
 {schemaVersion:1,records:[{id:'BAD',name:'bad',category:'c',metrics:[{label:'x',value:{a:1},unit:'',origin:'',condition:''}]}]},
 {schemaVersion:1,records:[{id:'BAD',name:'bad',category:'c',tags:'oops'}]},
 {schemaVersion:1,records:[{id:'BAD',name:'a',category:'c'},{id:'BAD',name:'b',category:'c'}]}
])assert.throws(()=>mergeImported(imported,bad,'2026-11-22'));
assert.equal(JSON.stringify(imported),snapshot);
for(const danger of ['=HYPERLINK("x")','+SUM(1)','-CMD','@SUM(1)',' =SUM(1)','\t=1','\r\n=1'])
 assert.ok(csvCell(danger).startsWith('"\''));
assert.equal(csvCell('日本語'),'"日本語"');assert.equal(csvCell('47.0'),'"47.0"');assert.equal(csvCell('-123'),'"-123"');
assert.ok(index.includes('/* tracker-core-helpers begin */'));
assert.ok(index.includes('"id": "SPD-0033"'));assert.ok(index.includes('"id": "REF-FROSTBITE-001"'));
assert.ok(!index.includes('__SEED_JSON__'));
console.log('OK: 27-to-40 migration, lossless edits, safe imports, safe CSV, generated HTML');
