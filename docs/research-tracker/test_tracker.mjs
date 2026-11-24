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

const moe25=deep(seed.records.find(r=>r.id==='SPD-0025'));
moe25.metrics[0].otherProvenance={source:'moe-only'};
moe25.metrics[1].otherProvenance={source:'dense-only'};
const old25=deep(moe25.metrics),rows25=metricLines(moe25.metrics).split('\n');
const reordered25=[rows25[1],rows25[0].replace('1151.66→1432.97','1151.67→1432.97')].join('\n');
const swapped25=applyMetricEdit(moe25.metrics,reordered25);
assert.equal(swapped25[0].label,'dense pp2048');
assert.equal(swapped25[0].note,'逆効果');
assert.equal(swapped25[0].before,'322.5');
assert.equal(swapped25[0].after,'309.8');
assert.deepEqual(swapped25[0].otherProvenance,{source:'dense-only'});
assert.equal(swapped25[1].label,'MoE pp512');
assert.equal(swapped25[1].value,'1151.67→1432.97');
assert.equal(swapped25[1].note,'');
assert.equal(swapped25[1].before,'1151.66');
assert.equal(swapped25[1].after,'1432.97');
assert.deepEqual(swapped25[1].otherProvenance,{source:'moe-only'});
assert.deepEqual(moe25.metrics,old25); // editing must not mutate original
const edited25=mergeEditorRecord(moe25,{id:moe25.id,name:moe25.name,category:moe25.category},reordered25,moe25.tags.join(','),moe25.sourceRefs.join('\n'));
assert.deepEqual(edited25.metrics,swapped25);
const roundTrip25=mergeImported(seed,{schemaVersion:1,records:[edited25]},'2026-11-23').next;
assert.deepEqual(JSON.parse(JSON.stringify(roundTrip25)).records.find(r=>r.id==='SPD-0025').metrics,swapped25);
assert.deepEqual(applyMetricEdit(moe25.metrics,rows25[1]),[old25[1]]); // deletion must not copy another row's note
const inserted25=applyMetricEdit(moe25.metrics,metricLines(moe25.metrics)+'\nnew metric | 1 | tok/s | 未確認 | test');
assert.deepEqual(inserted25.slice(0,2),old25);assert.equal(inserted25[2].note,undefined);
assert.throws(()=>applyMetricEdit(moe25.metrics,[rows25[1],rows25[0].replace('MoE pp512','renamed metric')].join('\n')),/同一性/);
assert.throws(()=>applyMetricEdit(moe25.metrics,[rows25[1],rows25[0].replace('公表値（当方未実測）','未確認')].join('\n')),/同一性/);
const duplicate25=deep(moe25.metrics);for(const key of ['label','unit','origin','condition'])duplicate25[1][key]=duplicate25[0][key];
assert.throws(()=>applyMetricEdit(duplicate25,metricLines(duplicate25).replace('1151.66→1432.97','1151.67→1432.97')),/同一性/);

console.log('OK: 27-to-40 migration, lossless edits, safe imports, safe CSV, provenance-safe reorder and value edits, generated HTML');


// Exercise the actual editor rendering and submit handler in a minimal DOM fixture.
// The browser's selected option is modelled explicitly; this is not a browser test.
const editorStart=template.indexOf('const editSpec=');
const editorEnd=template.indexOf("\ne('addTop')",editorStart);
const escStart=template.indexOf('function esc(s)');
const escEnd=template.indexOf('\nfunction link(',escStart);
assert.ok(editorStart>=0&&editorEnd>editorStart&&escStart>=0&&escEnd>escStart);
const editor=new Function('SEED','FormData',template.slice(begin,end)+template.slice(escStart,escEnd)+
  '\nlet state=deep(SEED),editId="",selected=new Set();const elements=new Map();'+
  'function e(id){if(!elements.has(id))elements.set(id,{classList:{add(){},remove(){}},addEventListener(type,fn){this[type]=fn}});return elements.get(id)}'+
  'function byId(id){return state.records.find(r=>r.id===id)}function persist(){}function renderAll(){}function toast(message){if(message!=="ローカル台帳に保存しました。外部への反映はありません。")throw Error(message)}\n'+
  template.slice(editorStart,editorEnd)+
  '\nreturn {state,openEditor,editSpec,markup:()=>e("editFields").innerHTML,submit:values=>e("editForm").submit({preventDefault(){},target:values})}'
)(seed,class{constructor(values){this.values=values}get(key){return this.values[key]??null}});
function kindSelect(markup){
 const select=markup.match(/<select id="edit-kind" name="kind">([\s\S]*?)<\/select>/);
 assert.ok(select);
 const options=[...select[1].matchAll(/<option value="([^"]*)" ([^>]*)>([\s\S]*?)<\/option>/g)];
 assert.ok(options.length>=3);
 const chosen=options.filter(x=>x[2]==='selected');
 assert.equal(chosen.length,1);
 return {value:chosen[0][1],values:options.map(x=>x[1]),html:select[1]};
}
function editorValues(record,kind){
 return Object.fromEntries(editor.editSpec.map(([key])=>[key,key==='kind'?kind:key==='metrics'?metricLines(record.metrics):key==='tags'?(record.tags||[]).join(', '):key==='sourceRefs'?(record.sourceRefs||[]).join('\n'):record[key]??'']));
}
for(const id of ['SPD-0025','SPD-0024','SPD-0001']){
 const previous=deep(editor.state.records.find(r=>r.id===id));
 editor.openEditor(id);
 const select=kindSelect(editor.markup());
 assert.equal(select.value,previous.kind);
 assert.equal(select.values.filter(x=>x===previous.kind).length,1);
 const values=editorValues(previous,select.value);values.name+=' edited';
 editor.submit(values);
 const updated=editor.state.records.find(r=>r.id===id);
 assert.equal(updated.kind,previous.kind);
 assert.deepEqual(updated.metrics,previous.metrics);
 assert.deepEqual(updated.sourceRefs,previous.sourceRefs);
 assert.equal(editor.state.audit[0].text,id+' をローカル編集');
}
const exported=JSON.parse(JSON.stringify(editor.state));
const reimported=mergeImported(editor.state,exported,'2026-11-24').next;
assert.deepEqual(reimported.records,exported.records);
assert.deepEqual(reimported.audit.slice(1),exported.audit);
const standard=deep(editor.state.records.find(r=>r.kind==='手法'));
editor.openEditor(standard.id);
assert.deepEqual(kindSelect(editor.markup()).values,['手法','資料集','環境別評価']);
editor.submit(editorValues(standard,'資料集'));
assert.equal(editor.state.records.find(r=>r.id===standard.id).kind,'資料集');
editor.openEditor();
assert.equal(kindSelect(editor.markup()).value,'手法');
editor.submit(editorValues({id:'NEW-TEST-KIND',name:'new test',category:'test',checkedDate:'2026-11-24',status:'未確認'},'環境別評価'));
assert.equal(editor.state.records.find(r=>r.id==='NEW-TEST-KIND').kind,'環境別評価');
// An imported value is displayed safely and not silently coerced to a standard kind.
const custom=editor.state.records.find(r=>r.id==='SPD-0025');
custom.kind=' custom <kind> & "quote" ';
editor.openEditor(custom.id);
assert.equal(kindSelect(editor.markup()).value,' custom &lt;kind&gt; &amp; &quot;quote&quot; ');
editor.submit(editorValues(custom,custom.kind));
assert.equal(editor.state.records.find(r=>r.id===custom.id).kind,' custom <kind> & "quote" ');
console.log('OK: editor kind preservation, escaped imported kinds, JSON round-trip, intentional standard/new edits');
