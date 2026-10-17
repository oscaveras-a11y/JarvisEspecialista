// CYBER CORE — approved visual evolution of the existing browser prototype.
// State key and demonstration flows are compatible with Claude's web prototype.
// This interface never invokes CORE, reads evidence or calls provider services.
'use strict';
const STORE_KEY='cybercore.ui.v1';
const DEFAULT_STATE={cases:[],tasks:[],audit:[],reports:[],activeCase:null};
const VIEWS=['dashboard','new','investigations','tasks','logs','reports','recovery','forensics','tools','agents'];
const VIEW_TITLES={dashboard:'Visão geral',new:'Nova investigação',investigations:'Investigações',tasks:'Tarefas e progresso',logs:'Registros',reports:'Relatórios',recovery:'Recuperação',forensics:'Perícia digital',tools:'Ferramentas',agents:'Agentes'};
const TOOL_LABELS={'analyze-file':'Análise estática','analyze-firmware':'Ghidra / Binwalk','assess-recovery':'Chaves candidatas','inventory-disk':'Disco MBR / GPT','inventory-pcap':'PCAP','inspect-disk':'Disco MBR / GPT','inspect-pcap':'PCAP','audit-config':'Configuração','audit-crypto':'Criptografia','strings':'Strings','differentiate':'Tipo de conteúdo'};
let storageIssue=false;
function loadState(){
 try{
  const raw=localStorage.getItem(STORE_KEY);
  if(!raw)return null;
  const parsed=JSON.parse(raw);
  if(!parsed||!Array.isArray(parsed.cases)||!Array.isArray(parsed.tasks)||!Array.isArray(parsed.audit))throw Error();
  const cases=parsed.cases.filter(c=>c&&typeof c.id==='string'&&/^[a-zA-Z0-9-]{1,64}$/.test(c.id)&&typeof c.project==='string');
  const tasks=parsed.tasks.filter(t=>t&&typeof t.id==='string'&&typeof t.case_id==='string');
  return {cases,tasks,audit:parsed.audit,reports:Array.isArray(parsed.reports)?parsed.reports:[],activeCase:cases.some(c=>c.id===parsed.activeCase)?parsed.activeCase:null};
 }catch{storageIssue=true;return structuredClone(DEFAULT_STATE);}
}
let state=loadState();
const firstVisit=state===null;
if(firstVisit)state=structuredClone(DEFAULT_STATE);
let search='',currentView='dashboard',auditQueue=Promise.resolve(),actionQueue=Promise.resolve(),renderVersion=0;
function uid(){return crypto.randomUUID().replaceAll('-','');}
function nowIso(){return new Date().toISOString();}
function saveState(){localStorage.setItem(STORE_KEY,JSON.stringify(state));}
function escapeHtml(value){return String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function icon(name){return '<svg class="icon" aria-hidden="true"><use href="assets/icons.svg#'+name+'"></use></svg>';}
function getCase(id){return state.cases.find(c=>c.id===id)||null;}
function dateText(value){const date=new Date(value);return Number.isNaN(date.valueOf())?'Data indisponível':date.toLocaleString('pt-BR');}
function toast(message,kind='info'){
 const el=document.createElement('div');el.className='toast'+(kind==='danger'?' toast-danger':'');el.textContent=message;
 document.getElementById('toast-stack').appendChild(el);setTimeout(()=>el.remove(),4500);
}
function schedule(action){
 actionQueue=actionQueue.then(action).catch(error=>toast(error.message||'Não foi possível concluir a ação demonstrativa.','danger'));
 return actionQueue;
}
async function sha256Hex(text){
 const digest=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(text));
 return Array.from(new Uint8Array(digest)).map(n=>n.toString(16).padStart(2,'0')).join('');
}
function appendAudit(caseId,event,data){
 const task=auditQueue.catch(()=>{}).then(async()=>{
  const chain=state.audit.filter(e=>e?.case_id===caseId),previous=chain.length?chain[chain.length-1].digest:'0'.repeat(64);
  const created=nowIso(),payload=JSON.stringify(data??{});
  const digest=await sha256Hex(JSON.stringify([caseId,event,payload,created,previous]));
  state.audit.push({id:uid(),case_id:caseId,event,data:payload,created,previous,digest});saveState();
 });
 auditQueue=task;return task;
}
async function verifyChain(caseId){
 let previous='0'.repeat(64);
 for(const e of state.audit.filter(item=>item?.case_id===caseId)){
  if(e.previous!==previous||typeof e.data!=='string'||typeof e.event!=='string'||typeof e.created!=='string')return false;
  const expected=await sha256Hex(JSON.stringify([caseId,e.event,e.data,e.created,previous]));
  if(e.digest!==expected)return false;
  previous=e.digest;
 }
 return true;
}
function closeMenu(){
 document.body.classList.remove('menu-open');document.getElementById('menu-backdrop').hidden=true;
 document.getElementById('menu-toggle').setAttribute('aria-expanded','false');
}
function showView(view){
 currentView=VIEWS.includes(view)?view:'dashboard';document.body.dataset.view=currentView;
 for(const item of VIEWS)document.getElementById('view-'+item).hidden=item!==currentView;
 const selected=['new','tasks','logs'].includes(currentView)?'investigations':currentView;
 for(const button of document.querySelectorAll('.nav-item')){
  const active=button.dataset.view===selected;button.classList.toggle('is-active',active);
  if(active)button.setAttribute('aria-current','page');else button.removeAttribute('aria-current');
 }
 document.getElementById('view-title').textContent=VIEW_TITLES[currentView];closeMenu();return render();
}
function stateBadge(c){
 if(c.state==='CANCELADO')return '<span class="badge badge-cancelled">cancelado</span>';
 if(c.paused)return '<span class="badge badge-paused">pausado</span>';
 const tasks=state.tasks.filter(t=>t.case_id===c.id);
 if(tasks.length&&tasks.every(t=>t.status==='done'))return '<span class="badge badge-completed">Concluída</span>';
 if(tasks.some(t=>t.status==='running'))return '<span class="badge badge-active">Em análise</span>';
 return '<span class="badge badge-active">Em investigação</span>';
}
function filteredCases(){
 const term=search.toLocaleLowerCase('pt-BR');
 return [...state.cases].filter(c=>(c.project+' '+c.id).toLocaleLowerCase('pt-BR').includes(term)).sort((a,b)=>String(b.created).localeCompare(String(a.created)));
}
function populateCaseSelect(){
 const select=document.getElementById('case-select');
 select.innerHTML='<option value="">Selecione uma investigação</option>'+state.cases.map(c=>'<option value="'+escapeHtml(c.id)+'">'+escapeHtml(c.project)+'</option>').join('');
 select.value=getCase(state.activeCase)?state.activeCase:'';
}
function renderDashboard(){
 document.getElementById('stat-total').textContent=String(state.cases.length);
 document.getElementById('stat-running').textContent=String(state.tasks.filter(t=>t.status==='running'&&!getCase(t.case_id)?.paused&&getCase(t.case_id)?.state!=='CANCELADO').length);
 document.getElementById('stat-reports').textContent=String(state.reports.length);
 const cases=filteredCases().slice(0,5);
 document.getElementById('dashboard-recent').innerHTML=cases.length?'<table><thead><tr><th>Investigação</th><th>Etapa</th><th>Status</th></tr></thead><tbody>'+cases.map(c=>{
  const task=state.tasks.filter(t=>t.case_id===c.id).at(-1),stage=task?(TOOL_LABELS[task.tool]||'Análise demonstrativa'):'Planejamento';
  return '<tr><td><button class="project-link" data-case-select="'+escapeHtml(c.id)+'">'+escapeHtml(c.project)+'</button></td><td>'+escapeHtml(stage)+'</td><td>'+stateBadge(c)+'</td></tr>';
 }).join('')+'</tbody></table>':'<div class="empty">'+(search?'Nenhuma investigação encontrada.':'Nenhuma investigação ainda. Crie a primeira demonstração.')+'</div>';
}
function renderInvestigations(){
 const cases=filteredCases();
 document.getElementById('investigations-table').innerHTML=cases.length?'<div class="table-scroll"><table><thead><tr><th>Projeto</th><th>Estado</th><th>Responsável</th><th>Ações</th></tr></thead><tbody>'+cases.map(c=>'<tr data-id="'+escapeHtml(c.id)+'"'+(c.id===state.activeCase?' class="is-selected"':'')+'><td><strong>'+escapeHtml(c.project)+'</strong><span class="item-sub">'+escapeHtml(c.id.slice(0,8))+'</span></td><td>'+stateBadge(c)+'</td><td>'+escapeHtml(c.owner)+'</td><td class="actions"><button class="btn btn-sm" data-act="select">selecionar</button>'+(c.state!=='CANCELADO'?(c.paused?'<button class="btn btn-sm" data-act="resume">retomar</button>':'<button class="btn btn-sm" data-act="pause">pausar</button>')+'<button class="btn btn-sm btn-danger" data-act="cancel">cancelar</button>':'')+'</td></tr>').join('')+'</tbody></table></div>':'<div class="empty">'+(search?'Nenhuma investigação encontrada.':'Nenhuma investigação criada ainda.')+'</div>';
}
function canOrganize(c){return Boolean(c&&c.state!=='CANCELADO'&&!c.paused);}
function renderTasks(){
 const c=getCase(state.activeCase),list=document.getElementById('tasks-list');
 document.querySelector('#form-new-task button[type=submit]').disabled=!canOrganize(c);
 if(!c){list.innerHTML='<div class="empty">Selecione uma investigação acima.</div>';return;}
 const tasks=state.tasks.filter(t=>t.case_id===c.id);
 list.innerHTML=tasks.length?tasks.map(t=>'<div class="item"><div class="item-main"><div class="item-title">'+escapeHtml(TOOL_LABELS[t.tool]||t.tool)+'</div><div class="item-sub">'+escapeHtml(t.path)+' • demonstração</div></div><span class="badge badge-pending">'+escapeHtml(t.status==='done'?'concluída (exemplo)':t.status==='running'?'em análise (exemplo)':'planejada')+'</span></div>').join(''):'<div class="empty">Nenhuma tarefa demonstrativa organizada para esta investigação.</div>';
}
function renderRecovery(){
 const c=getCase(state.activeCase),eligible=Boolean(c&&c.allowRecovery&&c.state!=='CANCELADO');
 document.getElementById('recovery-case-label').textContent=eligible?c.project+' • demonstração local':'Selecione uma investigação com recuperação autorizada.';
 const progress=eligible&&typeof c.illustrativeProgress==='number'?Math.max(0,Math.min(100,c.illustrativeProgress)):0;
 document.getElementById('recovery-percent').textContent=progress+'%';document.getElementById('recovery-progress').style.width=progress+'%';
 document.querySelector('[data-recovery-act=pause]').disabled=!eligible||c.paused;
 document.querySelector('[data-recovery-act=resume]').disabled=!eligible||!c.paused;
 const cases=state.cases.filter(item=>item.allowRecovery);
 document.getElementById('recovery-list').innerHTML=cases.length?cases.map(item=>'<div class="item"><div class="item-main"><button class="project-link" data-case-select="'+escapeHtml(item.id)+'">'+escapeHtml(item.project)+'</button><span class="item-sub">Fluxo demonstrativo • sem tentativas reais</span></div>'+stateBadge(item)+'</div>').join(''):'<div class="empty">Crie uma investigação e marque a permissão de recuperação.</div>';
}
async function renderLogs(version){
 const id=state.activeCase,list=document.getElementById('logs-list'),status=document.getElementById('chain-status');
 if(!id){list.innerHTML='<div class="empty">Selecione uma investigação acima.</div>';status.textContent='';return;}
 const chain=state.audit.filter(e=>e?.case_id===id);
 list.innerHTML=chain.length?[...chain].reverse().map(e=>'<div class="item"><div class="item-main"><div class="item-title">'+escapeHtml(e.event)+'</div><span class="item-sub">'+escapeHtml(dateText(e.created))+' • '+escapeHtml(String(e.digest).slice(0,16))+'…</span></div></div>').join(''):'<div class="empty">Nenhum registro local nesta investigação.</div>';
 const valid=await verifyChain(id);if(version!==renderVersion||id!==state.activeCase)return;
 status.textContent=chain.length?(valid?'Cadeia de registros demonstrativos íntegra':'A cadeia de registros foi alterada'):'Sem registros para verificar.';
 status.className='chain-status '+(chain.length?(valid?'ok':'bad'):'');
}
function buildReportMarkdown(c){
 const tasks=state.tasks.filter(t=>t.case_id===c.id),audit=state.audit.filter(e=>e?.case_id===c.id);
 return ['# Relatório demonstrativo — '+c.project,'','> Dados locais de demonstração. Nenhum arquivo foi analisado por esta interface.','',
 'ID: '+c.id,'Responsável declarado: '+(c.owner||''),'Referência da autorização: '+(c.authorization||''),'Escopo declarado: '+(c.scope||''),'Estado da demonstração: '+c.state+(c.paused?' (pausada)':''),'',
 '## Objetivo',c.objective||'','',
 '## Tarefas demonstrativas',tasks.length?tasks.map(t=>'- '+(TOOL_LABELS[t.tool]||t.tool)+' → '+t.path+' ('+t.status+')').join('\n'):'Nenhuma tarefa.','',
 '## Registros locais',audit.length?audit.map(e=>'- '+e.created+' — '+e.event).join('\n'):'Sem registros.','',
 'Este arquivo não substitui o relatório técnico emitido pelo CORE.',''].join('\n');
}
function renderReports(){
 const c=getCase(state.activeCase);document.getElementById('report-preview').textContent=c?buildReportMarkdown(c):'Selecione uma investigação para pré-visualizar o relatório de demonstração.';
 document.getElementById('gen-report').disabled=!c;
}
async function render(){
 const version=++renderVersion;
 populateCaseSelect();renderDashboard();renderInvestigations();renderTasks();renderRecovery();renderReports();
 const results=await Promise.all(state.cases.map(c=>verifyChain(c.id)));
 if(version===renderVersion)document.getElementById('stat-integrity').textContent=!state.audit.length?'Sem registros':results.every(Boolean)?'Verificada':'Alterada';
 await renderLogs(version);
}
function requiredCase(id){const c=getCase(id);if(!c)throw Error('Selecione uma investigação.');return c;}
async function createCase(fields){
 if(!['project','objective','scope','owner','authorization'].every(k=>typeof fields[k]==='string'&&fields[k].trim()))throw Error('Preencha os dados da investigação.');
 if(!Number.isFinite(fields.validHours)||fields.validHours<1||fields.validHours>8760)throw Error('Informe uma validade entre 1 e 8760 horas.');
 const c={id:uid(),...fields,state:'EM INVESTIGACAO',paused:false,created:nowIso()};
 state.cases.push(c);state.activeCase=c.id;
 await appendAudit(c.id,'investigation_created',{project:c.project,owner:c.owner,demonstration:true});return c;
}
async function pauseCase(id){const c=requiredCase(id);if(c.state==='CANCELADO')throw Error('A investigação está cancelada.');if(c.paused)return;c.paused=true;await appendAudit(id,'investigation_paused',{});}
async function resumeCase(id){const c=requiredCase(id);if(c.state==='CANCELADO')throw Error('Uma investigação cancelada não pode ser retomada.');if(!c.paused)return;c.paused=false;await appendAudit(id,'investigation_resumed',{});}
async function cancelCase(id,reason){
 const c=requiredCase(id);if(c.state==='CANCELADO')return;if(!reason?.trim())throw Error('Informe o motivo do cancelamento.');
 c.state='CANCELADO';c.paused=true;await appendAudit(id,'investigation_cancelled',{reason:reason.trim()});
}
async function enqueueTask(caseId,tool,path){
 const c=requiredCase(caseId);if(!canOrganize(c))throw Error('Retome uma investigação ativa antes de organizar tarefas.');
 if(!Object.hasOwn(TOOL_LABELS,tool)||!path.trim())throw Error('Selecione uma análise e um caminho demonstrativo.');
 const t={id:uid(),case_id:caseId,tool,path,status:'pending',created:nowIso()};state.tasks.push(t);await appendAudit(caseId,'task_enqueued',{tool,path,demonstration:true});return t;
}
function downloadText(filename,text){
 const url=URL.createObjectURL(new Blob([text],{type:'text/markdown;charset=utf-8'})),link=document.createElement('a');
 link.href=url;link.download=filename;document.body.appendChild(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
async function seedExamples(){
 const now=Date.now();
 const example=(id,project,allowRecovery,paused,seconds)=>({id,project,objective:'Exercício sintético para conhecer o painel.',scope:'/laboratorio/exemplos',owner:'Proprietário',authorization:'DEMONSTRAÇÃO — sem execução real',validHours:72,allowRecovery,state:'EM INVESTIGACAO',paused,created:new Date(now-seconds*1000).toISOString()});
 const firmware=example('a'.repeat(32),'Análise de firmware',false,false,0),recovery=example('b'.repeat(32),'Recuperação de arquivo',true,true,60),pcap=example('c'.repeat(32),'Inventário de captura',false,false,120);
 recovery.illustrativeProgress=60;state.cases=[firmware,recovery,pcap];state.activeCase=recovery.id;
 state.tasks=[{id:uid(),case_id:firmware.id,tool:'analyze-firmware',path:'/laboratorio/firmware.bin',status:'running',created:nowIso()},{id:uid(),case_id:recovery.id,tool:'assess-recovery',path:'/laboratorio/arquivo.ccaes',status:'pending',created:nowIso()},{id:uid(),case_id:pcap.id,tool:'inventory-pcap',path:'/laboratorio/captura.pcap',status:'done',created:nowIso()}];
 state.reports=[{case_id:firmware.id,demonstration:true},{case_id:pcap.id,demonstration:true}];
 for(const c of state.cases)await appendAudit(c.id,'demonstration_loaded',{synthetic_only:true});
}
document.addEventListener('DOMContentLoaded',async()=>{
 document.body.dataset.view='dashboard';
 document.getElementById('menu-toggle').addEventListener('click',()=>{
  const open=!document.body.classList.contains('menu-open');document.body.classList.toggle('menu-open',open);
  document.getElementById('menu-backdrop').hidden=!open;document.getElementById('menu-toggle').setAttribute('aria-expanded',String(open));
 });
 document.getElementById('menu-backdrop').addEventListener('click',closeMenu);
 document.addEventListener('keydown',event=>{if(event.key==='Escape'){closeMenu();document.getElementById('menu-toggle').focus();}});
 document.getElementById('case-search').addEventListener('input',event=>{search=event.target.value;renderDashboard();renderInvestigations();});
 document.getElementById('case-select').addEventListener('change',event=>schedule(async()=>{state.activeCase=event.target.value||null;saveState();await render();}));
 document.addEventListener('click',event=>{
  const nav=event.target.closest('[data-view],[data-nav]');
  if(nav&&nav.tagName==='BUTTON'){schedule(()=>showView(nav.dataset.view||nav.dataset.nav));return;}
  const select=event.target.closest('[data-case-select]');
  if(select){schedule(async()=>{state.activeCase=select.dataset.caseSelect;saveState();await showView('investigations');});return;}
  const tool=event.target.closest('[data-demo-tool]');
  if(tool){document.getElementById('task-tool').value=tool.dataset.demoTool;schedule(()=>showView('tasks'));return;}
  const recovery=event.target.closest('[data-recovery-act]');
  if(recovery){schedule(async()=>{if(recovery.dataset.recoveryAct==='pause')await pauseCase(state.activeCase);else await resumeCase(state.activeCase);await render();});return;}
  const action=event.target.closest('button[data-act]');if(!action)return;
  schedule(async()=>{
   const id=action.closest('tr').dataset.id;
   if(action.dataset.act==='select'){state.activeCase=id;saveState();}
   else if(action.dataset.act==='pause')await pauseCase(id);
   else if(action.dataset.act==='resume')await resumeCase(id);
   else if(action.dataset.act==='cancel'){
    const reason=prompt('Motivo do cancelamento (obrigatório):');if(!reason?.trim()){toast('Cancelamento requer um motivo.','danger');return;}
    if(!confirm('Cancelar esta investigação demonstrativa? Essa ação não pode ser desfeita.'))return;
    await cancelCase(id,reason);
   }
   await render();
  });
 });
 document.getElementById('form-new-case').addEventListener('submit',event=>{
  event.preventDefault();const form=event.target;
  schedule(async()=>{
   const fields={};for(const key of ['project','objective','scope','owner','authorization'])fields[key]=document.getElementById('f-'+key).value.trim();
   fields.validHours=Number(document.getElementById('f-valid-hours').value);fields.allowRecovery=document.getElementById('f-recovery').checked;
   await createCase(fields);form.reset();document.getElementById('f-valid-hours').value=72;search='';document.getElementById('case-search').value='';
   toast('Investigação demonstrativa criada.');await showView('investigations');
  });
 });
 document.getElementById('form-new-task').addEventListener('submit',event=>{
  event.preventDefault();schedule(async()=>{await enqueueTask(state.activeCase,document.getElementById('task-tool').value,document.getElementById('task-path').value.trim());
   document.getElementById('task-path').value='';toast('Tarefa demonstrativa organizada. Nenhuma análise foi executada.');await render();});
 });
 document.getElementById('verify-chain').addEventListener('click',()=>schedule(async()=>{requiredCase(state.activeCase);await render();toast('Conferência dos registros locais concluída.');}));
 document.getElementById('gen-report').addEventListener('click',()=>schedule(async()=>{
  const c=requiredCase(state.activeCase);await appendAudit(c.id,'demonstration_report_generated',{demonstration:true});
  state.reports.push({case_id:c.id,created:nowIso(),demonstration:true});saveState();
  downloadText('relatorio-demonstrativo-'+c.id.slice(0,8)+'.md',buildReportMarkdown(c));await render();
 }));
 try{if(firstVisit)await seedExamples();await render();if(storageIssue)toast('Não foi possível carregar os dados anteriores deste navegador.','danger');}
 catch{toast('Não foi possível iniciar a demonstração neste navegador.','danger');}
 document.body.dataset.ready='true';
});
