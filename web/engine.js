// Same-origin adapter for the private remote CORE. Never sends provider keys.
'use strict';
class CoreConnection{
 constructor(health){this.token=health.token;this.capabilities=health.capabilities;this.online=true;this.reportCache=new Map();}
 static async open(){
  const required=document.querySelector('meta[name="cyber-engine"]')?.content==='required';
  try{
   const response=await fetch('/api/health',{cache:'no-store',signal:AbortSignal.timeout(5000)});
   if(!response.ok)throw Error('Motor indisponível');
   const health=await response.json();
   if(health.service!=='cyber-core'||health.version!==1||typeof health.token!=='string')throw Error('Motor incompatível');
   return new CoreConnection(health);
  }catch(error){if(required)throw error;return null;}
 }
 async request(path,data){
  let response;
  try{response=await fetch('/api'+path,{method:data===undefined?'GET':'POST',cache:'no-store',
   headers:{'X-Cyber-Request':this.token,...(data===undefined?{}:{'Content-Type':'application/json'})},
   body:data===undefined?undefined:JSON.stringify(data),signal:AbortSignal.timeout(15000)});
  }catch{this.online=false;connectionNotice(false);throw Error('Conexão com o motor interrompida. Reabra o Codespace e atualize o painel.');}
  let result;
  try{result=await response.json();}catch{this.online=false;connectionNotice(false);throw Error('Reabra o painel pelo Codespace para restabelecer a conexão.');}
  if(!response.ok){
   if(response.status===403||response.status>=500){this.online=false;this.needsReload=response.status===403;connectionNotice(false);}
   throw Error(result.error||'O motor recusou a operação.');
  }
  this.online=true;connectionNotice(true);return result;
 }
}
function connectionNotice(online){
 document.body.dataset.connection=online?'online':'offline';
 document.querySelector('#demo-notice p').textContent=online?
 'Motor conectado. Arquivos enviados são analisados pelo CORE no ambiente remoto. Limite de 4 MiB por arquivo. Mantenha a porta do Codespace privada.':
 'Conexão interrompida. As ações estão bloqueadas até o motor voltar. Os dados demonstrativos não serão usados.';
 if(!online)document.querySelector('#form-new-task button[type=submit]').disabled=true;
}
async function refreshEngine(){
 const snapshot=await liveClient.request('/state'),selected=state.activeCase;
 state={...snapshot,activeCase:snapshot.cases.some(c=>c.id===selected)?selected:(snapshot.cases[0]?.id||null)};
}
async function liveAction(id,action,data={}){
 requiredCase(id);await liveClient.request('/cases/'+encodeURIComponent(id)+'/'+action,data);await refreshEngine();
}
async function sendEngineFile(id,tool){
 if(!canOrganize(requiredCase(id)))throw Error('Selecione uma investigação ativa e aguarde o motor.');
 const file=document.getElementById('task-file').files[0];
 if(!file)throw Error('Escolha o arquivo autorizado.');
 if(file.size>liveClient.capabilities.max_file_bytes)throw Error('O limite por arquivo é 4 MiB.');
 const payload={};
 if(tool==='recover-password'){
  if(document.getElementById('task-wordlist-builtin').checked){
   payload.wordlist='rockyou';
  }else{
   const candidates=document.getElementById('task-candidates').value.split('\n').map(line=>line.replace(/\r$/,'')).filter(Boolean);
   if(!candidates.length)throw Error('Informe ao menos uma senha candidata (uma por linha) ou marque a lista embutida.');
   if(candidates.length>5000)throw Error('No máximo 5000 senhas candidatas por envio.');
   payload.candidates=candidates;
  }
 }
 const content=await new Promise((resolve,reject)=>{
  const reader=new FileReader();reader.onload=()=>resolve(String(reader.result).split(',')[1]||'');
  reader.onerror=()=>reject(Error('Não foi possível ler o arquivo selecionado.'));reader.readAsDataURL(file);
 });
 await liveClient.request('/cases/'+id+'/files',{name:file.name,tool,content_base64:content,...payload});
 document.getElementById('task-file').value='';document.getElementById('task-candidates').value='';
 document.getElementById('task-wordlist-builtin').checked=false;await refreshEngine();
}
function renderEngineResults(){
 const c=getCase(state.activeCase),element=document.getElementById('engine-results');
 if(!c){element.innerHTML='<p>Selecione uma investigação.</p>';return;}
 const results=state.results[c.id]||[],operations=state.operations[c.id]||[];
 element.innerHTML=results.length?results.map(result=>'<article class="engine-result"><strong>'+escapeHtml(result.format||'Resultado')+
  '</strong><p>SHA-256: <span class="mono">'+escapeHtml(result.sha256)+'</span></p><p>'+escapeHtml(result.size)+' bytes • cópia verificada: '+(result.copy_verified?'sim':'não confirmada')+
  '</p><details><summary>Detalhes técnicos</summary><pre>'+escapeHtml(JSON.stringify(result,null,2))+'</pre></details></article>').join(''):'<p>Nenhuma análise concluída nesta investigação.</p>';
 if(operations.length)element.innerHTML+='<h3>Inventários</h3><pre>'+escapeHtml(JSON.stringify(operations,null,2))+'</pre>';
 if(state.recovery_result){
  const r=state.recovery_result;
  element.innerHTML+=r.recovered?
   '<article class="engine-result recovery-found"><strong>Senha encontrada</strong><p class="mono">'+escapeHtml(r.password)+'</p><p>formato: '+escapeHtml(r.format_id||'?')+' • '+escapeHtml(r.attempts)+' tentativa(s)</p></article>':
   r.status==='unsupported_format'?
   '<article class="engine-result"><strong>Formato ainda não suportado</strong><p>'+escapeHtml(r.note||'')+'</p></article>':
   '<article class="engine-result"><strong>Senha não encontrada na lista enviada</strong><p>'+escapeHtml(r.attempts)+' tentativa(s) • '+escapeHtml(r.status)+'</p></article>';
 }
 if(state.result_errors?.[c.id])element.innerHTML+='<p role="alert">'+escapeHtml(state.result_errors[c.id])+'</p>';
 if(state.last_error)element.innerHTML+='<p role="alert">'+escapeHtml(state.last_error)+'</p>';
 document.getElementById('engine-run-pending').disabled=!canOrganize(c)||!state.tasks.some(t=>t.case_id===c.id&&t.status==='pending');
}
function prepareEngineUI(){
 document.body.dataset.engine='connected';
 const changes={
  'Interface de demonstração':'Conectado ao CORE',
  'Ambiente de demonstração':'Motor conectado',
  'Organize um caso de demonstração. Nenhum arquivo será lido ou enviado.':'Crie uma investigação e declare a autorização para os arquivos que você enviará.',
  'Escopo (caminho autorizado)':'Escopo dos arquivos enviados',
  'Verifique a integridade dos registros desta demonstração. Essa conferência não valida arquivos ou evidências do CORE.':'Consulte a auditoria persistente e a verificação de integridade feita pelo CORE.',
  'Exporte os dados demonstrativos desta investigação. O relatório técnico do CORE é separado.':'Gere e baixe o relatório técnico com os resultados persistidos pelo CORE.',
  'Aqui você organiza a demonstração. Nenhuma tentativa é executada.':'Neste painel, envie um arquivo com a análise “Avaliar recuperação”. Sessões de tentativa de chaves ainda são operadas pela CLI, fora deste fluxo.',
  'Organizar tarefa demonstrativa':'Enviar arquivo para análise',
  'Consulte os registros locais e seus hashes. Eles representam esta demonstração e não substituem custódia forense ou o relatório do CORE.':'Consulte os registros e hashes persistidos pelo CORE e gere o relatório da investigação.',
  'Prévia visual • dados demonstrativos • sem execução real':'Beta pessoal • execução remota no CORE • arquivos autorizados',
  'Disponibilidade no ambiente de execução não consultada por esta prévia.':'Disponibilidade verificada na configuração deste ambiente remoto.',
 };
 const walker=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT),nodes=[];
 while(walker.nextNode())nodes.push(walker.currentNode);
 for(const node of nodes){const replacement=changes[node.nodeValue.trim()];if(replacement)node.nodeValue=replacement;}
 document.querySelector('.data-label').innerHTML='Dados do CORE <span>• ambiente remoto</span>';
 const scope=document.getElementById('f-scope');scope.value=scope.defaultValue='Arquivos enviados nesta investigação';scope.readOnly=true;
 document.getElementById('task-path').hidden=true;document.getElementById('task-path').required=false;
 document.getElementById('task-file').hidden=false;document.getElementById('task-file').required=true;
 document.querySelector('#form-new-task button[type=submit]').textContent='Enviar e analisar';
 for(const option of [...document.getElementById('task-tool').options])if(!['analyze-file','analyze-firmware','assess-recovery','recover-password','inventory-disk','inventory-pcap'].includes(option.value))option.remove();
 document.querySelector('#task-tool option[value="assess-recovery"]').textContent='Avaliar recuperação (sem tentar senha)';
 document.getElementById('task-tool').addEventListener('change',event=>{
  const recovering=event.target.value==='recover-password';
  document.getElementById('task-candidates').hidden=!recovering;
  document.getElementById('task-wordlist-builtin-label').hidden=!recovering;
 });
 const recoveringNow=document.getElementById('task-tool').value==='recover-password';
 document.getElementById('task-candidates').hidden=!recoveringNow;
 document.getElementById('task-wordlist-builtin-label').hidden=!recoveringNow;
 document.getElementById('task-wordlist-builtin').addEventListener('change',event=>{
  document.getElementById('task-candidates').disabled=event.target.checked;
 });
 document.getElementById('engine-results-card').hidden=false;
 document.getElementById('engine-run-pending').hidden=false;
 document.getElementById('engine-refresh').hidden=false;
 document.querySelector('.progress-heading').hidden=true;document.querySelector('.progress-track').hidden=true;
 for(const row of document.querySelectorAll('.capability-row')){
  const name=row.querySelector('span')?.textContent?.toLowerCase();
  if(name==='ghidra'||name==='binwalk')row.querySelector('.badge').textContent=liveClient.capabilities[name]?'Configurado neste ambiente':'Indisponível neste ambiente';
 }
 document.getElementById('engine-refresh').addEventListener('click',()=>schedule(async()=>{await refreshEngine();await render();}));
 document.getElementById('engine-run-pending').addEventListener('click',()=>schedule(async()=>{await liveAction(state.activeCase,'run');await render();}));
 connectionNotice(true);
 setInterval(()=>{if(!liveClient.needsReload&&(state.busy||!liveClient.online))schedule(async()=>{await refreshEngine();await render();});},1500);
}
