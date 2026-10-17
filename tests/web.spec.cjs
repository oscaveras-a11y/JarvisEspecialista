const {test,expect}=require('@playwright/test');
test.beforeEach(async({page})=>{const response=await page.goto('/web/');expect(response.ok()).toBe(true);await expect(page.locator('body')).toHaveAttribute('data-ready','true');});
test('approved dashboard is usable without implying real execution',async({page})=>{
 await expect(page.getByRole('heading',{name:'Clareza para cada investigação.'})).toBeVisible();
 await expect(page.getByText('Ambiente de demonstração',{exact:true})).toBeVisible();
 await expect(page.locator('#stat-total')).toHaveText('3');
 await expect(page.locator('#agents-summary')).toContainText('Aguardando configuração');
 await expect(page.locator('#demo-notice')).toContainText('Nenhum arquivo é analisado');
 await page.screenshot({path:'test-results/dashboard-desktop.png',fullPage:true});
});
test('navigation, search and accessible mobile menu expose their real views',async({page})=>{
 await page.getByLabel('Buscar investigação').fill('Recuperação');
 await expect(page.locator('#dashboard-recent')).toContainText('Recuperação de arquivo');
 await expect(page.locator('#dashboard-recent')).not.toContainText('Análise de firmware');
 await page.getByLabel('Buscar investigação').fill('resultado inexistente');
 await expect(page.locator('#dashboard-recent')).toContainText('Nenhuma investigação encontrada');
 await page.setViewportSize({width:390,height:844});
 await page.getByRole('button',{name:'Abrir menu'}).click();
 await page.getByRole('navigation',{name:'Navegação principal'}).getByRole('button',{name:'Ferramentas',exact:true}).click();
 await expect(page.locator('#view-tools')).toBeVisible();
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
 await page.getByLabel('Buscar investigação').fill('');
 await page.getByRole('button',{name:'Abrir menu'}).click();
 await page.getByRole('navigation',{name:'Navegação principal'}).getByRole('button',{name:'Visão geral',exact:true}).click();
 await expect(page.locator('#sidebar')).toBeHidden();
 await page.screenshot({path:'test-results/dashboard-mobile.png',fullPage:true});
});
test('a declared demonstration case persists and blocks tasks while paused or cancelled',async({page})=>{
 await page.getByRole('button',{name:'Nova investigação',exact:true}).first().click();
 for(const [id,value]of Object.entries({'f-project':'Prévia autorizada','f-objective':'Exercício sintético','f-scope':'/laboratorio','f-owner':'Proprietário','f-authorization':'Demonstração'}))await page.locator('#'+id).fill(value);
 await page.locator('#f-recovery').check();
 await page.getByRole('button',{name:'Criar investigação'}).click();
 const row=page.locator('#investigations-table tr').filter({hasText:'Prévia autorizada'});
 await expect(row).toBeVisible();
 await page.reload();
 await page.getByRole('navigation',{name:'Navegação principal'}).getByRole('button',{name:'Investigações',exact:true}).click();
 await expect(row).toBeVisible();
 await row.getByRole('button',{name:'pausar',exact:true}).click();
 await expect(row).toContainText('pausado');
 await page.getByRole('button',{name:'Tarefas e progresso',exact:true}).click();
 await expect(page.locator('#form-new-task button[type=submit]')).toBeDisabled();
 await page.getByRole('navigation',{name:'Navegação principal'}).getByRole('button',{name:'Investigações',exact:true}).click();
 await row.getByRole('button',{name:'retomar',exact:true}).click();
 page.on('dialog',dialog=>dialog.type()==='prompt'?dialog.accept('Encerrar exercício'):dialog.accept());
 await row.getByRole('button',{name:'cancelar',exact:true}).click();
 await expect(row).toContainText('cancelado');
 await expect(row.getByRole('button',{name:'retomar',exact:true})).toHaveCount(0);
 await page.getByRole('button',{name:'Tarefas e progresso',exact:true}).click();
 await expect(page.locator('#form-new-task button[type=submit]')).toBeDisabled();
});
test('legacy browser cases remain readable and user strings remain plain text',async({page})=>{
 await page.evaluate(()=>localStorage.setItem('cybercore.ui.v1',JSON.stringify({
 cases:[{id:'12345678901234567890123456789012',project:'<img src=x onerror=window.injected=1>',objective:'legacy',scope:'/lab',owner:'owner',authorization:'synthetic',validHours:72,allowRecovery:true,state:'EM INVESTIGACAO',paused:false,created:new Date().toISOString()}],
 tasks:[],audit:[],activeCase:'12345678901234567890123456789012'})));
 await page.reload();
 await expect(page.locator('#stat-total')).toHaveText('1');
 await expect(page.locator('#dashboard-recent')).toContainText('<img src=x onerror=window.injected=1>');
 await expect(page.locator('#dashboard-recent img')).toHaveCount(0);
 expect(await page.evaluate(()=>window.injected)).toBeUndefined();
});
test('report download is explicitly demonstrative and contains actual line breaks',async({page})=>{
 await page.getByRole('navigation',{name:'Navegação principal'}).getByRole('button',{name:'Relatórios',exact:true}).click();
 const download=page.waitForEvent('download');
 await page.getByRole('button',{name:'Gerar e baixar relatório'}).click();
 const stream=await(await download).createReadStream();
 const chunks=[];for await(const chunk of stream)chunks.push(chunk);
 const text=Buffer.concat(chunks).toString('utf8');
 expect(text).toContain('\n## Objetivo\n');
 expect(text).toContain('demonstração');
 expect(text).not.toContain('\\n## Objetivo');
});
test('audit verifier detects a modified predecessor and handles concurrent events',async({page})=>{
 const result=await page.evaluate(async()=>{
 const id=state.activeCase;
 await Promise.all([appendAudit(id,'demo_a',{}),appendAudit(id,'demo_b',{})]);
 const intact=await verifyChain(id);const entries=state.audit.filter(e=>e.case_id===id);
 entries[entries.length-1].previous='f'.repeat(64);
 return {intact,modified:await verifyChain(id)};});
 expect(result).toEqual({intact:true,modified:false});
});
test('application only loads local assets and all module views remain navigable',async({page})=>{
 const external=[],errors=[];
 page.on('request',request=>{if(!request.url().startsWith('http://127.0.0.1:4173/')&&!request.url().startsWith('data:'))external.push(request.url());});
 page.on('pageerror',error=>errors.push(error.message));
 await page.reload();
 for(const[label,id]of [['Recuperação','recovery'],['Perícia digital','forensics'],['Ferramentas','tools'],['Agentes','agents']]){
 await page.getByRole('navigation',{name:'Navegação principal'}).getByRole('button',{name:label,exact:true}).click();
 await expect(page.locator('#view-'+id)).toBeVisible();}
 expect(external).toEqual([]);expect(errors).toEqual([]);
});
test('mobile navigation hides closed links, restores focus and adapts to desktop',async({page})=>{
 await page.setViewportSize({width:390,height:844});
 const sidebar=page.locator('#sidebar'),toggle=page.getByRole('button',{name:'Abrir menu'});
 await expect(sidebar).toBeHidden();
 await toggle.focus();await page.keyboard.press('Tab');
 await expect(page.getByLabel('Buscar investigação')).toBeFocused();
 await toggle.click();
 await expect(sidebar).toBeVisible();
 await expect(page.getByRole('link',{name:'CYBER CORE, início'})).toBeFocused();
 await page.keyboard.press('Shift+Tab');await expect(toggle).toBeFocused();
 await page.keyboard.press('Tab');await expect(page.getByRole('link',{name:'CYBER CORE, início'})).toBeFocused();
 await page.getByRole('navigation',{name:'Navegação principal'}).getByRole('button',{name:'Ferramentas',exact:true}).click();
 await expect(page.locator('#view-tools')).toBeVisible();
 await expect(sidebar).toBeHidden();await expect(toggle).toBeFocused();
 await toggle.click();await page.keyboard.press('Escape');
 await expect(sidebar).toBeHidden();await expect(toggle).toBeFocused();
 await page.setViewportSize({width:1584,height:992});
 await expect(sidebar).toBeVisible();
 const tools=page.getByRole('navigation',{name:'Navegação principal'}).getByRole('button',{name:'Ferramentas',exact:true});
 await tools.focus();await expect(tools).toBeFocused();
 await page.keyboard.press('Escape');await expect(tools).toBeFocused();
 await page.setViewportSize({width:390,height:844});
 await expect(sidebar).toBeHidden();await expect(toggle).toBeFocused();
 await toggle.click();await page.setViewportSize({width:1584,height:992});
 await expect(sidebar).toBeVisible();await expect(page.locator('#menu-backdrop')).toBeHidden();
 await tools.focus();await expect(tools).toBeFocused();
});
