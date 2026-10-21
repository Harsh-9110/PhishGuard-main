'use strict';
const el=(tag,text,cls)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n;};
const percent=x=>(100*x).toFixed(1)+'%';
async function api(path,options={}){
  const response=await fetch(path,{credentials:'same-origin',...options});
  let data;
  try{data=await response.json();}catch{throw new Error('The service returned an unreadable response.');}
  if(!response.ok)throw new Error(data.error?.message||'The service is unavailable.');
  return data;
}
function showError(error){const n=document.getElementById('error');n.textContent=error.message;n.hidden=false;}
function renderResult(data){
  const root=document.getElementById('result');root.replaceChildren();root.hidden=false;
  const verdict=el('section',undefined,'verdict'+(data.is_phishing?' flagged':''));
  verdict.append(el('h2',data.is_phishing?'Potential phishing risk':'Lower risk detected'));
  verdict.append(el('div',data.url,'url'));
  const score=el('div',percent(data.risk_score),'score');score.append(el('small','mean ML phishing score'));verdict.append(score);
  verdict.append(el('p',data.content_flag?'Page evidence flagged a password form submitting to another hostname. Review the destination carefully.':'Verdict from '+data.aggregation.replaceAll('_',' ')+'. Review the supporting signals below.'));
  verdict.append(el('p',data.notice,'hint'));root.append(verdict);
  const grid=el('div',undefined,'result-grid');
  const models=el('section',undefined,'panel');models.append(el('h3','Individual model scores'));
  for(const value of Object.values(data.models)){
    const row=el('div',undefined,'model');row.append(el('strong',value.label));
    row.append(el('p',percent(value.phishing_probability)+' phishing score · '+percent(value.confidence)+' predicted-class confidence'));
    row.append(el('span',value.prediction?'Phishing prediction':'Legitimate prediction','badge'));models.append(row);
  }
  grid.append(models);
  const signals=el('section',undefined,'panel');signals.append(el('h3','Observed page & URL evidence'));
  const list=el('ul',undefined,'signals');for(const s of data.signals)list.append(el('li',s.message));
  if(!data.signals.length)list.append(el('li','No listed warning patterns were detected. This does not establish safety.'));
  signals.append(list,el('p',data.content.form_count+' form(s) · '+data.content.word_count+' visible word(s) · '+data.page.redirects+' redirect(s)','hint'));
  if(data.final_url!==data.url)signals.append(el('p','Final address: '+data.final_url,'url'));grid.append(signals);
  const chart=el('section',undefined,'panel wide');chart.append(el('h3','What the trained models use most'));
  const max=Math.max(...data.feature_importance.map(x=>x.importance),.0001);
  for(const feature of data.feature_importance){const row=el('div',undefined,'chart-row');row.append(el('span',feature.feature.replaceAll('_',' '),'chart-label'));const bar=el('div',undefined,'bar');const fill=el('span',undefined,'bar-fill');fill.style.width=(100*feature.importance/max)+'%';bar.append(fill);row.append(bar,el('span',percent(feature.importance)));chart.append(row);}
  chart.append(el('p','Global mean learned feature importance across the three models. It is not a causal explanation of this individual result.','chart-note'));grid.append(chart);root.append(grid);
  const actions=el('div',undefined,'result-actions');const link=el('a','Open saved analysis');link.href='/results?id='+encodeURIComponent(data.id);actions.append(link,el('span',new Date(data.created_at).toLocaleString()+' · '+data.model_version));root.append(actions);
}
async function init(){
  try{await api('/healthz');document.getElementById('health').textContent='Service ready';}catch{document.getElementById('health').textContent='Service unavailable';}
  const page=document.body.dataset.page;
  if(page==='check'){
    document.getElementById('scan-form').addEventListener('submit',async event=>{
      event.preventDefault();document.getElementById('error').hidden=true;
      const button=document.getElementById('scan-button');button.disabled=true;document.getElementById('progress').hidden=false;document.getElementById('result').hidden=true;
      const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),20000);
      try{const data=await api('/api/check',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:document.getElementById('url').value}),signal:controller.signal});renderResult(data);}catch(error){showError(error.name==='AbortError'?new Error('The scan timed out. Try again.'):error);}finally{clearTimeout(timer);button.disabled=false;document.getElementById('progress').hidden=true;}
    });
  }else if(page==='history'){
    try{const data=await api('/api/history');const root=document.getElementById('history-list');root.replaceChildren();if(!data.results.length)root.append(el('p','No saved scans for this browser yet.'));
      for(const scan of data.results){const row=el('article',undefined,'history-item');const info=el('div');info.append(el('div',scan.is_phishing?'Potential phishing risk':'Lower risk','history-title'),el('div',scan.url,'url'),el('time',new Date(scan.created_at).toLocaleString()));const link=el('a','View analysis →');link.href='/results?id='+encodeURIComponent(scan.id);row.append(info,link);root.append(row);}
    }catch(error){showError(error);document.getElementById('history-list').textContent='History could not be loaded.';}
  }else if(page==='result'){
    try{const id=new URLSearchParams(location.search).get('id');if(!id)throw new Error('No saved analysis was selected.');renderResult(await api('/api/results/'+encodeURIComponent(id)));}catch(error){showError(error);document.getElementById('result').replaceChildren();}
  }else if(page==='about'){
    try{const info=await api('/api/model-info');const container=document.getElementById('model-metrics');container.replaceChildren();container.append(el('p',info.test_rows.toLocaleString()+' held-out rows · grouped split · '+info.aggregation.replaceAll('_',' ')));const table=el('table');const header=el('tr');for(const title of ['Model','Accuracy','F1','ROC-AUC'])header.append(el('th',title));table.append(header);for(const [name,m]of Object.entries(info.metrics)){const row=el('tr');for(const text of [name.replaceAll('_',' '),percent(m.accuracy),m.f1.toFixed(4),m.roc_auc.toFixed(4)])row.append(el('td',text));table.append(row);}container.append(table);}catch(error){document.getElementById('model-metrics').textContent=error.message;}
  }
}
init();
