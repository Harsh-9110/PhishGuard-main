'use strict';
const $=id=>document.getElementById(id);
let settings={};
async function request(path,body){
  if(!settings.apiBase)throw new Error('Save and authorize your API URL first.');
  const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),20000);
  try{
    const response=await fetch(settings.apiBase+path,{method:body?'POST':'GET',headers:{'Content-Type':'application/json','X-Client-Key':settings.clientKey},body:body?JSON.stringify(body):undefined,signal:controller.signal});
    const data=await response.json();
    if(!response.ok)throw new Error(data.error?.message||'API request failed.');
    return data;
  }finally{clearTimeout(timer);}
}
function status(error){$('status').textContent=error?.message||error||'';}
async function initialize(){
  settings=await chrome.storage.local.get(['apiBase','clientKey']);
  if(!settings.clientKey){settings.clientKey=Array.from(crypto.getRandomValues(new Uint8Array(32)),x=>x.toString(16).padStart(2,'0')).join('');await chrome.storage.local.set({clientKey:settings.clientKey});}
  $('base').value=settings.apiBase||'http://127.0.0.1:5000';
  $('origin').textContent='Allow this exact origin in the API settings: '+location.origin;
  $('save').addEventListener('click',async()=>{
    try{const url=new URL($('base').value);if(url.username||url.password||!['http:','https:'].includes(url.protocol))throw new Error('Enter an HTTP(S) API URL without credentials.');if(url.protocol!=='https:'&&!['localhost','127.0.0.1','[::1]'].includes(url.hostname))throw new Error('Use HTTPS for a remote API.');const granted=await chrome.permissions.request({origins:[url.origin+'/*']});if(!granted)throw new Error('API host permission was not granted.');settings.apiBase=url.origin;await chrome.storage.local.set({apiBase:settings.apiBase});status('API saved. Ensure ALLOWED_ORIGINS includes this extension origin.');}catch(error){status(error);}
  });
  $('check').addEventListener('click',async()=>{
    $('check').disabled=true;status('Analyzing…');$('result').hidden=true;
    try{const [tab]=await chrome.tabs.query({active:true,currentWindow:true});if(!tab?.url||!/^https?:\/\//i.test(tab.url))throw new Error('Open a public HTTP(S) website first.');const data=await request('/api/check',{url:tab.url});$('verdict').textContent=data.is_phishing?'Potential phishing risk':'Lower risk detected';$('score').textContent=(100*data.risk_score).toFixed(1)+'% mean ML phishing score';$('models').replaceChildren();for(const m of Object.values(data.models)){const li=document.createElement('li');li.textContent=m.label+': '+(m.phishing_probability*100).toFixed(1)+'% phishing score';$('models').append(li);}$('signals').replaceChildren();for(const s of data.signals){const li=document.createElement('li');li.textContent=s.message;$('signals').append(li);}$('result').hidden=false;status('Scan completed and saved.');}catch(error){status(error.name==='AbortError'?'The request timed out.':error);}finally{$('check').disabled=false;}
  });
  $('history').addEventListener('click',async()=>{try{const data=await request('/api/history');$('history-list').replaceChildren();for(const scan of data.results){const li=document.createElement('li');li.textContent=(scan.is_phishing?'Flagged: ':'Lower risk: ')+scan.url;$('history-list').append(li);}if(!data.results.length)status('No saved scans for this extension.');}catch(error){status(error);}});
}
initialize().catch(status);
