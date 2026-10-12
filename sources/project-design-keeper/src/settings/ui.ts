/** Self-contained local UI: no remote scripts, fonts, accounts, or telemetry. */
export function settingsHtml(nonce: string): string {
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Keeper 设置</title>
<style nonce="${nonce}">:root{font-family:system-ui,sans-serif;color:#e5eaf2;background:#111722;color-scheme:dark}body{max-width:640px;margin:8vh auto;padding:24px}main{background:#1b2433;border:1px solid #39465d;border-radius:18px;padding:30px}h1{font-size:28px;margin-top:0}p{line-height:1.7;color:#b8c4d6}label{display:block;font-weight:650;margin:24px 0 10px}input[type=checkbox]{width:22px;height:22px;vertical-align:middle;margin-right:12px;accent-color:#80b8ff}input[type=number]{width:100px;padding:10px;border:1px solid #68778f;border-radius:6px;font-size:17px}button{margin:18px 10px 0 0;padding:12px 16px;border-radius:7px;border:1px solid #8298b5;font:inherit;cursor:pointer}button[type=submit]{background:#9ac5ff;color:#11213a}button:disabled{opacity:.5;cursor:wait}:focus-visible{outline:3px solid #ffc85c;outline-offset:4px}#status{min-height:3em;white-space:pre-wrap}#current{border-top:1px solid #39465d;padding-top:18px;font-size:14px}.error{color:#ffadad!important}</style></head>
<body><main><h1>Keeper 设置</h1><p>作用域：本机当前用户的 Keeper 安装，跨项目与任务保留。保存后在下一次操作生效，正在执行的操作继续使用原设置。</p>
<form id="settings"><fieldset id="fields" disabled><legend>更新策略</legend><label><input id="easy" type="checkbox" role="switch">Easy 模式</label><p>跳过 Keeper 人工确认；自动校验、冲突检查和恢复保护仍保留。宿主自己的工具权限不受影响。</p><label for="limit">单次更新合计上限（MiB）</label><input id="limit" type="number" min="1" max="64" step="1" required value="8" aria-describedby="range"><p id="range">1–64 的整数。按本次全部待写入文件的最终 UTF-8 内容计量。</p><p id="single">普通模式：单文件上限 2 MiB。</p><button type="submit">保存设置</button><button type="button" id="reset">恢复默认值</button></fieldset></form>
<p id="current">正在读取当前生效设置…</p><p id="status" role="status" aria-live="polite"></p></main>
<script nonce="${nonce}">"use strict";
const easy=document.getElementById('easy'),limit=document.getElementById('limit'),fields=document.getElementById('fields'),status=document.getElementById('status'),current=document.getElementById('current');
const fragment=location.hash.slice(1),key='keeper-settings-session';
let token=fragment||sessionStorage.getItem(key)||'';
if(fragment){sessionStorage.setItem(key,fragment);history.replaceState(null,'',location.pathname);}
let revision='',saved=null;
function note(message,error=false){status.textContent=message;status.className=error?'error':'';}
function explain(){document.getElementById('single').textContent=easy.checked?'Easy 模式：无独立单文件上限，受本次合计上限约束。':'普通模式：单文件上限 2 MiB。';}
function changed(){explain();note(saved&&(easy.checked!==saved.easyMode||Number(limit.value)!==saved.maxUpdateMiB)?'有未保存的更改。':'当前设置已保存。');}
function display(value){revision=value.revision;saved=value;easy.checked=value.easyMode;limit.value=String(value.maxUpdateMiB);current.textContent='当前生效：'+(value.easyMode?'Easy 模式':'普通模式')+' · 合计 '+value.maxUpdateMiB+' MiB';explain();}
async function request(method,body){const response=await fetch('/api/settings',{method,headers:{'content-type':'application/json','x-keeper-settings-session':token},body:body?JSON.stringify(body):undefined,cache:'no-store'});const data=await response.json();if(!response.ok)throw new Error(data.error||'请求失败');return data;}
easy.addEventListener('change',changed);limit.addEventListener('input',changed);
document.getElementById('reset').addEventListener('click',()=>{easy.checked=false;limit.value='8';explain();note('已填入默认值；点击“保存设置”后生效。');});
document.getElementById('settings').addEventListener('submit',async(event)=>{event.preventDefault();if(!event.isTrusted)return;const amount=Number(limit.value);if(!Number.isInteger(amount)||amount<1||amount>64){note('请输入 1–64 的整数。',true);return;}fields.disabled=true;note('正在保存…');try{display(await request('POST',{expectedRevision:revision,values:{easyMode:easy.checked,maxUpdateMiB:amount}}));note('保存成功。下一次操作将使用这些设置。');}catch(error){note(error.message,true);}finally{fields.disabled=false;}});
(async()=>{try{display(await request('GET'));fields.disabled=!token;note(token?'当前设置已保存。':'此链接为只读页面。请在聊天中调用“打开 Keeper 设置”，使用自动打开的浏览器页面编辑。',!token);}catch(error){note(error.message,true);}})();
</script></body></html>`;
}
