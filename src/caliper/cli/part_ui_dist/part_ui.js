"use strict";(()=>{async function y(e,t){let s=await fetch(e,t);if(!s.ok){let r="";try{r=(await s.json())?.error??""}catch{}throw new Error(r||`HTTP ${s.status}`)}return await s.json()}function g(e,t){return y(e,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(t)})}function C(){return y("/cutlist")}function R(e,t,s=""){return g("/reclassify",{glob:e,bucket:t,note:s})}function x(){return y("/repart",{method:"POST"})}function P(e){return g("/repart",{size_cap:e})}function _(){return y("/suggest",{method:"POST"})}function E(e){return g("/suggest/apply",{globs:e})}function j(e,t){return g("/range",{base:e,head:t})}function S(e){return g("/pr",{ref:e})}function H(e){return g("/restack",e)}function z(e){return g("/apply",{apply_token:e})}function M(){return y("/rollback",{method:"POST"})}function O(e){return e.targeted!==!1}var A=["frontend","business","data","infra","documentation","supply_chain","ci_cd","security_policy","config","schema_contracts","test","generated","logic"],L="logic";var p=null,l=null,d=null,T=!1,v=!1,h=null,c=null,b=!1,m=null,k=null;function a(e){let t=document.createElement("div");return t.textContent=e,t.innerHTML}function f(e){return a(e).replace(/"/g,"&quot;")}function I(e){return e?e.slice(0,9):"\u2014"}function D(e){let t=e.lastIndexOf("/");return t===-1?"":e.slice(0,t)}function J(e){let t=D(e);return t?`${t}/**`:"**"}function B(e){let t=new Set(e.parts.map(i=>i.bucket)).size,s=e.size_cap==null?"none (1 part/bucket)":String(e.size_cap),r=I(e.provenance.base_sha),n=I(e.provenance.head_sha);return`
    <header class="cut-header">
      <h1>caliper cut list</h1>
      <p class="sub">${e.stats.part_count} parts across ${t} bucket${t===1?"":"s"}
        &middot; ${e.stats.file_count} files &middot; cap ${s} &middot; ${r} \u2192 ${n}</p>
    </header>`}function F(e){return e.length===0?'<div class="overrides empty">no overrides yet \u2014 reclassify a file below</div>':`<div class="overrides"><h2>active overrides</h2>${e.map(s=>`<span class="ov"><code>${a(s.glob)}</code> \u2192 <b>${a(s.bucket)}</b></span>`).join("")}</div>`}function G(){return l?l.configured?l.suggestions.length===0?'<p class="muted">no tier suggestions \u2014 the residual is empty or the model found nothing.</p>':`
    <div class="suggestions">
      <ul class="chips">${l.suggestions.map(t=>`
      <li class="chip">
        <code>${a(t.glob)}</code> \u2192 <b>${a(t.bucket)}</b>
        <button type="button" class="btn-sm" data-action="suggest-accept"
          data-glob="${f(t.glob)}" data-bucket="${f(t.bucket)}"
          data-note="${f(t.note??"")}">accept</button>
      </li>`).join("")}</ul>
      <button type="button" class="btn" data-action="suggest-accept-all">
        accept all (${l.suggestions.length})
      </button>
    </div>`:'<p class="muted">tier suggester not configured (no local model reachable).</p>':'<button type="button" class="btn" data-action="suggest">\u2728 suggest tiers</button>'}function V(){let e=`
    <div class="restack-form">
      <label><input type="checkbox" class="restack-describe" /> describe (local model)</label>
      <label><input type="checkbox" class="restack-force" /> force (skip already-pushed check)</label>
      <select class="field restack-target" aria-label="restack target shape">
        <option value="">target: config default</option>
        <option value="stack">target: stack</option>
        <option value="series">target: series</option>
      </select>
      <button type="button" class="btn" data-action="generate-restack">generate restack script</button>
    </div>`;if(!c)return`<div class="restack-panel"><h2>restack</h2>${e}</div>`;let t=`
    <pre class="rollback-header">ROLLBACK  jj op restore ${a(c.rescue_op_id)}
backup bookmark: ${a(c.backup_bookmark)}
${a(c.jj_version||"jj version unknown")}${c.can_reconstruct?"":"  (manual path restore \u2014 jj lacks non-interactive support)"}</pre>`;return`
    <div class="restack-panel">
      <h2>restack</h2>
      ${e}
      ${t}
      <div class="restack-downloads">
        <button type="button" class="btn-sm" data-action="download-restack">download restack.sh</button>
        <button type="button" class="btn-sm" data-action="download-cutlist">download cutlist.json</button>
      </div>
      <details class="restack-script-viewer">
        <summary>view restack.sh</summary>
        <pre class="script-text">${a(c.script_text)}</pre>
      </details>
      ${Y(c)}
    </div>`}function U(e,t){return`
    <div class="apply-result ${t.ok?"ok":"fail"}">
      <p>${e} ${t.ok?"succeeded":"FAILED"}</p>
      ${t.stdout?`<pre class="apply-output">${a(t.stdout)}</pre>`:""}
      ${t.stderr?`<pre class="apply-output apply-stderr">${a(t.stderr)}</pre>`:""}
    </div>`}function Y(e){let t=b?`
      <div class="apply-confirm-overlay">
        <div class="apply-confirm">
          <h3>apply restack now?</h3>
          <p>This runs the jj surgery for real. If anything goes wrong:</p>
          <pre class="rollback-header">jj op restore ${a(e.rescue_op_id)}
backup bookmark: ${a(e.backup_bookmark)}</pre>
          <div class="apply-confirm-actions">
            <button type="button" class="btn" data-action="confirm-apply">yes, apply now</button>
            <button type="button" class="btn-sm" data-action="cancel-apply">cancel</button>
          </div>
        </div>
      </div>`:"";return`
    <div class="apply-controls">
      <button type="button" class="btn" data-action="open-apply-confirm">APPLY restack now</button>
      <button type="button" class="btn-sm" data-action="rollback">rollback (jj op restore)</button>
      ${m?U("apply",m):""}
      ${k?U("rollback",k):""}
    </div>
    ${t}`}function Q(e){return`
    <div class="toolbar">
      <button type="button" class="btn" data-action="repart">re-part</button>
      <div class="size-cap-control">
        <input
          type="number"
          min="1"
          class="field size-cap-input"
          placeholder="no cap"
          value="${e.size_cap??""}"
          aria-label="size cap"
        />
        <button type="button" class="btn-sm" data-action="set-size-cap">apply cap</button>
      </div>
      ${G()}
      ${N()}
    </div>`}function N(){return`
    <label class="btn-sm file-label">
      view a saved cutlist.json
      <input type="file" class="explain-file-input" accept="application/json" hidden />
    </label>`}function W(e,t){return`
    <li class="file-row-ro">
      <code class="path">${a(e)}</code>
      <span class="badge">${a(t)}</span>
    </li>`}function X(e,t){let s=e.bucket===L;return`
    <article class="cut-card" data-bucket="${a(e.bucket)}">
      <h3>
        <span class="idx">${t}</span>
        <span class="badge">${a(e.bucket)}</span>
        ${s?'<span class="untiered-tag">needs a tier</span>':""}
        <small>${e.files.length} file${e.files.length===1?"":"s"} &middot; size ${e.size}${e.oversized?" &middot; oversized":""}</small>
      </h3>
      <ul class="files-readonly">
        ${e.files.map(r=>W(r,e.bucket)).join("")}
      </ul>
    </article>`}function Z(e){return[`<div class="explain-banner">
       viewing a loaded <code>cutlist.json</code> \u2014 read-only
       <button type="button" class="btn-sm" data-action="close-explain">back to live session</button>
     </div>`,B(e),F(e.overrides??[]),`<div class="cut-cards">${e.parts.map((t,s)=>X(t,s+1)).join("")}</div>`].join("")}function K(){return`
    <div class="target-form">
      <div class="target-row">
        <input type="text" class="field target-base" placeholder="base (e.g. main)" aria-label="base revision" />
        <input type="text" class="field target-head" placeholder="head (e.g. HEAD)" aria-label="head revision" />
        <button type="button" class="btn-sm" data-action="set-range">target range</button>
      </div>
      <div class="target-row">
        <input type="text" class="field target-pr" placeholder="PR URL or number" aria-label="pull request" />
        <button type="button" class="btn-sm" data-action="set-pr">target PR</button>
      </div>
    </div>`}function ee(){return`
    <div class="target-panel">
      <button type="button" class="btn-sm" data-action="toggle-target-form">retarget</button>
      ${v?K():""}
    </div>`}function te(e){return A.map(t=>`<option value="${t}"${t===e?" selected":""}>${t}</option>`).join("")}function se(e,t){return`
    <li class="file-row" data-path="${f(e)}">
      <code class="path">${a(e)}</code>
      <input class="glob" type="text" value="${f(e)}" required
        pattern="\\S.*" aria-label="glob for ${f(e)}" />
      <button type="button" class="btn-sm" data-action="broaden"
        title="broaden to the containing directory">\u2922</button>
      <select class="bucket-select" aria-label="bucket for ${f(e)}">${te(t)}</select>
      <button type="button" class="btn-sm" data-action="reclassify">save</button>
    </li>`}function re(e,t){let r=e.bucket===L?'<span class="untiered-tag">needs a tier</span>':"",n=e.files.map(i=>se(i,e.bucket)).join("");return`
    <article class="cut-card" data-bucket="${a(e.bucket)}">
      <h3>
        <span class="idx">${t}</span>
        <span class="badge">${a(e.bucket)}</span>
        ${r}
        <small>${e.files.length} file${e.files.length===1?"":"s"}
          &middot; size ${e.size}${e.oversized?" &middot; oversized":""}</small>
      </h3>
      <ul class="files">${n}</ul>
    </article>`}function ne(e){return[B(e),e.pr?`<p class="muted">targeting PR ${a(e.pr.slug)}#${e.pr.number}</p>`:"",ee(),F(e.overrides??[]),Q(e),d?`<div class="error-banner">${a(d)}</div>`:"",`<div class="cut-cards">${e.parts.map((t,s)=>re(t,s+1)).join("")}</div>`,V()].join("")}function ae(){return`
    <header class="cut-header"><h1>caliper cut list</h1></header>
    <div class="empty-state">
      <p>no range targeted yet \u2014 enter a base/head range or a PR to begin.</p>
      ${K()}
      <p>${N()} a saved cutlist.json instead</p>
      ${d?`<div class="error-banner">${a(d)}</div>`:""}
    </div>`}function o(){let e=document.getElementById("app");if(e){if(h){e.innerHTML=Z(h);return}p&&(e.innerHTML=O(p)?ne(p):ae())}}async function u(e){if(!T){T=!0,d=null;try{return await e()}catch(t){d=t.message,o();return}finally{T=!1}}}async function ie(e,t){switch(e){case"repart":{let s=await u(()=>x());s&&(p=s,o());break}case"suggest":{let s=await u(()=>_());s&&(l=s,o());break}case"suggest-accept":{let s=t.dataset.glob??"",r=t.dataset.bucket??"",n=t.dataset.note??"";if(!s||!r)break;let i=await u(()=>R(s,r,n));i&&(p=i,l&&(l={...l,suggestions:l.suggestions.filter($=>$.glob!==s)}),o());break}case"suggest-accept-all":{if(!l||l.suggestions.length===0)break;let s=l.suggestions,r=await u(()=>E(s));r&&(p=r,l=null,o());break}case"broaden":{let s=t.closest(".file-row"),r=s?.dataset.path,n=s?.querySelector(".glob");r&&n&&(n.value=J(r));break}case"reclassify":{let s=t.closest(".file-row"),r=s?.querySelector(".glob"),n=s?.querySelector(".bucket-select");if(!r||!n||!r.value.trim())break;let i=await u(()=>R(r.value.trim(),n.value));i&&(p=i,o());break}case"toggle-target-form":{v=!v,o();break}case"set-range":{let s=t.closest(".target-form"),r=s?.querySelector(".target-base")?.value.trim(),n=s?.querySelector(".target-head")?.value.trim();if(!r||!n)break;let i=await u(()=>j(r,n));i&&(p=i,v=!1,l=null,c=null,m=null,k=null,b=!1,o());break}case"set-pr":{let r=t.closest(".target-form")?.querySelector(".target-pr")?.value.trim();if(!r)break;let n=await u(()=>S(r));n&&(p=n,v=!1,l=null,c=null,m=null,k=null,b=!1,o());break}case"set-size-cap":{let r=t.closest(".toolbar")?.querySelector(".size-cap-input")?.value.trim()??"",n=r===""?null:Number(r);if(n!==null&&(!Number.isInteger(n)||n<=0)){d="size cap must be a positive integer",o();break}let i=await u(()=>P(n));i&&(p=i,o());break}case"close-explain":{h=null,o();break}case"generate-restack":{let s=t.closest(".restack-panel"),r=s?.querySelector(".restack-describe")?.checked??!1,n=s?.querySelector(".restack-force")?.checked??!1,i=s?.querySelector(".restack-target")?.value??"",$=i===""?void 0:i,w=await u(()=>H({describe:r,force:n,target:$}));w&&(c=w,m=null,k=null,b=!1,o());break}case"download-restack":{if(!c)break;q("restack.sh",c.script_text,"text/x-shellscript");break}case"download-cutlist":{if(!c)break;q("cutlist.json",JSON.stringify(c.cutlist,null,2),"application/json");break}case"open-apply-confirm":{b=!0,o();break}case"cancel-apply":{b=!1,o();break}case"confirm-apply":{if(!c)break;b=!1;let s=await u(()=>z(c.apply_token));s&&(m=s),o();break}case"rollback":{let s=await u(()=>M());s&&(k=s),o();break}default:break}}function q(e,t,s){let r=new Blob([t],{type:s}),n=URL.createObjectURL(r),i=document.createElement("a");i.href=n,i.download=e,i.click(),URL.revokeObjectURL(n)}async function oe(e){try{let t=JSON.parse(await e.text());if(!t||!Array.isArray(t.parts))throw new Error("not a valid cutlist.json (missing 'parts')");d=null,h=t}catch(t){d=`failed to load cutlist.json: ${t.message}`}o()}function le(e){e.addEventListener("click",t=>{let s=t.target.closest("[data-action]");s&&ie(s.dataset.action??"",s)}),e.addEventListener("change",t=>{let s=t.target;if(s instanceof HTMLInputElement&&s.classList.contains("explain-file-input")){let r=s.files?.[0];r&&oe(r)}})}async function ce(){let e=document.getElementById("app");if(e){le(e),e.textContent="loading\u2026";try{p=await C(),o()}catch(t){e.textContent=`failed to load cut list: ${t.message}`}}}ce();})();
