javascript:(async function(){
  const regex=/\/[a-zA-Z0-9_\-\/]+/g;
  const results=new Set();
  const scripts=Array.from(document.scripts);

  for(let s of scripts){
    let url=s.src;
    if(url){
      try{
        const res=await fetch(url);
        const text=await res.text();
        const matches=text.matchAll(regex);
        for(const m of matches){
          results.add(m[0]);
        }
      }catch(e){}
    }
  }

  const pageHTML=document.documentElement.outerHTML;
  const matches=pageHTML.matchAll(regex);
  for(const m of matches){
    results.add(m[0]);
  }

  // ВOutput the result in the new tab
  const output = Array.from(results).join('<br>');
  const win = window.open();
  win.document.write(`<h1>Find: ${results.size}</h1><pre>${output}</pre>`);
})();
