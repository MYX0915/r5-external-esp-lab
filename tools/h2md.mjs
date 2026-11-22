import fs from 'node:fs';
let h = fs.readFileSync('apex_article.html','utf8');
// protect code blocks
const blocks = [];
h = h.replace(/<pre[\s\S]*?<\/pre>/gi, m => {
  let code = m.replace(/<[^>]+>/g,'')
    .replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&amp;/g,'&').replace(/&quot;/g,'"').replace(/&#039;/g,"'").replace(/&#8217;/g,"'");
  blocks.push(code);
  return `\n@@CODE${blocks.length-1}@@\n`;
});
h = h.replace(/<br\s*\/?>/gi,'\n');
h = h.replace(/<\/(p|div|h[1-6]|li|tr|figure|figcaption)>/gi,'\n');
h = h.replace(/<h([1-6])[^>]*>/gi,(m,l)=>'\n'+'#'.repeat(Number(l))+' ');
h = h.replace(/<li[^>]*>/gi,'- ');
h = h.replace(/<[^>]+>/g,'');
h = h.replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&amp;/g,'&').replace(/&quot;/g,'"').replace(/&#039;/g,"'").replace(/&#8217;/g,"'").replace(/&nbsp;/g,' ');
h = h.replace(/@@CODE(\d+)@@/g,(m,i)=>'\n```\n'+blocks[Number(i)].trim()+'\n```\n');
h = h.replace(/[ \t]+\n/g,'\n').replace(/\n{3,}/g,'\n\n').trim();
fs.writeFileSync('apex_article.md', h);
console.log('chars', h.length, 'codeblocks', blocks.length);
