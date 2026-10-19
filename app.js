const $ = (s) => document.querySelector(s);
const feed = $('#feed');
const emptyState = $('#emptyState');
const postText = $('#postText');
const imageInput = $('#imageInput');
const imagePreview = $('#imagePreview');
let pendingImage = '';
let posts = [];
let currentView = 'feed';
let activeTag = '';

try { posts = JSON.parse(localStorage.getItem('alphaPosts') || '[]'); } catch { posts = []; }
function savePosts(){ localStorage.setItem('alphaPosts', JSON.stringify(posts)); }
function esc(s){ return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function timeAgo(t){ const mins=Math.max(0,Math.floor((Date.now()-t)/60000)); if(mins<1)return 'Just now'; if(mins<60)return mins+'m ago'; if(mins<1440)return Math.floor(mins/60)+'h ago'; return Math.floor(mins/1440)+'d ago'; }
function toast(msg){const el=$('#toast');el.textContent=msg;el.classList.add('show');setTimeout(()=>el.classList.remove('show'),2300);}
function render(){
  const q=$('#searchInput').value.trim().toLowerCase();
  let visible=posts.filter(p=>{
    const matchesQ=!q || (p.text||'').toLowerCase().includes(q) || 'umar'.includes(q);
    const matchesTag=!activeTag || (p.text||'').toLowerCase().includes(activeTag.toLowerCase());
    const matchesView=currentView==='saved'?p.saved:currentView==='profile'?p.author==='You':true;
    return matchesQ&&matchesTag&&matchesView;
  });
  if(currentView==='explore') visible=visible.slice().sort((a,b)=>b.likes-a.likes);
  feed.innerHTML=visible.map(p=>`<article class="post card" data-id="${p.id}">
    <div class="post-header"><div class="avatar">${esc((p.author||'U').charAt(0).toUpperCase())}</div><div class="post-author"><strong>${esc(p.author||'You')}</strong><small>${timeAgo(p.time)} · 🌐 Public</small></div><button class="post-menu" data-action="delete" title="Delete post">⋯</button></div>
    ${p.text?`<div class="post-content">${esc(p.text)}</div>`:''}
    ${p.image?`<img class="post-image" src="${p.image}" alt="Post attachment">`:''}
    <div class="post-actions"><button class="action-btn ${p.liked?'liked':''}" data-action="like">♥ ${p.likes} ${p.likes===1?'Like':'Likes'}</button><button class="action-btn" data-action="comment">▢ ${p.comments.length} Comments</button><button class="action-btn ${p.saved?'saved':''}" data-action="save">${p.saved?'▣ Saved':'♡ Save'}</button></div>
    <div class="comments">${p.comments.map(c=>`<div class="comment"><strong>You:</strong> ${esc(c)}</div>`).join('')}</div>
    <form class="comment-box"><input name="comment" maxlength="180" placeholder="Write a comment..." aria-label="Write a comment"><button type="submit">Reply</button></form>
  </article>`).join('');
  emptyState.classList.toggle('hidden',visible.length!==0);
  $('#postTotal').textContent=visible.length+' '+(visible.length===1?'post':'posts');
  $('#statPosts').textContent=posts.length;
  $('#statLikes').textContent=posts.reduce((n,p)=>n+p.likes,0);
}
$('#publishBtn').addEventListener('click',()=>{
  const text=postText.value.trim();
  if(!text&&!pendingImage){toast('Write something or add a photo first.');return;}
  posts.unshift({id:Date.now().toString(36)+Math.random().toString(36).slice(2,7),author:'You',text,image:pendingImage,time:Date.now(),likes:0,liked:false,saved:false,comments:[]});
  savePosts();postText.value='';$('#charCount').textContent='0 / 500';pendingImage='';imagePreview.innerHTML='';imagePreview.classList.add('hidden');render();toast('Your post was published on this device!');
});
postText.addEventListener('input',()=>$('#charCount').textContent=postText.value.length+' / 500');
imageInput.addEventListener('change',()=>{
  const file=imageInput.files[0];if(!file)return;
  if(file.size>1.5*1024*1024){toast('Choose an image smaller than 1.5 MB.');imageInput.value='';return;}
  const reader=new FileReader();reader.onload=()=>{pendingImage=reader.result;imagePreview.innerHTML=`<img src="${pendingImage}" alt="Image preview">`;imagePreview.classList.remove('hidden');};reader.readAsDataURL(file);
});
feed.addEventListener('click',e=>{
  const btn=e.target.closest('[data-action]');if(!btn)return;
  const article=btn.closest('[data-id]');const p=posts.find(x=>x.id===article.dataset.id);if(!p)return;
  const action=btn.dataset.action;
  if(action==='like'){p.liked=!p.liked;p.likes=Math.max(0,p.likes+(p.liked?1:-1));}
  if(action==='save'){p.saved=!p.saved;toast(p.saved?'Post saved.':'Post removed from saved posts.');}
  if(action==='delete'){if(confirm('Delete this post from this browser?')){posts=posts.filter(x=>x.id!==p.id);toast('Post deleted.');}}
  if(action==='comment'){article.querySelector('input[name="comment"]').focus();return;}
  savePosts();render();
});
feed.addEventListener('submit',e=>{
  if(!e.target.matches('.comment-box'))return;e.preventDefault();
  const article=e.target.closest('[data-id]');const p=posts.find(x=>x.id===article.dataset.id);const input=e.target.elements.comment;const text=input.value.trim();if(!text)return;
  p.comments.push(text);savePosts();render();toast('Comment added.');
});
$('#searchInput').addEventListener('input',render);
document.querySelectorAll('.nav-item').forEach(btn=>btn.addEventListener('click',()=>{
  currentView=btn.dataset.view;activeTag='';document.querySelectorAll('.nav-item').forEach(b=>b.classList.toggle('active',b===btn));
  $('#feedTitle').textContent=({feed:'Community feed',explore:'Explore popular posts',saved:'Saved posts',profile:'My posts'})[currentView];render();
}));
document.querySelectorAll('.trend').forEach(btn=>btn.addEventListener('click',()=>{
  activeTag=activeTag===btn.dataset.tag?'':btn.dataset.tag;$('#feedTitle').textContent=activeTag?'#'+activeTag:'Community feed';render();toast(activeTag?'Showing posts mentioning '+activeTag:'Topic filter cleared.');
}));
$('#themeBtn').addEventListener('click',()=>{document.body.classList.toggle('dark');localStorage.setItem('alphaDark',document.body.classList.contains('dark')?'1':'0');});
if(localStorage.getItem('alphaDark')==='1')document.body.classList.add('dark');
render();
