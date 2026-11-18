require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const rateLimit = require("express-rate-limit");
const http = require("http");
const { Server } = require("socket.io");
const path = require("path");
const fs = require("fs");

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const PORT = process.env.PORT || 3000;
const DATA = path.join(__dirname, "data");
fs.mkdirSync(DATA, { recursive: true });
const db = new Database(path.join(DATA, "erfan.sqlite"));
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, display_name TEXT NOT NULL, bio TEXT DEFAULT '', avatar TEXT DEFAULT '', role TEXT DEFAULT 'user', created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS posts(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, body TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS comments(id INTEGER PRIMARY KEY, post_id INTEGER NOT NULL, user_id INTEGER NOT NULL, body TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS follows(follower_id INTEGER NOT NULL, followed_id INTEGER NOT NULL, UNIQUE(follower_id, followed_id));
CREATE TABLE IF NOT EXISTS likes(user_id INTEGER NOT NULL, post_id INTEGER NOT NULL, UNIQUE(user_id, post_id));
CREATE TABLE IF NOT EXISTS stories(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, body TEXT NOT NULL, expires_at INTEGER NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS rooms(id INTEGER PRIMARY KEY, name TEXT NOT NULL, description TEXT DEFAULT '', kind TEXT NOT NULL, owner_id INTEGER NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS room_members(room_id INTEGER NOT NULL, user_id INTEGER NOT NULL, UNIQUE(room_id,user_id));
CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY, room_id INTEGER NOT NULL, sender_id INTEGER NOT NULL, body TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, target_type TEXT NOT NULL, target_id INTEGER NOT NULL, reason TEXT NOT NULL, status TEXT DEFAULT 'open', created_at TEXT DEFAULT CURRENT_TIMESTAMP);
`);
const q = (sql) => db.prepare(sql);
const sessionMiddleware = session({
  store: new SQLiteStore({ db: "sessions.sqlite", dir: DATA }),
  secret: process.env.SESSION_SECRET || "dev-only-change-this-secret-before-deploying",
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", maxAge: 7*24*60*60*1000 }
});
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: false }));
app.use(sessionMiddleware);
app.use(express.static(__dirname));
const authLimiter = rateLimit({ windowMs: 15*60*1000, limit: 30, standardHeaders: true, legacyHeaders: false });
const clean = (v, n=1000) => String(v ?? "").trim().slice(0,n);
const me = (req) => req.session.userId ? q("SELECT id,username,display_name,bio,avatar,role FROM users WHERE id=?").get(req.session.userId) : null;
function requireAuth(req,res,next){ if(!me(req)) return res.status(401).json({error:"ابتدا وارد حساب شو."}); next(); }
function requireAdmin(req,res,next){ const u=me(req); if(!u || u.role!=="admin") return res.status(403).json({error:"دسترسی مدیر لازم است."}); next(); }
function safeUser(u){ return {id:u.id,username:u.username,display_name:u.display_name,bio:u.bio,avatar:u.avatar,role:u.role}; }

const adminName=clean(process.env.ADMIN_USERNAME,30);
const adminPass=process.env.ADMIN_PASSWORD;
if(adminName && adminPass && !q("SELECT id FROM users WHERE username=?").get(adminName)){
  q("INSERT INTO users(username,password,display_name,role) VALUES(?,?,?,'admin')").run(adminName,bcrypt.hashSync(adminPass,12),adminName);
}

app.get("/api/me",(req,res)=>res.json({user:me(req)}));
app.post("/api/register",authLimiter,async(req,res)=>{
  const username=clean(req.body.username,24).toLowerCase(), password=String(req.body.password||""), display=clean(req.body.display_name||username,40);
  if(!/^[a-z0-9_]{3,24}$/.test(username)) return res.status(400).json({error:"نام کاربری باید ۳ تا ۲۴ حرف انگلیسی، عدد یا _ باشد."});
  if(password.length<8) return res.status(400).json({error:"رمز عبور باید حداقل ۸ کاراکتر باشد."});
  try{
    const info=q("INSERT INTO users(username,password,display_name) VALUES(?,?,?)").run(username,await bcrypt.hash(password,12),display);
    req.session.userId=info.lastInsertRowid; res.json({user:me(req)});
  }catch(e){res.status(409).json({error:"این نام کاربری قبلاً ثبت شده است."});}
});
app.post("/api/login",authLimiter,async(req,res)=>{
  const u=q("SELECT * FROM users WHERE username=?").get(clean(req.body.username,24).toLowerCase());
  if(!u || !(await bcrypt.compare(String(req.body.password||""),u.password))) return res.status(401).json({error:"نام کاربری یا رمز عبور اشتباه است."});
  req.session.userId=u.id; res.json({user:safeUser(u)});
});
app.post("/api/logout",requireAuth,(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.patch("/api/profile",requireAuth,(req,res)=>{
  const display=clean(req.body.display_name,40), bio=clean(req.body.bio,180), avatar=clean(req.body.avatar,500);
  if(!display) return res.status(400).json({error:"نام نمایشی نمی‌تواند خالی باشد."});
  q("UPDATE users SET display_name=?,bio=?,avatar=? WHERE id=?").run(display,bio,avatar,req.session.userId);
  res.json({user:me(req)});
});
app.get("/api/users",requireAuth,(req,res)=>{
  const term=clean(req.query.q,40);
  res.json(q("SELECT id,username,display_name,bio,avatar FROM users WHERE username LIKE ? OR display_name LIKE ? ORDER BY username LIMIT 30").all(`%${term}%`,`%${term}%`));
});
app.post("/api/follow/:id",requireAuth,(req,res)=>{
  const id=Number(req.params.id), uid=req.session.userId;
  if(id===uid || !q("SELECT id FROM users WHERE id=?").get(id)) return res.status(400).json({error:"کاربر نامعتبر است."});
  const exists=q("SELECT 1 FROM follows WHERE follower_id=? AND followed_id=?").get(uid,id);
  exists ? q("DELETE FROM follows WHERE follower_id=? AND followed_id=?").run(uid,id) : q("INSERT INTO follows(follower_id,followed_id) VALUES(?,?)").run(uid,id);
  res.json({following:!exists});
});
app.get("/api/posts",requireAuth,(req,res)=>{
  const posts=q(`SELECT p.*,u.username,u.display_name,u.avatar,
    (SELECT COUNT(*) FROM likes l WHERE l.post_id=p.id) likes,
    (SELECT COUNT(*) FROM comments c WHERE c.post_id=p.id) comments,
    EXISTS(SELECT 1 FROM likes l WHERE l.post_id=p.id AND l.user_id=?) liked
    FROM posts p JOIN users u ON u.id=p.user_id ORDER BY p.id DESC LIMIT 60`).all(req.session.userId);
  res.json(posts);
});
app.post("/api/posts",requireAuth,(req,res)=>{
  const body=clean(req.body.body,2000); if(!body) return res.status(400).json({error:"متن پست را بنویس."});
  q("INSERT INTO posts(user_id,body) VALUES(?,?)").run(req.session.userId,body); res.json({ok:true});
});
app.post("/api/posts/:id/like",requireAuth,(req,res)=>{
  const id=Number(req.params.id), uid=req.session.userId;
  if(!q("SELECT id FROM posts WHERE id=?").get(id)) return res.status(404).json({error:"پست پیدا نشد."});
  const exists=q("SELECT 1 FROM likes WHERE user_id=? AND post_id=?").get(uid,id);
  exists?q("DELETE FROM likes WHERE user_id=? AND post_id=?").run(uid,id):q("INSERT INTO likes(user_id,post_id) VALUES(?,?)").run(uid,id);
  res.json({liked:!exists});
});
app.get("/api/posts/:id/comments",requireAuth,(req,res)=>res.json(q("SELECT c.*,u.username,u.display_name FROM comments c JOIN users u ON u.id=c.user_id WHERE c.post_id=? ORDER BY c.id").all(Number(req.params.id))));
app.post("/api/posts/:id/comments",requireAuth,(req,res)=>{
  const body=clean(req.body.body,500); if(!body) return res.status(400).json({error:"متن نظر خالی است."});
  q("INSERT INTO comments(post_id,user_id,body) VALUES(?,?,?)").run(Number(req.params.id),req.session.userId,body); res.json({ok:true});
});
app.get("/api/stories",requireAuth,(req,res)=>{
  q("DELETE FROM stories WHERE expires_at < ?").run(Date.now());
  res.json(q("SELECT s.*,u.username,u.display_name FROM stories s JOIN users u ON u.id=s.user_id ORDER BY s.id DESC").all());
});
app.post("/api/stories",requireAuth,(req,res)=>{
  const body=clean(req.body.body,500); if(!body) return res.status(400).json({error:"متن استوری را بنویس."});
  q("INSERT INTO stories(user_id,body,expires_at) VALUES(?,?,?)").run(req.session.userId,body,Date.now()+86400000); res.json({ok:true});
});
app.post("/api/rooms",requireAuth,(req,res)=>{
  const name=clean(req.body.name,50), description=clean(req.body.description,200), kind=req.body.kind==="channel"?"channel":"group";
  if(!name) return res.status(400).json({error:"نام گروه یا کانال را وارد کن."});
  const info=q("INSERT INTO rooms(name,description,kind,owner_id) VALUES(?,?,?,?)").run(name,description,kind,req.session.userId);
  q("INSERT INTO room_members(room_id,user_id) VALUES(?,?)").run(info.lastInsertRowid,req.session.userId);
  res.json({id:info.lastInsertRowid});
});
app.get("/api/rooms",requireAuth,(req,res)=>res.json(q(`SELECT r.*,u.username owner,
  (SELECT COUNT(*) FROM room_members m WHERE m.room_id=r.id) members,
  EXISTS(SELECT 1 FROM room_members m WHERE m.room_id=r.id AND m.user_id=?) joined
  FROM rooms r JOIN users u ON u.id=r.owner_id ORDER BY r.id DESC`).all(req.session.userId)));
app.post("/api/rooms/:id/join",requireAuth,(req,res)=>{
  const id=Number(req.params.id); if(!q("SELECT id FROM rooms WHERE id=?").get(id)) return res.status(404).json({error:"گروه پیدا نشد."});
  q("INSERT OR IGNORE INTO room_members(room_id,user_id) VALUES(?,?)").run(id,req.session.userId); res.json({ok:true});
});
app.get("/api/rooms/:id/messages",requireAuth,(req,res)=>{
  const id=Number(req.params.id);
  if(!q("SELECT 1 FROM room_members WHERE room_id=? AND user_id=?").get(id,req.session.userId)) return res.status(403).json({error:"عضو این گفتگو نیستی."});
  res.json(q("SELECT m.*,u.username,u.display_name FROM messages m JOIN users u ON u.id=m.sender_id WHERE room_id=? ORDER BY m.id DESC LIMIT 100").all(id).reverse());
});
app.post("/api/rooms/:id/messages",requireAuth,(req,res)=>{
  const id=Number(req.params.id), body=clean(req.body.body,1500);
  if(!body) return res.status(400).json({error:"پیام خالی است."});
  if(!q("SELECT 1 FROM room_members WHERE room_id=? AND user_id=?").get(id,req.session.userId)) return res.status(403).json({error:"عضو این گفتگو نیستی."});
  const info=q("INSERT INTO messages(room_id,sender_id,body) VALUES(?,?,?)").run(id,req.session.userId,body);
  const msg=q("SELECT m.*,u.username,u.display_name FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.id=?").get(info.lastInsertRowid);
  io.to(`room:${id}`).emit("new-message",msg); res.json(msg);
});
app.post("/api/reports",requireAuth,(req,res)=>{
  const targetType=["post","user","room"].includes(req.body.target_type)?req.body.target_type:"post";
  const targetId=Number(req.body.target_id), reason=clean(req.body.reason,300);
  if(!targetId||!reason) return res.status(400).json({error:"اطلاعات گزارش کامل نیست."});
  q("INSERT INTO reports(user_id,target_type,target_id,reason) VALUES(?,?,?,?)").run(req.session.userId,targetType,targetId,reason); res.json({ok:true});
});
app.get("/api/admin/overview",requireAuth,requireAdmin,(req,res)=>res.json({
 users:q("SELECT id,username,display_name,role,created_at FROM users ORDER BY id DESC LIMIT 100").all(),
 posts:q("SELECT p.id,p.body,p.created_at,u.username FROM posts p JOIN users u ON u.id=p.user_id ORDER BY p.id DESC LIMIT 100").all(),
 reports:q("SELECT r.*,u.username FROM reports r JOIN users u ON u.id=r.user_id ORDER BY r.id DESC LIMIT 100").all(),
 counts:{users:q("SELECT COUNT(*) n FROM users").get().n,posts:q("SELECT COUNT(*) n FROM posts").get().n,rooms:q("SELECT COUNT(*) n FROM rooms").get().n}
}));
app.delete("/api/admin/posts/:id",requireAuth,requireAdmin,(req,res)=>{q("DELETE FROM comments WHERE post_id=?").run(Number(req.params.id));q("DELETE FROM likes WHERE post_id=?").run(Number(req.params.id));q("DELETE FROM posts WHERE id=?").run(Number(req.params.id));res.json({ok:true});});
app.patch("/api/admin/users/:id/role",requireAuth,requireAdmin,(req,res)=>{
  const role=req.body.role==="admin"?"admin":"user";
  if(Number(req.params.id)===req.session.userId) return res.status(400).json({error:"نقش حساب فعلی را از اینجا تغییر نده."});
  q("UPDATE users SET role=? WHERE id=?").run(role,Number(req.params.id)); res.json({ok:true});
});
app.patch("/api/admin/reports/:id",requireAuth,requireAdmin,(req,res)=>{q("UPDATE reports SET status='reviewed' WHERE id=?").run(Number(req.params.id));res.json({ok:true});});

io.use((socket,next)=>sessionMiddleware(socket.request,{},next));
io.use((socket,next)=>{const uid=socket.request.session.userId;if(!uid)return next(new Error("unauthorized"));socket.userId=uid;next();});
io.on("connection",socket=>{
  socket.on("join-room",roomId=>{
    const id=Number(roomId);
    if(q("SELECT 1 FROM room_members WHERE room_id=? AND user_id=?").get(id,socket.userId)) socket.join(`room:${id}`);
  });
});

app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"index.html")));
server.listen(PORT,()=>console.log(`ERFAN Site running on ${PORT}`));
