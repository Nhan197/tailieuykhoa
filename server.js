import express from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import fs from "fs";
import path from "path";
import multer from "multer";
import { fileURLToPath } from "url";
import { v4 as uuidv4 } from "uuid";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json({ limit: "4mb" }));

// serve static
app.use("/uploads", express.static(path.join(__dirname, "uploads")));
app.use("/", express.static(path.join(__dirname, "public")));

const DATA_DIR = path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "db.json");
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(path.join(__dirname, "uploads")))
  fs.mkdirSync(path.join(__dirname, "uploads"), { recursive: true });

const JWT_SECRET = process.env.JWT_SECRET || "demo-secret-please-change";

// --------- helpers ----------
const save = (db) => fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), "utf8");
const load = () => {
  if (!fs.existsSync(DB_FILE)) {
    const s = seedDB();
    save(s);
    return s;
  }
  return JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
};

const SUBS = [
  { key: "lythuyet", name: "Lý thuyết" },
  { key: "video", name: "Video bài giảng" },
  { key: "tracnghiem", name: "Trắc nghiệm" },
  { key: "detuluyen", name: "Đề tự luyện" },
  { key: "dechinhthuc", name: "Đề chính thức các năm" }
];

const CATS = [
  "y học thể dục thể thao",
  "sức khỏe cộng đồng",
  "nhi",
  "điều trị nội",
  "dược lâm sàng",
  "ung bướu",
  "tâm lý y học 2",
  "sản phụ khoa",
  "nhiễm",
  "dịch tễ học",
  "chấn thương chỉnh hình",
  "chẩn đoán hình ảnh"
];

const randPrice = () => (Math.floor(Math.random() * 10) + 1) * 10000; // 10k-100k
const code = (n = 10) =>
  Array.from({ length: n }, () =>
    "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"[Math.floor(Math.random() * 32)]
  ).join("");

function seedDB() {
  const adminPwd = bcrypt.hashSync("Nhan19.7@@@@", 10);
  const items = [];
  let id = 1;
  for (const cat of CATS) {
    for (const s of SUBS) {
      for (let i = 1; i <= 2; i++) {
        items.push({
          id: String(id++),
          category: cat,
          sub: s.key,
          subName: s.name,
          title: `${s.name} ${i} – ${cat}`,
          price: randPrice(),
          filePath: null
        });
      }
    }
  }
  return {
    users: [
      {
        id: "u-admin",
        username: "bahana",
        email: "bahana@local",
        name: "Administrator",
        role: "admin",
        passwordHash: adminPwd,
        ndck: "AC-" + code(8),
        notifications: [],
        unlockedItemIds: []
      }
    ],
    items,
    orders: [],
    settings: {
      momoName: "BACH HOAI NHAN",
      momoPhone: "0975841693",
      momoQrTemplate: "https://api.qrserver.com/v1/create-qr-code/?size=320x320&data="
    }
  };
}

// auth middlewares
const auth = (req, res, next) => {
  const token = (req.headers.authorization || "").replace("Bearer ", "");
  if (!token) return res.status(401).json({ message: "Unauthenticated" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ message: "Invalid token" });
  }
};
const adminOnly = (req, res, next) => {
  if (req.user?.role !== "admin") return res.status(403).json({ message: "Admin only" });
  next();
};

// upload config
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(__dirname, "uploads")),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${Date.now()}-${uuidv4()}${ext}`);
  }
});
const upload = multer({ storage });

// --------- public APIs ----------
app.get("/api/catalog", (req, res) => {
  res.json({ categories: CATS, subs: SUBS });
});

app.get("/api/items", (req, res) => {
  const { category, sub } = req.query;
  const db = load();
  let list = db.items;
  if (category) list = list.filter((i) => i.category === category);
  if (sub) list = list.filter((i) => i.sub === sub);
  res.json(list);
});

app.get("/api/settings", (req, res) => {
  res.json(load().settings);
});

app.post("/api/register", (req, res) => {
  const db = load();
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ message: "Thiếu thông tin" });
  if (db.users.find((u) => u.email === email)) return res.status(400).json({ message: "Email đã tồn tại" });

  const u = {
    id: uuidv4(),
    username: email.split("@")[0],
    email,
    name,
    role: "user",
    passwordHash: bcrypt.hashSync(password, 10),
    ndck: "AC-" + code(8),
    notifications: [],
    unlockedItemIds: []
  };
  db.users.push(u);
  save(db);
  res.json({ ok: true });
});

// login: admin bắt buộc gửi asAdmin=true
app.post("/api/login", (req, res) => {
  const db = load();
  const { login, password, asAdmin } = req.body;
  const user =
    db.users.find((u) => u.email === login) ||
    db.users.find((u) => u.username === login);
  if (!user) return res.status(400).json({ message: "Sai thông tin" });
  const ok = bcrypt.compareSync(password, user.passwordHash);
  if (!ok) return res.status(400).json({ message: "Sai thông tin" });
  if (user.role === "admin" && !asAdmin)
    return res.status(403).json({ message: 'Hãy chọn "Bạn là admin?" để đăng nhập quản trị.' });

  const token = jwt.sign({ id: user.id, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: "7d" });
  res.json({
    token,
    user: { id: user.id, email: user.email, name: user.name, role: user.role, ndck: user.ndck }
  });
});

app.get("/api/me", auth, (req, res) => {
  const db = load();
  const u = db.users.find((x) => x.id === req.user.id);
  res.json({
    id: u.id,
    email: u.email,
    name: u.name,
    role: u.role,
    ndck: u.ndck,
    unlockedItemIds: u.unlockedItemIds
  });
});

// --------- orders ----------
app.post("/api/order", auth, (req, res) => {
  const db = load();
  const { itemId } = req.body;
  const item = db.items.find((i) => i.id === itemId);
  if (!item) return res.status(404).json({ message: "Không tìm thấy tài liệu" });

  const order = {
    id: uuidv4(),
    userId: req.user.id,
    itemId: item.id,
    price: item.price,
    status: "new",
    reportedAt: null,
    approvedAt: null,
    activationCode: null,
    activationUsed: false,
    seenByAdmin: false,
    createdAt: Date.now()
  };
  db.orders.push(order);
  save(db);
  res.json(order);
});

app.post("/api/order/:id/confirm", auth, (req, res) => {
  const db = load();
  const order = db.orders.find((o) => o.id === req.params.id);
  if (!order || order.userId !== req.user.id) return res.status(404).json({ message: "Không tìm thấy đơn" });
  order.status = "reported";
  order.reportedAt = Date.now();
  order.seenByAdmin = false; // bật badge đỏ cho admin
  save(db);
  res.json({ ok: true });
});

app.get("/api/my-orders", auth, (req, res) => {
  const db = load();
  const list = db.orders
    .filter((o) => o.userId === req.user.id)
    .map((o) => ({ ...o, item: db.items.find((i) => i.id === o.itemId) }));
  res.json(list);
});

// kích hoạt bằng mã (1 lần)
app.post("/api/activate", auth, (req, res) => {
  const db = load();
  const { code: act } = req.body;
  const order = db.orders.find((o) => o.activationCode === act && o.userId === req.user.id);
  if (!order) return res.status(400).json({ message: "Mã không hợp lệ" });
  if (order.activationUsed) return res.status(400).json({ message: "Mã đã được sử dụng" });
  if (order.status !== "approved") return res.status(400).json({ message: "Đơn chưa được duyệt" });

  order.activationUsed = true;
  const u = db.users.find((x) => x.id === req.user.id);
  if (!u.unlockedItemIds.includes(order.itemId)) u.unlockedItemIds.push(order.itemId);
  save(db);
  res.json({ ok: true, itemId: order.itemId });
});

// --------- notifications ----------
app.get("/api/notifications/count", auth, (req, res) => {
  const db = load();
  const u = db.users.find((x) => x.id === req.user.id);
  res.json({ unread: u.notifications.filter((n) => !n.read).length });
});

app.get("/api/notifications", auth, (req, res) => {
  const db = load();
  const u = db.users.find((x) => x.id === req.user.id);
  res.json(u.notifications.sort((a, b) => b.createdAt - a.createdAt));
});

app.post("/api/notifications/read-all", auth, (req, res) => {
  const db = load();
  const u = db.users.find((x) => x.id === req.user.id);
  u.notifications.forEach((n) => (n.read = true));
  save(db);
  res.json({ ok: true });
});

// --------- admin ----------
app.get("/api/admin/pending-count", auth, adminOnly, (req, res) => {
  const db = load();
  const c = db.orders.filter((o) => o.status === "reported" && !o.seenByAdmin).length;
  res.json({ pending: c });
});

app.get("/api/admin/pending", auth, adminOnly, (req, res) => {
  const db = load();
  const list = db.orders
    .filter((o) => o.status === "reported")
    .map((o) => ({
      ...o,
      user: db.users.find((u) => u.id === o.userId),
      item: db.items.find((i) => i.id === o.itemId)
    }));
  // đánh dấu đã xem để tắt badge
  db.orders.forEach((o) => {
    if (o.status === "reported") o.seenByAdmin = true;
  });
  save(db);
  res.json(list.sort((a, b) => b.reportedAt - a.reportedAt));
});

app.post("/api/admin/orders/:id/approve", auth, adminOnly, (req, res) => {
  const db = load();
  const order = db.orders.find((o) => o.id === req.params.id);
  if (!order) return res.status(404).json({ message: "Không tìm thấy đơn" });

  order.status = "approved";
  order.approvedAt = Date.now();
  order.activationCode = code(12);
  order.seenByAdmin = true;

  const u = db.users.find((x) => x.id === order.userId);
  u.notifications.unshift({
    id: uuidv4(),
    message: `Đơn hàng ${order.id.slice(0, 8)} đã được duyệt. Mã kích hoạt: ${order.activationCode}`,
    read: false,
    createdAt: Date.now()
  });

  save(db);
  res.json({ ok: true, activationCode: order.activationCode });
});

// upload tài liệu
const upload2 = multer({ storage });
app.post("/api/admin/upload", auth, adminOnly, upload2.single("file"), (req, res) => {
  const db = load();
  const { category, sub, title, price } = req.body;
  if (!req.file) return res.status(400).json({ message: "Thiếu file" });
  if (!category || !sub || !title) return res.status(400).json({ message: "Thiếu thông tin" });

  const item = {
    id: uuidv4(),
    category,
    sub,
    subName: SUBS.find((s) => s.key === sub)?.name || sub,
    title,
    price: parseInt(price || randPrice(), 10),
    filePath: `/uploads/${req.file.filename}`
  };
  db.items.push(item);
  save(db);
  res.json(item);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server listening on http://localhost:" + PORT));
