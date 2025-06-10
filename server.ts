// ====================================================
// SimpleDraft Backend Server (v3.1 - Deno Deploy Final)
// ====================================================

import { Hono } from "hono";
import { cors } from "hono/cors";
import { jwt, sign } from "hono/jwt";
import { Client } from "postgres";
import { hash, compare } from "bcrypt";
import { z } from "zod";

// --- خواندن متغیرهای محیطی از داشبورد Deno Deploy ---
const JWT_SECRET = Deno.env.get("JWT_SECRET");
const DATABASE_URL = Deno.env.get("DATABASE_URL");
const FRONTEND_URL = Deno.env.get("FRONTEND_URL") || "https://simpledraft.cyrusstudio.ir";

// بررسی وجود متغیرهای حیاتی
if (!JWT_SECRET || !DATABASE_URL) {
  // به جای Deno.exit، یک خطای واضح ایجاد می‌کنیم.
  // Deno Deploy این خطا را لاگ کرده و اجرای برنامه را متوقف می‌کند.
  throw new Error("FATAL: JWT_SECRET or DATABASE_URL environment variables are not set in Deno Deploy dashboard.");
}

// --- راه‌اندازی کلاینت دیتابیس Postgres ---
const client = new Client(DATABASE_URL);

// --- تابع برای ساخت جدول‌ها در صورت عدم وجود ---
async function initializeSchema() {
  await client.queryObject(`
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
    );
  `);
  await client.queryObject(`
    CREATE TABLE IF NOT EXISTS documents (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        title TEXT DEFAULT 'Untitled Document',
        content TEXT,
        raw_content TEXT,
        "lastModified" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
    );
  `);
  await client.queryObject('CREATE INDEX IF NOT EXISTS idx_documents_user_id ON documents(user_id);');
  console.log("✅ Database schema is ready.");
}

// --- تابع اصلی برای راه‌اندازی و اتصال ---
async function startServer() {
  try {
    await client.connect();
    console.log("✅ Successfully connected to PostgreSQL database.");
    await initializeSchema();
  } catch (err) {
    console.error("❌ Database connection or schema initialization failed:", err);
    // به جای Deno.exit، یک خطا throw می‌کنیم تا Deno Deploy آن را مدیریت کند.
    throw new Error("Database initialization failed. Check connection string and database status.");
  }

  // --- راه‌اندازی اپلیکیشن Hono ---
  const app = new Hono();

  // --- Middlewares ---
  app.use('*', cors({
      origin: [FRONTEND_URL, 'http://127.0.0.1:5500'],
      credentials: true
  }));
          if (existingResult.rows.length > 0) {
              return c.json({ error: 'کاربری با این ایمیل قبلاً ثبت‌نام کرده است.' }, 409);
          }
          const passwordHash = await hash(password);
          const insertResult = await client.queryObject<{ id: number; email: string }>("INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email", [email, passwordHash]);
          const user = insertResult.rows[0];
          const token = await createToken(user.id, JWT_SECRET);
          c.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'None', maxAge: 60 * 60 * 24 * 7 });
          return c.json({ user });
      } catch (error) {
          if (error instanceof z.ZodError) return c.json({ error: 'اطلاعات وارد شده معتبر نیست.', details: error.errors }, 400);
          console.error("Register Error:", error);
          return c.json({ error: 'ثبت‌نام با خطا مواجه شد.' }, 500);
      }
  });

  // --- روت‌های اسناد ---
  app.get('/api/documents', jwtMiddleware, async (c) => {
      const payload = c.get('jwtPayload');
      const result = await client.queryObject(
          'SELECT id, title, content, raw_content as "rawContent", "lastModified" FROM documents WHERE user_id = $1 ORDER BY "lastModified" DESC',
          [payload.id]
      );
      return c.json({ documents: result.rows });
  });
  
  // ... (تمام روت‌های دیگر شما در اینجا قرار می‌گیرند) ...


  // --- شروع به کار سرور ---
  Deno.serve(app.fetch);
  console.log("Server is ready and listening.");
}

// اجرای تابع اصلی برنامه
startServer().catch(err => {
  console.error("Application failed to start:", err.message);
});