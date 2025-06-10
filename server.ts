// ====================================================
// SimpleDraft API - Oak Framework (Fixed Database)
// Migration-safe, Deno Deploy Compatible
// ====================================================

import { Application, Router } from "https://deno.land/x/oak@v12.6.1/mod.ts";
import { oakCors } from "https://deno.land/x/cors@v1.2.2/mod.ts";
import { create, verify, getNumericDate } from "https://deno.land/x/djwt@v3.0.1/mod.ts";
import { Client } from "https://deno.land/x/postgres@v0.17.0/mod.ts";

// === CONFIGURATION ===
const JWT_SECRET = Deno.env.get("JWT_SECRET") || "your-super-secret-jwt-key-change-this";
const DATABASE_URL = Deno.env.get("DATABASE_URL");
const PORT = parseInt(Deno.env.get("PORT") || "8000");
const FRONTEND_URL = Deno.env.get("FRONTEND_URL") || "https://simpledraft.cyrusstudio.ir";

if (!DATABASE_URL) {
  console.error("❌ DATABASE_URL is required");
  throw new Error("DATABASE_URL is required");
}

// === PASSWORD CRYPTO ===
class SimplePasswordCrypto {
  static async hash(password: string): Promise<string> {
    const encoder = new TextEncoder();
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const passwordData = encoder.encode(password);
    
    const combined = new Uint8Array(passwordData.length + salt.length);
    combined.set(passwordData);
    combined.set(salt, passwordData.length);
    
    const hashBuffer = await crypto.subtle.digest("SHA-256", combined);
    const hashArray = new Uint8Array(hashBuffer);
    
    const result = new Uint8Array(salt.length + hashArray.length);
    result.set(salt);
    result.set(hashArray, salt.length);
    
    return btoa(String.fromCharCode(...result));
  }
  
  static async verify(password: string, storedHash: string): Promise<boolean> {
    try {
      const encoder = new TextEncoder();
      const stored = Uint8Array.from(atob(storedHash), c => c.charCodeAt(0));
      
      const salt = stored.slice(0, 16);
      const originalHash = stored.slice(16);
      
      const passwordData = encoder.encode(password);
      const combined = new Uint8Array(passwordData.length + salt.length);
      combined.set(passwordData);
      combined.set(salt, passwordData.length);
      
      const newHashBuffer = await crypto.subtle.digest("SHA-256", combined);
      const newHash = new Uint8Array(newHashBuffer);
      
      if (newHash.length !== originalHash.length) return false;
      
      let result = 0;
      for (let i = 0; i < newHash.length; i++) {
        result |= newHash[i] ^ originalHash[i];
      }
      
      return result === 0;
    } catch {
      return false;
    }
  }
}

// === DATABASE ===
const client = new Client(DATABASE_URL);

async function safeQuery(sql: string, description: string, params: any[] = []) {
  try {
    await client.queryObject(sql, params);
    console.log(`✅ ${description}`);
  } catch (error) {
    // Ignore "already exists" errors
    if (error.message.includes("already exists") || error.message.includes("duplicate")) {
      console.log(`⚠️ ${description} (already exists)`);
    } else {
      console.error(`❌ ${description}:`, error.message);
      throw error;
    }
  }
}

async function columnExists(table: string, column: string): Promise<boolean> {
  try {
    const result = await client.queryObject(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = $1 AND column_name = $2
    `, [table, column]);
    return result.rows.length > 0;
  } catch {
    return false;
  }
}

async function initDatabase() {
  try {
    await client.connect();
    console.log("✅ Connected to PostgreSQL");
    
    // Create users table
    await safeQuery(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      )
    `, "Users table created");
    
    // Create documents table (basic version)
    await safeQuery(`
      CREATE TABLE IF NOT EXISTS documents (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        title TEXT NOT NULL DEFAULT 'Untitled Document',
        content TEXT DEFAULT '',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      )
    `, "Documents table created");
    
    // Add missing columns if they don't exist
    if (!(await columnExists('documents', 'raw_content'))) {
      await safeQuery(`
        ALTER TABLE documents ADD COLUMN raw_content TEXT DEFAULT ''
      `, "Added raw_content column");
    }
    
    if (!(await columnExists('documents', 'updated_at'))) {
      await safeQuery(`
        ALTER TABLE documents ADD COLUMN updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      `, "Added updated_at column");
    }
    
    // Create indexes (only if columns exist)
    if (await columnExists('documents', 'user_id')) {
      await safeQuery(`
        CREATE INDEX IF NOT EXISTS idx_documents_user_id ON documents(user_id)
      `, "User ID index created");
    }
    
    if (await columnExists('documents', 'updated_at')) {
      await safeQuery(`
        CREATE INDEX IF NOT EXISTS idx_documents_updated_at ON documents(updated_at DESC)
      `, "Updated at index created");
    }
    
    // Update existing documents without updated_at
    await safeQuery(`
      UPDATE documents 
      SET updated_at = created_at 
      WHERE updated_at IS NULL
    `, "Updated null updated_at values");
    
    console.log("✅ Database schema ready");
  } catch (error) {
    console.error("❌ Database initialization failed:", error);
    throw error;
  }
}

// === JWT HELPERS ===
const JWT_KEY = await crypto.subtle.importKey(
  "raw",
  new TextEncoder().encode(JWT_SECRET),
  { name: "HMAC", hash: "SHA-256" },
  false,
  ["sign", "verify"]
);

async function createJWT(userId: number, email: string): Promise<string> {
  const payload = {
    sub: userId.toString(),
    email: email,
    iat: getNumericDate(new Date()),
    exp: getNumericDate(new Date(Date.now() + 7 * 24 * 60 * 60 * 1000))
  };
  
  return await create({ alg: "HS256", typ: "JWT" }, payload, JWT_KEY);
}

async function verifyJWT(token: string): Promise<{ userId: number; email: string } | null> {
  try {
    const payload = await verify(token, JWT_KEY) as any;
    return {
      userId: parseInt(payload.sub),
      email: payload.email
    };
  } catch {
    return null;
  }
}

// === MIDDLEWARE ===
async function authMiddleware(context: any, next: () => Promise<unknown>) {
  const authHeader = context.request.headers.get("authorization");
  const cookieHeader = context.request.headers.get("cookie");
  
  let token: string | null = null;
  
  if (authHeader?.startsWith("Bearer ")) {
    token = authHeader.substring(7);
  } else if (cookieHeader) {
    const cookies = cookieHeader.split(';').map(c => c.trim());
    const tokenCookie = cookies.find(c => c.startsWith('token='));
    if (tokenCookie) {
      token = tokenCookie.substring(6);
    }
  }
  
  if (!token) {
    console.log("❌ No token found");
    context.response.status = 401;
    context.response.body = { error: "Authentication required" };
    return;
  }
  
  const payload = await verifyJWT(token);
  if (!payload) {
    console.log("❌ Invalid token");
    context.response.status = 401;
    context.response.body = { error: "Invalid or expired token" };
    return;
  }
  
  const userResult = await client.queryObject(
    "SELECT id, email FROM users WHERE id = $1",
    [payload.userId]
  );
  
  if (userResult.rows.length === 0) {
    console.log("❌ User not found:", payload.userId);
    context.response.status = 401;
    context.response.body = { error: "User not found" };
    return;
  }
  
  context.state.user = userResult.rows[0];
  console.log("✅ User authenticated:", payload.email);
  
  await next();
}

// === ROUTES ===
const router = new Router();

// Health check
router.get("/", (context) => {
  context.response.body = {
    message: "SimpleDraft API - Oak Framework (Migration Safe)",
    version: "1.1",
    framework: "Oak",
    timestamp: new Date().toISOString()
  };
});

router.get("/health", (context) => {
  context.response.body = { status: "healthy", framework: "Oak" };
});

// === AUTH ROUTES ===

// Register
router.post("/api/auth/register", async (context) => {
  try {
    const body = await context.request.body({ type: "json" }).value;
    const { email, password } = body;
    
    console.log("🔵 Register attempt:", email);
    
    if (!email || !password) {
      context.response.status = 400;
      context.response.body = { error: "Email and password are required" };
      return;
    }
    
    const existingUser = await client.queryObject(
      "SELECT id FROM users WHERE email = $1",
      [email.toLowerCase()]
    );
    
    if (existingUser.rows.length > 0) {
      console.log("❌ User already exists:", email);
      context.response.status = 409;
      context.response.body = { error: "User already exists" };
      return;
    }
    
    const passwordHash = await SimplePasswordCrypto.hash(password);
    
    const result = await client.queryObject(
      "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email, created_at",
      [email.toLowerCase(), passwordHash]
    );
    
    const user = result.rows[0] as any;
    console.log("✅ User created:", user.email);
    
    const token = await createJWT(user.id, user.email);
    
    context.response.headers.set(
      "Set-Cookie", 
      `token=${token}; HttpOnly; Secure; SameSite=None; Max-Age=${7 * 24 * 60 * 60}; Path=/`
    );
    
    context.response.body = {
      user: { id: user.id, email: user.email, createdAt: user.created_at },
      message: "Registration successful"
    };
    
  } catch (error) {
    console.error("❌ Register error:", error);
    context.response.status = 500;
    context.response.body = { error: "Registration failed" };
  }
});

// Login
router.post("/api/auth/login", async (context) => {
  try {
    const body = await context.request.body({ type: "json" }).value;
    const { email, password } = body;
    
    console.log("🔵 Login attempt:", email);
    
    if (!email || !password) {
      context.response.status = 400;
      context.response.body = { error: "Email and password are required" };
      return;
    }
    
    const result = await client.queryObject(
      "SELECT id, email, password_hash, created_at FROM users WHERE email = $1",
      [email.toLowerCase()]
    );
    
    if (result.rows.length === 0) {
      console.log("❌ User not found:", email);
      context.response.status = 401;
      context.response.body = { error: "Invalid credentials" };
      return;
    }
    
    const user = result.rows[0] as any;
    
    const validPassword = await SimplePasswordCrypto.verify(password, user.password_hash);
    
    if (!validPassword) {
      console.log("❌ Invalid password for:", email);
      context.response.status = 401;
      context.response.body = { error: "Invalid credentials" };
      return;
    }
    
    const token = await createJWT(user.id, user.email);
    
    context.response.headers.set(
      "Set-Cookie", 
      `token=${token}; HttpOnly; Secure; SameSite=None; Max-Age=${7 * 24 * 60 * 60}; Path=/`
    );
    
    console.log("✅ User logged in:", user.email);
    
    context.response.body = {
      user: { id: user.id, email: user.email, createdAt: user.created_at },
      message: "Login successful"
    };
    
  } catch (error) {
    console.error("❌ Login error:", error);
    context.response.status = 500;
    context.response.body = { error: "Login failed" };
  }
});

// Logout
router.post("/api/auth/logout", (context) => {
  context.response.headers.set(
    "Set-Cookie", 
    "token=; HttpOnly; Secure; SameSite=None; Max-Age=0; Path=/"
  );
  context.response.body = { message: "Logout successful" };
});

// === DOCUMENT ROUTES (Protected) ===

// Get all documents
router.get("/api/documents", authMiddleware, async (context) => {
  try {
    const user = context.state.user;
    console.log("🔵 Fetching documents for user:", user.email);
    
    // Check if updated_at column exists
    const hasUpdatedAt = await columnExists('documents', 'updated_at');
    const hasRawContent = await columnExists('documents', 'raw_content');
    
    let query = `SELECT id, title, content, created_at`;
    if (hasRawContent) query += `, raw_content`;
    if (hasUpdatedAt) query += `, updated_at`;
    query += ` FROM documents WHERE user_id = $1`;
    if (hasUpdatedAt) {
      query += ` ORDER BY updated_at DESC`;
    } else {
      query += ` ORDER BY created_at DESC`;
    }
    
    const result = await client.queryObject(query, [user.id]);
    
    const documents = result.rows.map((row: any) => ({
      id: row.id,
      title: row.title,
      content: row.content,
      rawContent: hasRawContent ? row.raw_content : '',
      createdAt: row.created_at,
      lastModified: hasUpdatedAt ? row.updated_at : row.created_at
    }));
    
    console.log(`✅ Found ${documents.length} documents`);
    
    context.response.body = { documents };
    
  } catch (error) {
    console.error("❌ Get documents error:", error);
    context.response.status = 500;
    context.response.body = { error: "Failed to fetch documents" };
  }
});

// Create document
router.post("/api/documents", authMiddleware, async (context) => {
  try {
    const user = context.state.user;
    const body = await context.request.body({ type: "json" }).value;
    
    console.log("🔵 Creating document for user:", user.email);
    console.log("🔵 Document data:", body);
    
    const title = body.title || "Untitled Document";
    const content = body.content || "";
    const rawContent = body.rawContent || "";
    
    // Check which columns exist
    const hasUpdatedAt = await columnExists('documents', 'updated_at');
    const hasRawContent = await columnExists('documents', 'raw_content');
    
    let query = `INSERT INTO documents (user_id, title, content`;
    let values = `($1, $2, $3`;
    const params = [user.id, title, content];
    let paramCount = 3;
    
    if (hasRawContent) {
      query += `, raw_content`;
      values += `, $${++paramCount}`;
      params.push(rawContent);
    }
    
    if (hasUpdatedAt) {
      query += `, updated_at`;
      values += `, CURRENT_TIMESTAMP`;
    }
    
    query += `) VALUES ${values}) RETURNING id, title, content, created_at`;
    if (hasRawContent) query += `, raw_content`;
    if (hasUpdatedAt) query += `, updated_at`;
    
    const result = await client.queryObject(query, params);
    
    const document = result.rows[0] as any;
    
    console.log("✅ Document created with ID:", document.id);
    
    context.response.status = 201;
    context.response.body = {
      document: {
        id: document.id,
        title: document.title,
        content: document.content,
        rawContent: hasRawContent ? document.raw_content : rawContent,
        createdAt: document.created_at,
        lastModified: hasUpdatedAt ? document.updated_at : document.created_at
      },
      message: "Document created successfully"
    };
    
  } catch (error) {
    console.error("❌ Create document error:", error);
    context.response.status = 500;
    context.response.body = { error: "Failed to create document" };
  }
});

// Update document
router.put("/api/documents/:id", authMiddleware, async (context) => {
  try {
    const user = context.state.user;
    const documentId = parseInt(context.params.id!);
    const body = await context.request.body({ type: "json" }).value;
    
    console.log(`🔵 Updating document ${documentId} for user:`, user.email);
    
    if (isNaN(documentId)) {
      context.response.status = 400;
      context.response.body = { error: "Invalid document ID" };
      return;
    }
    
    // Check which columns exist
    const hasUpdatedAt = await columnExists('documents', 'updated_at');
    const hasRawContent = await columnExists('documents', 'raw_content');
    
    let query = `UPDATE documents SET title = $1, content = $2`;
    const params = [body.title, body.content];
    let paramCount = 2;
    
    if (hasRawContent) {
      query += `, raw_content = $${++paramCount}`;
      params.push(body.rawContent);
    }
    
    if (hasUpdatedAt) {
      query += `, updated_at = CURRENT_TIMESTAMP`;
    }
    
    query += ` WHERE id = $${++paramCount} AND user_id = $${++paramCount}`;
    params.push(documentId, user.id);
    
    query += ` RETURNING id, title, content, created_at`;
    if (hasRawContent) query += `, raw_content`;
    if (hasUpdatedAt) query += `, updated_at`;
    
    const result = await client.queryObject(query, params);
    
    if (result.rows.length === 0) {
      context.response.status = 404;
      context.response.body = { error: "Document not found or access denied" };
      return;
    }
    
    const document = result.rows[0] as any;
    
    console.log("✅ Document updated successfully");
    
    context.response.body = {
      document: {
        id: document.id,
        title: document.title,
        content: document.content,
        rawContent: hasRawContent ? document.raw_content : body.rawContent,
        lastModified: hasUpdatedAt ? document.updated_at : document.created_at
      },
      message: "Document updated successfully"
    };
    
  } catch (error) {
    console.error("❌ Update document error:", error);
    context.response.status = 500;
    context.response.body = { error: "Failed to update document" };
  }
});

// Delete document
router.delete("/api/documents/:id", authMiddleware, async (context) => {
  try {
    const user = context.state.user;
    const documentId = parseInt(context.params.id!);
    
    console.log(`🔵 Deleting document ${documentId} for user:`, user.email);
    
    if (isNaN(documentId)) {
      context.response.status = 400;
      context.response.body = { error: "Invalid document ID" };
      return;
    }
    
    const result = await client.queryObject(
      "DELETE FROM documents WHERE id = $1 AND user_id = $2 RETURNING id",
      [documentId, user.id]
    );
    
    if (result.rows.length === 0) {
      context.response.status = 404;
      context.response.body = { error: "Document not found or access denied" };
      return;
    }
    
    console.log("✅ Document deleted successfully");
    
    context.response.body = { 
      message: "Document deleted successfully",
      deletedId: documentId 
    };
    
  } catch (error) {
    console.error("❌ Delete document error:", error);
    context.response.status = 500;
    context.response.body = { error: "Failed to delete document" };
  }
});

// === APPLICATION SETUP ===
const app = new Application();

// Global error handler
app.addEventListener("error", (evt) => {
  console.error("❌ Application error:", evt.error);
});

// CORS middleware
app.use(oakCors({
  origin: [FRONTEND_URL, "http://127.0.0.1:5500", "http://localhost:3000"],
  credentials: true,
  allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowHeaders: ["Content-Type", "Authorization"]
}));

// Request logging
app.use(async (context, next) => {
  const start = Date.now();
  await next();
  const ms = Date.now() - start;
  console.log(`${context.request.method} ${context.request.url.pathname} - ${context.response.status} - ${ms}ms`);
});

// Routes
app.use(router.routes());
app.use(router.allowedMethods());

// === START SERVER ===
async function startServer() {
  try {
    await initDatabase();
    
    console.log(`🚀 SimpleDraft API (Oak Framework) starting...`);
    console.log(`📄 Frontend: ${FRONTEND_URL}`);
    console.log(`🔐 JWT Authentication: ✅ Enabled`);
    console.log(`💾 Database: ✅ Connected & Migrated`);
    console.log(`🌐 Port: ${PORT}`);
    
    await app.listen({ port: PORT });
    
  } catch (error) {
    console.error("❌ Server startup failed:", error);
    throw error; // Don't use Deno.exit() in Deno Deploy
  }
}

// === START APPLICATION ===
if (import.meta.main) {
  startServer();
}