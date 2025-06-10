// ====================================================
// SimpleDraft API - Oak Framework Version
// Stable, Express-like, Production Ready
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
  Deno.exit(1);
}

// === PASSWORD CRYPTO ===
class SimplePasswordCrypto {
  static async hash(password: string): Promise<string> {
    const encoder = new TextEncoder();
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const passwordData = encoder.encode(password);
    
    // Combine password + salt
    const combined = new Uint8Array(passwordData.length + salt.length);
    combined.set(passwordData);
    combined.set(salt, passwordData.length);
    
    // Hash with SHA-256
    const hashBuffer = await crypto.subtle.digest("SHA-256", combined);
    const hashArray = new Uint8Array(hashBuffer);
    
    // Combine salt + hash for storage
    const result = new Uint8Array(salt.length + hashArray.length);
    result.set(salt);
    result.set(hashArray, salt.length);
    
    // Convert to base64
    return btoa(String.fromCharCode(...result));
  }
  
  static async verify(password: string, storedHash: string): Promise<boolean> {
    try {
      const encoder = new TextEncoder();
      const stored = Uint8Array.from(atob(storedHash), c => c.charCodeAt(0));
      
      // Extract salt (first 16 bytes) and hash (rest)
      const salt = stored.slice(0, 16);
      const originalHash = stored.slice(16);
      
      // Hash the provided password with same salt
      const passwordData = encoder.encode(password);
      const combined = new Uint8Array(passwordData.length + salt.length);
      combined.set(passwordData);
      combined.set(salt, passwordData.length);
      
      const newHashBuffer = await crypto.subtle.digest("SHA-256", combined);
      const newHash = new Uint8Array(newHashBuffer);
      
      // Compare hashes
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

async function initDatabase() {
  try {
    await client.connect();
    console.log("✅ Connected to PostgreSQL");
    
    // Create tables
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
        title TEXT NOT NULL DEFAULT 'Untitled Document',
        content TEXT DEFAULT '',
        raw_content TEXT DEFAULT '',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `);
    
    // Indexes
    await client.queryObject(`
      CREATE INDEX IF NOT EXISTS idx_documents_user_id ON documents(user_id);
      CREATE INDEX IF NOT EXISTS idx_documents_updated_at ON documents(updated_at DESC);
    `);
    
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
    exp: getNumericDate(new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)) // 7 days
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
  
  // Try to get token from Authorization header
  if (authHeader?.startsWith("Bearer ")) {
    token = authHeader.substring(7);
  }
  // Try to get token from cookie
  else if (cookieHeader) {
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
  
  // Verify user still exists
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
  
  // Attach user to context
  context.state.user = userResult.rows[0];
  console.log("✅ User authenticated:", payload.email);
  
  await next();
}

// === ROUTES ===
const router = new Router();

// Health check
router.get("/", (context) => {
  context.response.body = {
    message: "SimpleDraft API - Oak Framework",
    version: "1.0",
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
    
    // Check if user exists
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
    
    // Hash password
    const passwordHash = await SimplePasswordCrypto.hash(password);
    
    // Create user
    const result = await client.queryObject(
      "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email, created_at",
      [email.toLowerCase(), passwordHash]
    );
    
    const user = result.rows[0] as any;
    console.log("✅ User created:", user.email);
    
    // Create JWT
    const token = await createJWT(user.id, user.email);
    
    // Set cookie
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
    
    // Find user
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
    
    // Verify password
    const validPassword = await SimplePasswordCrypto.verify(password, user.password_hash);
    
    if (!validPassword) {
      console.log("❌ Invalid password for:", email);
      context.response.status = 401;
      context.response.body = { error: "Invalid credentials" };
      return;
    }
    
    // Create JWT
    const token = await createJWT(user.id, user.email);
    
    // Set cookie
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
    
    const result = await client.queryObject(
      `SELECT id, title, content, raw_content, created_at, updated_at 
       FROM documents 
       WHERE user_id = $1 
       ORDER BY updated_at DESC`,
      [user.id]
    );
    
    const documents = result.rows.map((row: any) => ({
      id: row.id,
      title: row.title,
      content: row.content,
      rawContent: row.raw_content,
      createdAt: row.created_at,
      lastModified: row.updated_at
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
    
    const result = await client.queryObject(
      `INSERT INTO documents (user_id, title, content, raw_content, updated_at) 
       VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP) 
       RETURNING id, title, content, raw_content, created_at, updated_at`,
      [user.id, title, content, rawContent]
    );
    
    const document = result.rows[0] as any;
    
    console.log("✅ Document created with ID:", document.id);
    
    context.response.status = 201;
    context.response.body = {
      document: {
        id: document.id,
        title: document.title,
        content: document.content,
        rawContent: document.raw_content,
        createdAt: document.created_at,
        lastModified: document.updated_at
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
    
    const result = await client.queryObject(
      `UPDATE documents 
       SET title = $1, content = $2, raw_content = $3, updated_at = CURRENT_TIMESTAMP
       WHERE id = $4 AND user_id = $5
       RETURNING id, title, content, raw_content, updated_at`,
      [body.title, body.content, body.rawContent, documentId, user.id]
    );
    
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
        rawContent: document.raw_content,
        lastModified: document.updated_at
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
    console.log(`💾 Database: ✅ Connected`);
    console.log(`🌐 Port: ${PORT}`);
    
    await app.listen({ port: PORT });
    
  } catch (error) {
    console.error("❌ Server startup failed:", error);
    Deno.exit(1);
  }
}

// Graceful shutdown
const gracefulShutdown = async () => {
  console.log("\n⏳ Gracefully shutting down...");
  try {
    await client.end();
    console.log("✅ Database connection closed");
  } catch (error) {
    console.error("❌ Error during shutdown:", error);
  }
  Deno.exit(0);
};

Deno.addSignalListener("SIGINT", gracefulShutdown);
Deno.addSignalListener("SIGTERM", gracefulShutdown);

// === START APPLICATION ===
if (import.meta.main) {
  startServer();
}