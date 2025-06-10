// ====================================================
// SimpleDraft Backend Server (v4.2 - Fixed Document Creation)
// Production-ready Deno 2.x server with fixed CRUD operations
// ====================================================

import { Hono } from "hono";
import { cors } from "hono/cors";
import { jwt, sign, verify } from "hono/jwt";
import { Client } from "postgres";
import { z } from "zod";

// --- Environment Configuration ---
const JWT_SECRET = Deno.env.get("JWT_SECRET");
const DATABASE_URL = Deno.env.get("DATABASE_URL");
const FRONTEND_URL = Deno.env.get("FRONTEND_URL") || "https://simpledraft.cyrusstudio.ir";
const PORT = parseInt(Deno.env.get("PORT") || "8000");

// Critical environment validation
if (!JWT_SECRET || !DATABASE_URL) {
  console.error("❌ FATAL: Missing required environment variables (JWT_SECRET, DATABASE_URL)");
  Deno.exit(1);
}

// --- Database Client Setup ---
const client = new Client(DATABASE_URL);

// --- Password Hashing with Web Crypto API ---
class PasswordCrypto {
  private static readonly ITERATIONS = 100000;
  private static readonly KEY_LENGTH = 64;
  private static readonly SALT_LENGTH = 16;

  static async hash(password: string): Promise<string> {
    try {
      const salt = crypto.getRandomValues(new Uint8Array(this.SALT_LENGTH));
      const passwordBuffer = new TextEncoder().encode(password);
      
      const keyMaterial = await crypto.subtle.importKey(
        "raw",
        passwordBuffer,
        "PBKDF2",
        false,
        ["deriveBits"]
      );
      
      const derivedKey = await crypto.subtle.deriveBits(
        {
          name: "PBKDF2",
          salt: salt,
          iterations: this.ITERATIONS,
          hash: "SHA-256"
        },
        keyMaterial,
        this.KEY_LENGTH * 8
      );
      
      const hashArray = new Uint8Array(this.SALT_LENGTH + this.KEY_LENGTH);
      hashArray.set(salt, 0);
      hashArray.set(new Uint8Array(derivedKey), this.SALT_LENGTH);
      
      return btoa(String.fromCharCode(...hashArray));
    } catch (error) {
      console.error("Password hashing failed:", error);
      throw new Error("Password hashing failed");
    }
  }

  static async verify(password: string, storedHash: string): Promise<boolean> {
    try {
      const hashArray = new Uint8Array(
        atob(storedHash).split('').map(char => char.charCodeAt(0))
      );
      
      const salt = hashArray.slice(0, this.SALT_LENGTH);
      const storedKey = hashArray.slice(this.SALT_LENGTH);
      const passwordBuffer = new TextEncoder().encode(password);
      
      const keyMaterial = await crypto.subtle.importKey(
        "raw",
        passwordBuffer,
        "PBKDF2",
        false,
        ["deriveBits"]
      );
      
      const derivedKey = await crypto.subtle.deriveBits(
        {
          name: "PBKDF2",
          salt: salt,
          iterations: this.ITERATIONS,
          hash: "SHA-256"
        },
        keyMaterial,
        this.KEY_LENGTH * 8
      );
      
      const derivedKeyArray = new Uint8Array(derivedKey);
      
      if (derivedKeyArray.length !== storedKey.length) {
        return false;
      }
      
      let result = 0;
      for (let i = 0; i < derivedKeyArray.length; i++) {
        result |= derivedKeyArray[i] ^ storedKey[i];
      }
      
      return result === 0;
    } catch (error) {
      console.error("Password verification failed:", error);
      return false;
    }
  }
}

// --- Validation Schemas ---
const authSchema = z.object({
  email: z.string().email("Invalid email format").max(255),
  password: z.string().min(6, "Password must be at least 6 characters").max(128)
});

// اصلاح schema برای documents
const documentSchema = z.object({
  title: z.string().min(1, "Title is required").max(255).default("Untitled Document"),
  content: z.string().optional().default(""),
  rawContent: z.string().optional().default("")
});

const documentUpdateSchema = z.object({
  title: z.string().min(1, "Title is required").max(255),
  content: z.string().optional().default(""),
  rawContent: z.string().optional().default("")
});

// --- Database Schema Initialization ---
async function initializeDatabase() {
  try {
    // Users table
    await client.queryObject(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Documents table  
    await client.queryObject(`
      CREATE TABLE IF NOT EXISTS documents (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        title TEXT NOT NULL DEFAULT 'Untitled Document',
        content TEXT DEFAULT '',
        raw_content TEXT DEFAULT '',
        "lastModified" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Indexes for performance
    await client.queryObject(`
      CREATE INDEX IF NOT EXISTS idx_documents_user_id ON documents(user_id);
      CREATE INDEX IF NOT EXISTS idx_documents_last_modified ON documents("lastModified" DESC);
      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
    `);

    console.log("✅ Database schema initialized successfully");
  } catch (error) {
    console.error("❌ Database schema initialization failed:", error);
    throw error;
  }
}

// --- Utility Functions ---
async function generateJWT(userId: number): Promise<string> {
  const payload = {
    id: userId,
    exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24 * 7)
  };
  return await sign(payload, JWT_SECRET!);
}

async function verifyJWT(token: string): Promise<{ id: number } | null> {
  try {
    const payload = await verify(token, JWT_SECRET!) as { id: number };
    return payload;
  } catch {
    return null;
  }
}

function setCookieHeader(token: string) {
  return `token=${token}; HttpOnly; Secure; SameSite=None; Max-Age=${60 * 60 * 24 * 7}; Path=/`;
}

function clearCookieHeader() {
  return "token=; HttpOnly; Secure; SameSite=None; Max-Age=0; Path=/";
}

// --- Authentication Middleware ---
async function authMiddleware(c: any, next: () => Promise<void>) {
  try {
    const token = c.req.header("cookie")?.match(/token=([^;]+)/)?.[1];
    
    if (!token) {
      console.log("❌ No token found in cookies");
      return c.json({ error: "Authentication required" }, 401);
    }

    const payload = await verifyJWT(token);
    if (!payload) {
      console.log("❌ Invalid JWT token");
      return c.json({ error: "Invalid or expired token" }, 401);
    }

    const userResult = await client.queryObject<{ id: number; email: string }>(
      "SELECT id, email FROM users WHERE id = $1",
      [payload.id]
    );

    if (userResult.rows.length === 0) {
      console.log("❌ User not found for ID:", payload.id);
      return c.json({ error: "User not found" }, 401);
    }

    console.log("✅ User authenticated:", userResult.rows[0].email);
    c.set("user", userResult.rows[0]);
    await next();
  } catch (error) {
    console.error("❌ Auth middleware error:", error);
    return c.json({ error: "Authentication failed" }, 401);
  }
}

// --- Server Initialization ---
async function startServer() {
  try {
    await client.connect();
    console.log("✅ Connected to PostgreSQL database");
    
    await initializeDatabase();
    
    const app = new Hono();

    // CORS Configuration
    app.use('*', cors({
      origin: [FRONTEND_URL, 'http://127.0.0.1:5500', 'http://localhost:3000'],
      credentials: true,
      allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowHeaders: ['Content-Type', 'Authorization']
    }));

    // Health Check
    app.get('/health', (c) => c.json({ 
      status: 'healthy', 
      timestamp: new Date().toISOString(),
      version: '4.2',
      crypto: 'Web Crypto API'
    }));

    app.get('/', (c) => c.json({ 
      message: 'SimpleDraft API v4.2 - Fixed Document Creation',
      endpoints: {
        auth: ['/api/auth/register', '/api/auth/login', '/api/auth/logout'],
        documents: ['/api/documents (GET/POST)', '/api/documents/:id (PUT/DELETE)']
      }
    }));

    // === AUTHENTICATION ROUTES ===

    // User Registration
    app.post('/api/auth/register', async (c) => {
      try {
        const body = await c.req.json();
        console.log("📝 Registration attempt for:", body.email);
        
        const { email, password } = authSchema.parse(body);

        const existingResult = await client.queryObject<{ id: number }>(
          "SELECT id FROM users WHERE email = $1",
          [email.toLowerCase()]
        );

        if (existingResult.rows.length > 0) {
          console.log("❌ User already exists:", email);
          return c.json({ error: "User with this email already exists" }, 409);
        }

        console.log("🔐 Hashing password...");
        const passwordHash = await PasswordCrypto.hash(password);
        
        console.log("👤 Creating user in database...");
        const insertResult = await client.queryObject<{ id: number; email: string; created_at: string }>(
          "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email, created_at",
          [email.toLowerCase(), passwordHash]
        );

        const user = insertResult.rows[0];
        console.log("✅ User created with ID:", user.id);
        
        const token = await generateJWT(user.id);
        c.header("Set-Cookie", setCookieHeader(token));

        return c.json({
          user: {
            id: user.id,
            email: user.email,
            createdAt: user.created_at
          },
          message: "Registration successful"
        });

      } catch (error) {
        if (error instanceof z.ZodError) {
          console.log("❌ Validation error:", error.errors);
          return c.json({ 
            error: "Invalid input data", 
            details: error.errors.map(e => ({ field: e.path.join('.'), message: e.message }))
          }, 400);
        }
        
        console.error("❌ Registration error:", error);
        return c.json({ 
          error: "Registration failed", 
          details: error.message 
        }, 500);
      }
    });

    // User Login
    app.post('/api/auth/login', async (c) => {
      try {
        const body = await c.req.json();
        console.log("🔐 Login attempt for:", body.email);
        
        const { email, password } = authSchema.parse(body);

        console.log("👤 Finding user in database...");
        const userResult = await client.queryObject<{ 
          id: number; 
          email: string; 
          password_hash: string; 
          created_at: string;
        }>(
          "SELECT id, email, password_hash, created_at FROM users WHERE email = $1",
          [email.toLowerCase()]
        );

        if (userResult.rows.length === 0) {
          console.log("❌ User not found:", email);
          return c.json({ error: "Invalid email or password" }, 401);
        }

        const user = userResult.rows[0];
        console.log("✅ User found with ID:", user.id);

        console.log("🔐 Verifying password...");
        const passwordValid = await PasswordCrypto.verify(password, user.password_hash);
        
        if (!passwordValid) {
          console.log("❌ Invalid password for:", email);
          return c.json({ error: "Invalid email or password" }, 401);
        }

        console.log("✅ Password verified successfully");

        const token = await generateJWT(user.id);
        c.header("Set-Cookie", setCookieHeader(token));

        return c.json({
          user: {
            id: user.id,
            email: user.email,
            createdAt: user.created_at
          },
          message: "Login successful"
        });

      } catch (error) {
        if (error instanceof z.ZodError) {
          console.log("❌ Validation error:", error.errors);
          return c.json({ 
            error: "Invalid input data", 
            details: error.errors.map(e => ({ field: e.path.join('.'), message: e.message }))
          }, 400);
        }
        
        console.error("❌ Login error:", error);
        return c.json({ 
          error: "Login failed", 
          details: error.message 
        }, 500);
      }
    });

    // User Logout
    app.post('/api/auth/logout', (c) => {
      c.header("Set-Cookie", clearCookieHeader());
      return c.json({ message: "Logout successful" });
    });

    // === DOCUMENT ROUTES ===

    // Get all documents for authenticated user
    app.get('/api/documents', authMiddleware, async (c) => {
      try {
        const user = c.get("user");
        console.log("📄 Fetching documents for user:", user.email);
        
        const result = await client.queryObject<{
          id: number;
          title: string;
          content: string;
          raw_content: string;
          lastModified: string;
          created_at: string;
        }>(
          `SELECT id, title, content, raw_content, "lastModified", created_at 
           FROM documents 
           WHERE user_id = $1 
           ORDER BY "lastModified" DESC`,
          [user.id]
        );

        console.log(`✅ Found ${result.rows.length} documents for user ${user.email}`);

        return c.json({ 
          documents: result.rows.map(doc => ({
            id: doc.id,
            title: doc.title,
            content: doc.content,
            rawContent: doc.raw_content,
            lastModified: doc.lastModified,
            createdAt: doc.created_at
          }))
        });

      } catch (error) {
        console.error("❌ Get documents error:", error);
        return c.json({ 
          error: "Failed to fetch documents",
          details: error.message 
        }, 500);
      }
    });

    // Create new document - اصلاح شده
    app.post('/api/documents', authMiddleware, async (c) => {
      try {
        const user = c.get("user");
        console.log("📝 Creating new document for user:", user.email);
        
        // دریافت body و validation
        let body;
        try {
          body = await c.req.json();
          console.log("📄 Document data received:", body);
        } catch (error) {
          console.error("❌ JSON parsing error:", error);
          return c.json({ error: "Invalid JSON format" }, 400);
        }

        // Parse و validate کردن data
        const validatedData = documentSchema.parse(body);
        console.log("✅ Document data validated:", validatedData);
        
        const { title, content, rawContent } = validatedData;

        // Insert در database
        const result = await client.queryObject<{
          id: number;
          title: string;
          content: string;
          raw_content: string;
          lastModified: string;
          created_at: string;
        }>(
          `INSERT INTO documents (user_id, title, content, raw_content, "lastModified") 
           VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP) 
           RETURNING id, title, content, raw_content, "lastModified", created_at`,
          [user.id, title, content || "", rawContent || ""]
        );

        if (result.rows.length === 0) {
          throw new Error("Document creation failed - no rows returned");
        }

        const document = result.rows[0];
        console.log("✅ Document created successfully with ID:", document.id);

        return c.json({
          document: {
            id: document.id,
            title: document.title,
            content: document.content,
            rawContent: document.raw_content,
            lastModified: document.lastModified,
            createdAt: document.created_at
          },
          message: "Document created successfully"
        }, 201);

      } catch (error) {
        if (error instanceof z.ZodError) {
          console.error("❌ Validation error:", error.errors);
          return c.json({ 
            error: "Invalid document data", 
            details: error.errors.map(e => ({ 
              field: e.path.join('.'), 
              message: e.message 
            }))
          }, 400);
        }
        
        console.error("❌ Create document error:", error);
        return c.json({ 
          error: "Failed to create document",
          details: error.message 
        }, 500);
      }
    });

    // Update document
    app.put('/api/documents/:id', authMiddleware, async (c) => {
      try {
        const user = c.get("user");
        const documentId = parseInt(c.req.param('id'));
        
        if (isNaN(documentId)) {
          return c.json({ error: "Invalid document ID" }, 400);
        }

        console.log(`📝 Updating document ${documentId} for user:`, user.email);

        const body = await c.req.json();
        const validatedData = documentUpdateSchema.parse(body);
        const { title, content, rawContent } = validatedData;

        // Verify document ownership
        const ownershipResult = await client.queryObject<{ id: number }>(
          "SELECT id FROM documents WHERE id = $1 AND user_id = $2",
          [documentId, user.id]
        );

        if (ownershipResult.rows.length === 0) {
          console.log(`❌ Document ${documentId} not found or access denied for user:`, user.email);
          return c.json({ error: "Document not found or access denied" }, 404);
        }

        // Update document
        const result = await client.queryObject<{
          id: number;
          title: string;
          content: string;
          raw_content: string;
          lastModified: string;
        }>(
          `UPDATE documents 
           SET title = $1, content = $2, raw_content = $3, "lastModified" = CURRENT_TIMESTAMP
           WHERE id = $4 AND user_id = $5
           RETURNING id, title, content, raw_content, "lastModified"`,
          [title, content || "", rawContent || "", documentId, user.id]
        );

        const document = result.rows[0];
        console.log(`✅ Document ${documentId} updated successfully`);

        return c.json({
          document: {
            id: document.id,
            title: document.title,
            content: document.content,
            rawContent: document.raw_content,
            lastModified: document.lastModified
          },
          message: "Document updated successfully"
        });

      } catch (error) {
        if (error instanceof z.ZodError) {
          return c.json({ 
            error: "Invalid document data", 
            details: error.errors.map(e => ({ field: e.path.join('.'), message: e.message }))
          }, 400);
        }
        
        console.error("❌ Update document error:", error);
        return c.json({ 
          error: "Failed to update document",
          details: error.message 
        }, 500);
      }
    });

    // Delete document
    app.delete('/api/documents/:id', authMiddleware, async (c) => {
      try {
        const user = c.get("user");
        const documentId = parseInt(c.req.param('id'));
        
        if (isNaN(documentId)) {
          return c.json({ error: "Invalid document ID" }, 400);
        }

        console.log(`🗑️ Deleting document ${documentId} for user:`, user.email);

        // Verify document ownership and delete
        const result = await client.queryObject<{ id: number }>(
          "DELETE FROM documents WHERE id = $1 AND user_id = $2 RETURNING id",
          [documentId, user.id]
        );

        if (result.rows.length === 0) {
          console.log(`❌ Document ${documentId} not found or access denied for user:`, user.email);
          return c.json({ error: "Document not found or access denied" }, 404);
        }

        console.log(`✅ Document ${documentId} deleted successfully`);

        return c.json({ 
          message: "Document deleted successfully",
          deletedId: documentId 
        });

      } catch (error) {
        console.error("❌ Delete document error:", error);
        return c.json({ 
          error: "Failed to delete document",
          details: error.message 
        }, 500);
      }
    });

    // === ERROR HANDLING ===
    app.notFound((c) => {
      return c.json({ error: "Endpoint not found" }, 404);
    });

    app.onError((err, c) => {
      console.error("Global error handler:", err);
      return c.json({ 
        error: "Internal server error",
        details: err.message 
      }, 500);
    });

    // === SERVER STARTUP ===
    console.log(`🚀 SimpleDraft API v4.2 starting on port ${PORT}`);
    console.log(`📄 Frontend: ${FRONTEND_URL}`);
    console.log(`🔐 Authentication: Web Crypto API (PBKDF2)`);
    console.log(`💾 Database: ✅ Connected`);

    Deno.serve({ port: PORT }, app.fetch);
    
  } catch (error) {
    console.error("❌ Server startup failed:", error);
    Deno.exit(1);
  }
}

// === GRACEFUL SHUTDOWN ===
async function gracefulShutdown() {
  console.log("\n⏳ Gracefully shutting down...");
  try {
    await client.end();
    console.log("✅ Database connection closed");
  } catch (error) {
    console.error("❌ Error during shutdown:", error);
  }
  Deno.exit(0);
}

// Handle shutdown signals
Deno.addSignalListener("SIGINT", gracefulShutdown);
Deno.addSignalListener("SIGTERM", gracefulShutdown);

// === APPLICATION ENTRY POINT ===
if (import.meta.main) {
  startServer().catch((error) => {
    console.error("💥 Fatal error:", error);
    Deno.exit(1);
  });
}