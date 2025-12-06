const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcrypt');
const session = require('express-session');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = 3000;
const DB_PATH = path.join(__dirname, 'tenants.db');

app.use(cookieParser());
app.use(express.json());
app.use(express.static('public'));
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'change-this-secret-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    },
  })
);

const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
    process.exit(1);
  }
  console.log('Connected to SQLite database');
});

db.serialize(() => {
  db.run(
    `
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `,
    (err) => {
      if (err) {
        console.error('Error creating users table:', err.message);
      } else {
        console.log('Users table ready');
      }
    }
  );

  db.run(
    `
        CREATE TABLE IF NOT EXISTS tenants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            domain TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            themeColor TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    `,
    (err) => {
      if (err) {
        console.error('Error creating tenants table:', err.message);
      } else {
        console.log('Tenants table ready');
      }
    }
  );

  db.run(
    `
        CREATE INDEX IF NOT EXISTS idx_tenants_user_id ON tenants(user_id)
    `,
    (err) => {
      if (err) {
        console.error('Error creating index:', err.message);
      }
    }
  );
});

function getTenantByDomain(domain, callback) {
  db.get('SELECT * FROM tenants WHERE domain = ?', [domain], callback);
}

function getUserByEmail(email, callback) {
  db.get('SELECT * FROM users WHERE email = ?', [email], callback);
}

function getUserById(id, callback) {
  db.get(
    'SELECT id, email, created_at FROM users WHERE id = ?',
    [id],
    callback
  );
}

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  next();
}

app.get('/allow-host', (req, res) => {
  const domain = req.query.domain;

  if (!domain) {
    return res.status(400).json({ error: 'domain parameter required' });
  }

  getTenantByDomain(domain, (err, tenant) => {
    if (err) {
      console.error('Error checking tenant:', err.message);
      return res.status(500).json({ error: 'Database error' });
    }

    if (tenant) {
      console.log(`Certificate allowed for domain: ${domain}`);
      return res.status(200).json({ allowed: true });
    } else {
      console.log(`Certificate denied for domain: ${domain}`);
      return res.status(403).json({ allowed: false });
    }
  });
});

function tenantMiddleware(req, res, next) {
  const hostname = req.hostname || req.get('host')?.split(':')[0];

  if (!hostname) {
    return res.status(400).json({ error: 'Host header required' });
  }

  getTenantByDomain(hostname, (err, tenant) => {
    if (err) {
      console.error('Error loading tenant:', err.message);
      return res.status(500).json({ error: 'Database error' });
    }

    if (!tenant) {
      console.log(`Tenant not found for hostname: ${hostname}`);
      return res.status(404).json({ error: 'Tenant not found' });
    }

    req.tenant = tenant;
    next();
  });
}

app.get(
  '/',
  (req, res, next) => {
    const hostname = req.hostname || req.get('host')?.split(':')[0];

    getTenantByDomain(hostname, (err, tenant) => {
      if (err || !tenant) {
        return res.sendFile(path.join(__dirname, 'public', 'index.html'));
      }

      req.tenant = tenant;
      next();
    });
  },
  (req, res) => {
    const { tenant } = req;
    const html = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${tenant.name}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, ${tenant.themeColor}15 0%, ${tenant.themeColor}05 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            padding: 40px;
            max-width: 600px;
            width: 100%;
        }
        h1 {
            color: ${tenant.themeColor};
            margin-bottom: 20px;
            font-size: 2.5em;
        }
        .info {
            margin-top: 30px;
        }
        .info-item {
            margin: 15px 0;
            padding: 15px;
            background: ${tenant.themeColor}10;
            border-left: 4px solid ${tenant.themeColor};
            border-radius: 4px;
        }
        .label {
            font-weight: 600;
            color: #333;
            margin-bottom: 5px;
        }
        .value {
            color: #666;
            font-family: 'Monaco', 'Courier New', monospace;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>${tenant.name}</h1>
        <div class="info">
            <div class="info-item">
                <div class="label">Domain</div>
                <div class="value">${tenant.domain}</div>
            </div>
            <div class="info-item">
                <div class="label">Theme Color</div>
                <div class="value">${tenant.themeColor}</div>
            </div>
        </div>
    </div>
</body>
</html>
    `;
    res.send(html);
  }
);

app.get('/api/me', tenantMiddleware, (req, res) => {
  res.json({
    host: req.hostname || req.get('host'),
    tenant: req.tenant,
  });
});

app.post('/auth/signup', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'email and password are required' });
  }

  if (password.length < 8) {
    return res
      .status(400)
      .json({ error: 'password must be at least 8 characters' });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: 'invalid email format' });
  }

  getUserByEmail(email, async (err, existingUser) => {
    if (err) {
      console.error('Error checking user:', err.message);
      return res.status(500).json({ error: 'Database error' });
    }

    if (existingUser) {
      return res.status(409).json({ error: 'Email already exists' });
    }

    try {
      const passwordHash = await bcrypt.hash(password, 10);

      db.run(
        'INSERT INTO users (email, password_hash) VALUES (?, ?)',
        [email, passwordHash],
        function (err) {
          if (err) {
            console.error('Error creating user:', err.message);
            return res.status(500).json({ error: 'Database error' });
          }

          req.session.userId = this.lastID;
          console.log(`User created: ${email}`);

          getUserById(this.lastID, (err, user) => {
            if (err) {
              console.error('Error fetching user:', err.message);
              return res.status(500).json({ error: 'Database error' });
            }
            res.status(201).json({ user });
          });
        }
      );
    } catch (err) {
      console.error('Error hashing password:', err.message);
      return res.status(500).json({ error: 'Server error' });
    }
  });
});

app.post('/auth/signin', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'email and password are required' });
  }

  getUserByEmail(email, async (err, user) => {
    if (err) {
      console.error('Error checking user:', err.message);
      return res.status(500).json({ error: 'Database error' });
    }

    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    try {
      const match = await bcrypt.compare(password, user.password_hash);
      if (!match) {
        return res.status(401).json({ error: 'Invalid email or password' });
      }

      req.session.userId = user.id;
      console.log(`User signed in: ${email}`);

      getUserById(user.id, (err, userData) => {
        if (err) {
          console.error('Error fetching user:', err.message);
          return res.status(500).json({ error: 'Database error' });
        }
        res.json({ user: userData });
      });
    } catch (err) {
      console.error('Error comparing password:', err.message);
      return res.status(500).json({ error: 'Server error' });
    }
  });
});

app.post('/auth/signout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Error destroying session:', err.message);
      return res.status(500).json({ error: 'Server error' });
    }
    res.clearCookie('connect.sid');
    res.json({ message: 'Signed out successfully' });
  });
});

app.get('/auth/me', requireAuth, (req, res) => {
  getUserById(req.session.userId, (err, user) => {
    if (err) {
      console.error('Error fetching user:', err.message);
      return res.status(500).json({ error: 'Database error' });
    }
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ user });
  });
});

app.get('/api/websites', requireAuth, (req, res) => {
  db.all(
    'SELECT * FROM tenants WHERE user_id = ? ORDER BY created_at DESC',
    [req.session.userId],
    (err, websites) => {
      if (err) {
        console.error('Error fetching websites:', err.message);
        return res.status(500).json({ error: 'Database error' });
      }
      res.json(websites);
    }
  );
});

app.post('/api/websites', requireAuth, (req, res) => {
  const { domain, name, themeColor } = req.body;

  if (!domain || !name || !themeColor) {
    return res.status(400).json({
      error: 'domain, name, and themeColor are required',
    });
  }

  const colorRegex = /^#[0-9A-Fa-f]{6}$/;
  if (!colorRegex.test(themeColor)) {
    return res.status(400).json({
      error: 'themeColor must be a valid hex color (e.g., #3b82f6)',
    });
  }

  const domainRegex =
    /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
  if (!domainRegex.test(domain)) {
    return res.status(400).json({
      error: 'invalid domain format',
    });
  }

  db.run(
    'INSERT INTO tenants (user_id, domain, name, themeColor) VALUES (?, ?, ?, ?)',
    [req.session.userId, domain, name, themeColor],
    function (err) {
      if (err) {
        if (err.message.includes('UNIQUE constraint')) {
          return res.status(409).json({
            error: 'Domain already exists',
          });
        }
        console.error('Error creating website:', err.message);
        return res.status(500).json({ error: 'Database error' });
      }

      db.get(
        'SELECT * FROM tenants WHERE id = ?',
        [this.lastID],
        (err, website) => {
          if (err) {
            console.error('Error fetching created website:', err.message);
            return res.status(500).json({ error: 'Database error' });
          }
          console.log(
            `Created website: ${website.domain} for user ${req.session.userId}`
          );
          res.status(201).json(website);
        }
      );
    }
  );
});

app.put('/api/websites/:id', requireAuth, (req, res) => {
  const { id } = req.params;
  const { domain, name, themeColor } = req.body;

  if (!domain || !name || !themeColor) {
    return res.status(400).json({
      error: 'domain, name, and themeColor are required',
    });
  }

  const colorRegex = /^#[0-9A-Fa-f]{6}$/;
  if (!colorRegex.test(themeColor)) {
    return res.status(400).json({
      error: 'themeColor must be a valid hex color (e.g., #3b82f6)',
    });
  }

  const domainRegex =
    /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
  if (!domainRegex.test(domain)) {
    return res.status(400).json({
      error: 'invalid domain format',
    });
  }

  db.get(
    'SELECT * FROM tenants WHERE id = ? AND user_id = ?',
    [id, req.session.userId],
    (err, website) => {
      if (err) {
        console.error('Error checking website:', err.message);
        return res.status(500).json({ error: 'Database error' });
      }

      if (!website) {
        return res.status(404).json({ error: 'Website not found' });
      }

      db.run(
        'UPDATE tenants SET domain = ?, name = ?, themeColor = ? WHERE id = ? AND user_id = ?',
        [domain, name, themeColor, id, req.session.userId],
        function (err) {
          if (err) {
            if (err.message.includes('UNIQUE constraint')) {
              return res.status(409).json({
                error: 'Domain already exists',
              });
            }
            console.error('Error updating website:', err.message);
            return res.status(500).json({ error: 'Database error' });
          }

          db.get(
            'SELECT * FROM tenants WHERE id = ?',
            [id],
            (err, updatedWebsite) => {
              if (err) {
                console.error('Error fetching updated website:', err.message);
                return res.status(500).json({ error: 'Database error' });
              }
              console.log(`Updated website: ${updatedWebsite.domain}`);
              res.json(updatedWebsite);
            }
          );
        }
      );
    }
  );
});

app.delete('/api/websites/:id', requireAuth, (req, res) => {
  const { id } = req.params;

  db.get(
    'SELECT * FROM tenants WHERE id = ? AND user_id = ?',
    [id, req.session.userId],
    (err, website) => {
      if (err) {
        console.error('Error checking website:', err.message);
        return res.status(500).json({ error: 'Database error' });
      }

      if (!website) {
        return res.status(404).json({ error: 'Website not found' });
      }

      db.run(
        'DELETE FROM tenants WHERE id = ? AND user_id = ?',
        [id, req.session.userId],
        function (err) {
          if (err) {
            console.error('Error deleting website:', err.message);
            return res.status(500).json({ error: 'Database error' });
          }
          console.log(`Deleted website: ${website.domain}`);
          res.json({ message: 'Website deleted successfully' });
        }
      );
    }
  );
});

app.get('/api/websites/:id', requireAuth, (req, res) => {
  const { id } = req.params;

  db.get(
    'SELECT * FROM tenants WHERE id = ? AND user_id = ?',
    [id, req.session.userId],
    (err, website) => {
      if (err) {
        console.error('Error fetching website:', err.message);
        return res.status(500).json({ error: 'Database error' });
      }

      if (!website) {
        return res.status(404).json({ error: 'Website not found' });
      }

      res.json(website);
    }
  );
});

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`Express server running on http://localhost:${PORT}`);
  console.log(`Ready to handle multi-tenant requests`);
});

process.on('SIGINT', () => {
  db.close((err) => {
    if (err) {
      console.error('Error closing database:', err.message);
    } else {
      console.log('Database connection closed');
    }
    process.exit(0);
  });
});
