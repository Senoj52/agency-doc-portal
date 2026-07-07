const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./database');
const { authenticateToken, requireAdmin, JWT_SECRET } = require('./auth');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Serve frontend pages
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));
app.get('/admin.html', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));

// Ensure upload directories exist
const uploadDirs = ['uploads', 'uploads/target', 'uploads/accomplished', 'uploads/approved', 'uploads/signed'];
uploadDirs.forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
});

// Multer storage configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const category = req.body.category || 'target';
    cb(null, `uploads/${category}`);
  },
  filename: (req, file, cb) => {
    const uniqueName = Date.now() + '-' + crypto.randomBytes(8).toString('hex') + path.extname(file.originalname);
    cb(null, uniqueName);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 100 * 1024 * 1024 }, // 100MB
  fileFilter: (req, file, cb) => {
    const allowedTypes = [
      'application/pdf',
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'application/vnd.ms-excel',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'image/jpeg',
      'image/png',
      'image/gif',
      'text/plain',
      'application/zip'
    ];
    
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type'), false);
    }
  }
});

// ==================== AUTH ROUTES ====================

// Login
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: '24h' }
  );
  
  res.json({
    token,
    user: {
      id: user.id,
      username: user.username,
      role: user.role
    }
  });
});

// Verify token (for auto-login)
app.get('/api/auth/verify', authenticateToken, (req, res) => {
  res.json({ user: req.user });
});

// ==================== PUBLIC ROUTES ====================

// Get all files (public view)
app.get('/api/files', (req, res) => {
  const { category, search } = req.query;
  
  let query = 'SELECT id, title, description, category, original_name, file_size, mime_type, upload_date, download_count FROM files WHERE is_active = 1';
  const params = [];
  
  if (category) {
    query += ' AND category = ?';
    params.push(category);
  }
  
  if (search) {
    query += ' AND (title LIKE ? OR description LIKE ?)';
    params.push(`%${search}%`, `%${search}%`);
  }
  
  query += ' ORDER BY upload_date DESC';
  
  const files = db.prepare(query).all(...params);
  res.json(files);
});

// Download file (public)
app.get('/api/files/:id/download', (req, res) => {
  const file = db.prepare('SELECT * FROM files WHERE id = ? AND is_active = 1').get(req.params.id);
  
  if (!file) {
    return res.status(404).json({ error: 'File not found' });
  }
  
  // Update download count
  db.prepare('UPDATE files SET download_count = download_count + 1 WHERE id = ?').run(file.id);
  
  // Log activity
  db.prepare('INSERT INTO activity_log (file_id, action, user_info, ip_address) VALUES (?, ?, ?, ?)').run(
    file.id,
    'download',
    'public_user',
    req.ip
  );
  
  const filePath = path.join(__dirname, 'uploads', file.category, file.stored_name);
  res.download(filePath, file.original_name);
});

// ==================== ADMIN ROUTES ====================

// Upload file (admin only)
app.post('/api/admin/files', authenticateToken, requireAdmin, upload.array('files', 20), (req, res) => {
  try {
    const { title, description, category } = req.body;
    const files = req.files && req.files.length ? req.files : [];

    if (!title || !category) {
      return res.status(400).json({ error: 'Title and category are required' });
    }

    if (files.length === 0) {
      return res.status(400).json({ error: 'At least one file must be uploaded' });
    }

    const insert = db.prepare(`
      INSERT INTO files (title, description, category, original_name, stored_name, file_size, mime_type, uploaded_by)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const uploadedFiles = files.map((file) => {
      const result = insert.run(
        title,
        description || '',
        category,
        file.originalname,
        file.filename,
        file.size,
        file.mimetype,
        req.user.username
      );

      db.prepare('INSERT INTO activity_log (file_id, action, user_info, ip_address) VALUES (?, ?, ?, ?)').run(
        result.lastInsertRowid,
        'upload',
        req.user.username,
        req.ip
      );

      return {
        fileId: result.lastInsertRowid,
        originalName: file.originalname
      };
    });

    res.json({ 
      success: true,
      files: uploadedFiles,
      message: `${uploadedFiles.length} file(s) uploaded successfully`
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get all files for admin (including inactive)
app.get('/api/admin/files', authenticateToken, requireAdmin, (req, res) => {
  const { category, search } = req.query;
  
  let query = 'SELECT * FROM files WHERE 1=1';
  const params = [];
  
  if (category) {
    query += ' AND category = ?';
    params.push(category);
  }
  
  if (search) {
    query += ' AND (title LIKE ? OR description LIKE ?)';
    params.push(`%${search}%`, `%${search}%`);
  }
  
  query += ' ORDER BY upload_date DESC';
  
  const files = db.prepare(query).all(...params);
  res.json(files);
});

// Update file details (admin only)
app.put('/api/admin/files/:id', authenticateToken, requireAdmin, (req, res) => {
  const { title, description, category, is_active } = req.body;
  const fileId = req.params.id;
  
  const file = db.prepare('SELECT * FROM files WHERE id = ?').get(fileId);
  if (!file) {
    return res.status(404).json({ error: 'File not found' });
  }
  
  db.prepare(`
    UPDATE files 
    SET title = ?, description = ?, category = ?, is_active = ?
    WHERE id = ?
  `).run(
    title || file.title,
    description || file.description,
    category || file.category,
    is_active !== undefined ? is_active : file.is_active,
    fileId
  );
  
  res.json({ success: true, message: 'File updated successfully' });
});

// Delete file (admin only)
app.delete('/api/admin/files/:id', authenticateToken, requireAdmin, (req, res) => {
  const file = db.prepare('SELECT * FROM files WHERE id = ?').get(req.params.id);
  
  if (!file) {
    return res.status(404).json({ error: 'File not found' });
  }
  
  // Delete physical file
  const filePath = path.join(__dirname, 'uploads', file.category, file.stored_name);
  if (fs.existsSync(filePath)) {
    fs.unlinkSync(filePath);
  }
  
  // Soft delete from database
  db.prepare('UPDATE files SET is_active = 0 WHERE id = ?').run(file.id);
  
  // Log activity
  db.prepare('INSERT INTO activity_log (file_id, action, user_info, ip_address) VALUES (?, ?, ?, ?)').run(
    file.id,
    'delete',
    req.user.username,
    req.ip
  );
  
  res.json({ success: true, message: 'File deleted successfully' });
});

// Get activity log (admin only)
app.get('/api/admin/activity', authenticateToken, requireAdmin, (req, res) => {
  const activities = db.prepare(`
    SELECT al.*, f.title as file_title 
    FROM activity_log al 
    LEFT JOIN files f ON al.file_id = f.id 
    ORDER BY al.timestamp DESC 
    LIMIT 100
  `).all();
  
  res.json(activities);
});

// Get dashboard stats (admin only)
app.get('/api/admin/stats', authenticateToken, requireAdmin, (req, res) => {
  const stats = {
    totalFiles: db.prepare('SELECT COUNT(*) as count FROM files WHERE is_active = 1').get().count,
    categoryStats: {
      target: db.prepare('SELECT COUNT(*) as count FROM files WHERE category = ? AND is_active = 1').get('target').count,
      accomplished: db.prepare('SELECT COUNT(*) as count FROM files WHERE category = ? AND is_active = 1').get('accomplished').count,
      approved: db.prepare('SELECT COUNT(*) as count FROM files WHERE category = ? AND is_active = 1').get('approved').count,
      signed: db.prepare('SELECT COUNT(*) as count FROM files WHERE category = ? AND is_active = 1').get('signed').count,
    },
    totalDownloads: db.prepare('SELECT SUM(download_count) as total FROM files WHERE is_active = 1').get().total || 0,
    recentActivity: db.prepare(`
      SELECT al.*, f.title as file_title 
      FROM activity_log al 
      LEFT JOIN files f ON al.file_id = f.id 
      ORDER BY al.timestamp DESC 
      LIMIT 10
    `).all()
  };
  
  res.json(stats);
});

// Error handling middleware
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File too large. Maximum size is 100MB.' });
    }
    return res.status(400).json({ error: error.message });
  }
  console.error(error);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`Agency Document Management System running on port ${PORT}`);
  console.log(`Admin login: http://localhost:${PORT}/admin`);
  console.log(`Public access: http://localhost:${PORT}/`);
});