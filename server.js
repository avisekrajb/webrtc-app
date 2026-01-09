const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');

// Load environment variables
const path = require('path');
require('dotenv').config({ 
    path: path.resolve(__dirname, process.env.NODE_ENV === 'production' ? '.env.production' : '.env') 
});

const app = express();
const server = http.createServer(app);

// Determine environment
const isProduction = process.env.NODE_ENV === 'production';
console.log(`🚀 Starting server in ${isProduction ? 'PRODUCTION' : 'DEVELOPMENT'} mode`);

// Configure Socket.io
const io = socketIo(server, {
    cors: {
        origin: isProduction 
            ? [process.env.FRONTEND_URL, 'https://*.onrender.com'] 
            : ["http://localhost:3000", "http://localhost:8080", "http://127.0.0.1:3000"],
        methods: ["GET", "POST"],
        credentials: true
    },
    transports: ['websocket', 'polling']
});

// Security middleware - disable for development to allow WebRTC
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));

// Compression
app.use(compression());

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: isProduction ? 100 : 1000,
    message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// CORS configuration
app.use(cors({
    origin: isProduction ? process.env.FRONTEND_URL : true,
    credentials: true
}));

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Serve static files
app.use(express.static(__dirname));

// MongoDB Connection setup
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/webrtc_app';

console.log('🔗 Connecting to MongoDB...');
console.log('Database:', MONGODB_URI.replace(/mongodb(\+srv)?:\/\/(.*):(.*)@/, 'mongodb$1://***:***@'));

// MongoDB connection options
const mongooseOptions = {
    serverSelectionTimeoutMS: 30000,
    socketTimeoutMS: 45000,
    maxPoolSize: 10,
    minPoolSize: 2,
    retryWrites: true,
    w: 'majority'
};

mongoose.connect(MONGODB_URI, mongooseOptions)
.then(() => {
    console.log('✅ Connected to MongoDB successfully');
    console.log(`📊 Database: ${mongoose.connection.db.databaseName}`);
    console.log(`📍 Host: ${mongoose.connection.host}`);
    return initializeDatabase();
})
.catch(err => {
    console.error('❌ MongoDB connection failed:');
    console.error('Error:', err.message);
    console.error('\n💡 Troubleshooting tips:');
    console.error('1. Check your MongoDB connection string in .env file');
    console.error('2. For MongoDB Atlas, ensure your IP is whitelisted');
    console.error('3. Check if username/password are correct');
    console.error('4. Verify network connectivity');
    
    if (!isProduction) {
        console.error('\n⚠️ Running in development mode without database...');
        console.error('Some features will be limited.');
    } else {
        process.exit(1);
    }
});

// User Schema
const userSchema = new mongoose.Schema({
    username: { 
        type: String, 
        required: true, 
        unique: true,
        trim: true,
        minlength: 3,
        maxlength: 30
    },
    password: { 
        type: String, 
        required: true,
        minlength: 6
    },
    email: {
        type: String,
        sparse: true,
        trim: true,
        lowercase: true
    },
    lastSeen: { type: Date, default: Date.now },
    createdAt: { type: Date, default: Date.now }
});

// Token Schema
const tokenSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    token: { type: String, required: true, unique: true },
    expiresAt: { type: Date, default: () => new Date(Date.now() + 24 * 60 * 60 * 1000) },
    createdAt: { type: Date, default: Date.now }
});

tokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const User = mongoose.model('User', userSchema);
const Token = mongoose.model('Token', tokenSchema);

// Initialize database
async function initializeDatabase() {
    try {
        await User.init();
        await Token.init();
        console.log('✅ Database indexes created');
    } catch (error) {
        console.log('⚠️ Database initialization note:', error.message);
    }
}

// In-memory storage for online users
const onlineUsers = new Map(); // socket.id -> {username, userId}
const userSockets = new Map(); // username -> socket.id

// Authentication middleware
const authenticateToken = async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        
        if (!token) {
            return res.status(401).json({ success: false, message: 'No token provided' });
        }
        
        const tokenDoc = await Token.findOne({ token }).populate('userId');
        
        if (!tokenDoc) {
            return res.status(401).json({ success: false, message: 'Invalid token' });
        }
        
        if (tokenDoc.expiresAt < new Date()) {
            await Token.deleteOne({ _id: tokenDoc._id });
            return res.status(401).json({ success: false, message: 'Token expired' });
        }
        
        req.user = tokenDoc.userId;
        next();
    } catch (error) {
        console.error('Auth error:', error);
        res.status(500).json({ success: false, message: 'Authentication failed' });
    }
};

// API Routes
app.post('/api/register', async (req, res) => {
    try {
        const { username, password, email } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ success: false, message: 'Username and password are required' });
        }
        
        const trimmedUsername = username.trim();
        if (trimmedUsername.length < 3) {
            return res.status(400).json({ success: false, message: 'Username must be at least 3 characters' });
        }
        
        if (password.length < 6) {
            return res.status(400).json({ success: false, message: 'Password must be at least 6 characters' });
        }
        
        // Check if MongoDB is connected
        if (mongoose.connection.readyState !== 1) {
            return res.status(500).json({ success: false, message: 'Database not connected' });
        }
        
        const existingUser = await User.findOne({ 
            username: trimmedUsername 
        });
        
        if (existingUser) {
            return res.status(400).json({ success: false, message: 'Username already exists' });
        }
        
        const hashedPassword = await bcrypt.hash(password, 12);
        
        const user = new User({
            username: trimmedUsername,
            password: hashedPassword,
            email: email ? email.trim().toLowerCase() : null
        });
        
        await user.save();
        
        console.log(`👤 New user registered: ${trimmedUsername}`);
        
        res.status(201).json({ 
            success: true, 
            message: 'Registration successful',
            username: trimmedUsername
        });
    } catch (error) {
        console.error('Registration error:', error);
        
        if (error.code === 11000) {
            return res.status(400).json({ success: false, message: 'Username already exists' });
        }
        
        res.status(500).json({ success: false, message: 'Registration failed' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ success: false, message: 'Username and password are required' });
        }
        
        // Check if MongoDB is connected
        if (mongoose.connection.readyState !== 1) {
            return res.status(500).json({ success: false, message: 'Database not connected. Please try again.' });
        }
        
        const user = await User.findOne({
            $or: [
                { username: username.trim() },
                { email: username.trim().toLowerCase() }
            ]
        });
        
        if (!user) {
            return res.status(401).json({ success: false, message: 'User not found. Please register first.' });
        }
        
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ success: false, message: 'Invalid password' });
        }
        
        const token = crypto.randomBytes(48).toString('hex');
        
        const tokenDoc = new Token({
            userId: user._id,
            token: token
        });
        
        await tokenDoc.save();
        
        user.lastSeen = new Date();
        await user.save();
        
        console.log(`🔑 User logged in: ${user.username}`);
        
        res.json({ 
            success: true, 
            message: 'Login successful',
            token: token,
            username: user.username
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, message: 'Login failed' });
    }
});

app.post('/api/check-session', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        if (!user) {
            return res.status(401).json({ success: false, message: 'User not found' });
        }
        
        res.json({ 
            success: true, 
            message: 'Session valid',
            username: user.username 
        });
    } catch (error) {
        res.status(401).json({ success: false, message: 'Session invalid' });
    }
});

app.post('/api/logout', authenticateToken, async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        
        if (token) {
            await Token.deleteOne({ token });
            console.log(`👋 User logged out: ${req.user.username}`);
        }
        
        res.json({ success: true, message: 'Logged out successfully' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Logout failed' });
    }
});

app.get('/api/users', async (req, res) => {
    try {
        // If MongoDB is not connected, return empty list
        if (mongoose.connection.readyState !== 1) {
            return res.json({ 
                success: true, 
                users: [],
                message: 'Database not connected'
            });
        }
        
        const users = await User.find({})
            .select('username lastSeen')
            .sort({ lastSeen: -1 })
            .limit(50);
        
        const onlineUsernames = Array.from(onlineUsers.values()).map(u => u.username);
        
        res.json({ 
            success: true, 
            users: users.map(user => ({
                username: user.username,
                lastSeen: user.lastSeen,
                isOnline: onlineUsernames.includes(user.username)
            }))
        });
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch users' });
    }
});

app.get('/api/health', (req, res) => {
    res.json({ 
        success: true, 
        status: 'OK',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        environment: isProduction ? 'production' : 'development',
        mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
        onlineUsers: onlineUsers.size
    });
});

// Serve index.html for all routes
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Socket.io middleware
io.use(async (socket, next) => {
    const token = socket.handshake.auth.token;
    
    if (!token) {
        return next(new Error('Authentication error: No token provided'));
    }
    
    try {
        // Check if MongoDB is connected
        if (mongoose.connection.readyState !== 1) {
            return next(new Error('Database not connected'));
        }
        
        const tokenDoc = await Token.findOne({ token }).populate('userId');
        if (!tokenDoc || tokenDoc.expiresAt < new Date()) {
            return next(new Error('Authentication error: Invalid or expired token'));
        }
        
        socket.userId = tokenDoc.userId._id;
        socket.username = tokenDoc.userId.username;
        socket.token = token;
        
        next();
    } catch (error) {
        console.error('Socket auth error:', error);
        next(new Error('Authentication failed'));
    }
});

// Socket.io events
io.on('connection', (socket) => {
    console.log(`✅ User connected: ${socket.username} (${socket.id})`);
    
    // Add to online users
    onlineUsers.set(socket.id, {
        username: socket.username,
        userId: socket.userId,
        socketId: socket.id
    });
    
    userSockets.set(socket.username, socket.id);
    
    // Update last seen in database if connected
    if (mongoose.connection.readyState === 1) {
        User.findByIdAndUpdate(socket.userId, { 
            lastSeen: new Date()
        }).exec();
    }
    
    // Broadcast updated users list
    broadcastUsersList();
    
    // Call offer
    socket.on('call-offer', ({ to, offer, callType }) => {
        console.log(`📞 Call offer from ${socket.username} to ${to}`);
        
        const targetSocketId = userSockets.get(to);
        if (!targetSocketId) {
            socket.emit('call-error', { message: 'User is offline' });
            return;
        }
        
        io.to(targetSocketId).emit('call-offer', {
            from: socket.username,
            offer: offer,
            callType: callType || 'video',
            timestamp: Date.now()
        });
    });
    
    // Call answer
    socket.on('call-answer', ({ to, answer }) => {
        console.log(`✅ Call answer from ${socket.username} to ${to}`);
        
        const targetSocketId = userSockets.get(to);
        if (targetSocketId) {
            io.to(targetSocketId).emit('call-answer', {
                from: socket.username,
                answer: answer,
                timestamp: Date.now()
            });
        }
    });
    
    // ICE candidate
    socket.on('ice-candidate', ({ to, candidate }) => {
        const targetSocketId = userSockets.get(to);
        if (targetSocketId) {
            io.to(targetSocketId).emit('ice-candidate', {
                candidate: candidate,
                timestamp: Date.now()
            });
        }
    });
    
    // Call rejected
    socket.on('call-rejected', ({ to }) => {
        console.log(`❌ Call rejected by ${socket.username}`);
        
        const targetSocketId = userSockets.get(to);
        if (targetSocketId) {
            io.to(targetSocketId).emit('call-rejected', {
                from: socket.username,
                timestamp: Date.now()
            });
        }
    });
    
    // Call ended
    socket.on('call-ended', ({ to }) => {
        console.log(`📴 Call ended by ${socket.username}`);
        
        const targetSocketId = userSockets.get(to);
        if (targetSocketId) {
            io.to(targetSocketId).emit('call-ended', {
                from: socket.username,
                timestamp: Date.now()
            });
        }
    });
    
    // Call error
    socket.on('call-error', ({ to, message }) => {
        const targetSocketId = userSockets.get(to);
        if (targetSocketId) {
            io.to(targetSocketId).emit('call-error', { 
                message,
                timestamp: Date.now()
            });
        }
    });
    
    // Disconnect
    socket.on('disconnect', () => {
        console.log(`❌ User disconnected: ${socket.username}`);
        
        onlineUsers.delete(socket.id);
        userSockets.delete(socket.username);
        
        // Clean up token if database is connected
        if (mongoose.connection.readyState === 1 && socket.token) {
            Token.deleteOne({ token: socket.token }).catch(console.error);
        }
        
        broadcastUsersList();
    });
});

// Broadcast users list
function broadcastUsersList() {
    const usersList = Array.from(onlineUsers.values()).map(user => ({
        username: user.username,
        isOnline: true,
        inCall: false
    }));
    
    io.emit('users-update', usersList);
}

// Clean expired tokens
setInterval(async () => {
    if (mongoose.connection.readyState === 1) {
        try {
            const result = await Token.deleteMany({
                expiresAt: { $lt: new Date() }
            });
            if (result.deletedCount > 0) {
                console.log(`🧹 Cleaned up ${result.deletedCount} expired tokens`);
            }
        } catch (error) {
            console.error('Token cleanup error:', error);
        }
    }
}, 60 * 60 * 1000);

// Start server
const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📡 Environment: ${isProduction ? 'production' : 'development'}`);
    console.log(`🌐 WebSocket: ws://localhost:${PORT}`);
    console.log(`📊 MongoDB: ${mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected'}`);
    console.log('='.repeat(50));
    console.log(`✅ Server is ready!`);
    console.log(`👉 Open http://localhost:${PORT} in your browser`);
    console.log('='.repeat(50));
});