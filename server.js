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

// Load .env only in development
if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
    console.log('📁 Loading .env file for development');
}

const app = express();
const server = http.createServer(app);

// Configuration
const isProduction = process.env.NODE_ENV === 'production';
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/webrtc_app';

console.log(`🚀 Environment: ${isProduction ? 'PRODUCTION' : 'DEVELOPMENT'}`);
console.log(`🔗 MongoDB URI: ${MONGODB_URI ? MONGODB_URI.replace(/mongodb(\+srv)?:\/\/(.*):(.*)@/, 'mongodb$1://***:***@') : 'Not set'}`);

// Socket.io configuration for Render
const io = socketIo(server, {
    cors: {
        origin: isProduction 
            ? ["https://*.onrender.com", "https://videocallapp-kld0.onrender.com"]
            : ["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:8080"],
        methods: ["GET", "POST"],
        credentials: true
    },
    transports: ['websocket', 'polling'],
    pingTimeout: 60000,
    pingInterval: 25000
});

// Middleware
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));
app.use(compression());
app.use(cors({
    origin: isProduction 
        ? ["https://videocallapp-kld0.onrender.com", "https://*.onrender.com"]
        : true,
    credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(__dirname));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: isProduction ? 200 : 1000,
    message: 'Too many requests from this IP, please try again later.',
    standardHeaders: true,
    legacyHeaders: false
});
app.use('/api/', limiter);

// MongoDB Connection
console.log('🔗 Connecting to MongoDB Atlas...');

mongoose.connect(MONGODB_URI, {
    serverSelectionTimeoutMS: 10000,
    socketTimeoutMS: 45000,
    maxPoolSize: 10,
    minPoolSize: 2,
    retryWrites: true,
    w: 'majority'
})
.then(() => {
    console.log('✅ MongoDB Atlas connected successfully');
    console.log(`📊 Database: ${mongoose.connection.db.databaseName}`);
    console.log(`📍 Host: ${mongoose.connection.host}`);
})
.catch(err => {
    console.error('❌ MongoDB Atlas connection failed:', err.message);
    console.error('💡 Check your MONGODB_URI environment variable in Render dashboard');
    if (isProduction) {
        console.error('⚠️ Running in limited mode - database features disabled');
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

// Token Schema for sessions
const tokenSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    token: { type: String, required: true, unique: true },
    userAgent: String,
    ipAddress: String,
    expiresAt: { type: Date, default: () => new Date(Date.now() + 24 * 60 * 60 * 1000) },
    createdAt: { type: Date, default: Date.now }
});

// Auto-expire tokens
tokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const User = mongoose.model('User', userSchema);
const Token = mongoose.model('Token', tokenSchema);

// In-memory storage for real-time
const onlineUsers = new Map(); // socket.id -> {username, userId}
const userSockets = new Map(); // username -> socket.id
const activeCalls = new Map(); // username -> {with: username, type: 'video'|'audio'}

// Improved Authentication Middleware
const authenticateToken = async (req, res, next) => {
    try {
        // Get token from Authorization header or cookies
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.startsWith('Bearer ') 
            ? authHeader.split(' ')[1] 
            : req.cookies?.token;
        
        if (!token) {
            return res.status(401).json({ 
                success: false, 
                message: 'No authentication token provided' 
            });
        }
        
        // Check if MongoDB is connected
        if (mongoose.connection.readyState !== 1) {
            return res.status(503).json({ 
                success: false, 
                message: 'Database temporarily unavailable' 
            });
        }
        
        const tokenDoc = await Token.findOne({ token }).populate('userId');
        
        if (!tokenDoc) {
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid or expired session' 
            });
        }
        
        // Check if token is expired
        if (tokenDoc.expiresAt < new Date()) {
            await Token.deleteOne({ _id: tokenDoc._id });
            return res.status(401).json({ 
                success: false, 
                message: 'Session expired' 
            });
        }
        
        // Update token expiry
        tokenDoc.expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
        await tokenDoc.save();
        
        req.user = tokenDoc.userId;
        req.token = token;
        next();
    } catch (error) {
        console.error('Authentication error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Authentication failed' 
        });
    }
};

// Routes
app.post('/api/register', async (req, res) => {
    try {
        const { username, password, email } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ 
                success: false, 
                message: 'Username and password are required' 
            });
        }
        
        const trimmedUsername = username.trim();
        if (trimmedUsername.length < 3) {
            return res.status(400).json({ 
                success: false, 
                message: 'Username must be at least 3 characters' 
            });
        }
        
        if (password.length < 6) {
            return res.status(400).json({ 
                success: false, 
                message: 'Password must be at least 6 characters' 
            });
        }
        
        // Check database connection
        if (mongoose.connection.readyState !== 1) {
            return res.status(503).json({ 
                success: false, 
                message: 'Database not available. Please try again.' 
            });
        }
        
        // Check for existing user
        const existingUser = await User.findOne({ 
            $or: [
                { username: trimmedUsername },
                ...(email ? [{ email: email.trim().toLowerCase() }] : [])
            ]
        });
        
        if (existingUser) {
            if (existingUser.username === trimmedUsername) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'Username already exists' 
                });
            }
            if (email && existingUser.email === email.trim().toLowerCase()) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'Email already registered' 
                });
            }
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 12);
        
        // Create user
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
            return res.status(400).json({ 
                success: false, 
                message: 'Username already exists' 
            });
        }
        
        res.status(500).json({ 
            success: false, 
            message: 'Registration failed. Please try again.' 
        });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ 
                success: false, 
                message: 'Username and password are required' 
            });
        }
        
        // Check database connection
        if (mongoose.connection.readyState !== 1) {
            return res.status(503).json({ 
                success: false, 
                message: 'Database not available. Please try again.' 
            });
        }
        
        // Find user by username or email
        const user = await User.findOne({
            $or: [
                { username: username.trim() },
                { email: username.trim().toLowerCase() }
            ]
        });
        
        if (!user) {
            return res.status(401).json({ 
                success: false, 
                message: 'User not found. Please register first.' 
            });
        }
        
        // Verify password
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid password' 
            });
        }
        
        // Generate token
        const token = crypto.randomBytes(48).toString('hex');
        
        // Create token document
        const tokenDoc = new Token({
            userId: user._id,
            token: token,
            userAgent: req.headers['user-agent'],
            ipAddress: req.ip || req.connection.remoteAddress
        });
        
        await tokenDoc.save();
        
        // Update user last seen
        user.lastSeen = new Date();
        await user.save();
        
        console.log(`🔑 User logged in: ${user.username}`);
        
        // Set cookie for web clients
        res.cookie('token', token, {
            httpOnly: true,
            secure: isProduction,
            sameSite: isProduction ? 'none' : 'lax',
            maxAge: 24 * 60 * 60 * 1000
        });
        
        res.json({ 
            success: true, 
            message: 'Login successful',
            token: token,
            username: user.username
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Login failed' 
        });
    }
});

// Public session check (no authentication required)
app.post('/api/check-session', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1] || req.cookies?.token;
        
        if (!token) {
            return res.status(401).json({ 
                success: false, 
                message: 'No session token' 
            });
        }
        
        if (mongoose.connection.readyState !== 1) {
            return res.status(200).json({ 
                success: false, 
                message: 'Database not connected' 
            });
        }
        
        const tokenDoc = await Token.findOne({ token }).populate('userId');
        
        if (!tokenDoc) {
            return res.status(200).json({ 
                success: false, 
                message: 'Session not found' 
            });
        }
        
        if (tokenDoc.expiresAt < new Date()) {
            await Token.deleteOne({ _id: tokenDoc._id });
            return res.status(200).json({ 
                success: false, 
                message: 'Session expired' 
            });
        }
        
        // Update expiry
        tokenDoc.expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
        await tokenDoc.save();
        
        const user = await User.findById(tokenDoc.userId._id);
        
        res.json({ 
            success: true, 
            message: 'Session valid',
            username: user.username,
            token: token
        });
    } catch (error) {
        console.error('Session check error:', error);
        res.status(200).json({ 
            success: false, 
            message: 'Session check failed' 
        });
    }
});

app.post('/api/logout', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1] || req.cookies?.token;
        
        if (token && mongoose.connection.readyState === 1) {
            await Token.deleteOne({ token });
            console.log(`👋 User logged out`);
        }
        
        // Clear cookie
        res.clearCookie('token');
        
        res.json({ 
            success: true, 
            message: 'Logged out successfully' 
        });
    } catch (error) {
        res.status(500).json({ 
            success: false, 
            message: 'Logout failed' 
        });
    }
});

app.get('/api/users', async (req, res) => {
    try {
        // If database not connected, return empty list
        if (mongoose.connection.readyState !== 1) {
            return res.json({ 
                success: true, 
                users: [],
                message: 'Database not connected'
            });
        }
        
        const users = await User.find({})
            .select('username lastSeen createdAt')
            .sort({ lastSeen: -1 })
            .limit(100);
        
        const onlineUsernames = Array.from(onlineUsers.values()).map(u => u.username);
        const callingUsernames = Array.from(activeCalls.keys());
        
        res.json({ 
            success: true, 
            users: users.map(user => ({
                username: user.username,
                lastSeen: user.lastSeen,
                isOnline: onlineUsernames.includes(user.username),
                inCall: callingUsernames.includes(user.username)
            }))
        });
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to fetch users' 
        });
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
        onlineUsers: onlineUsers.size,
        activeCalls: activeCalls.size,
        memory: process.memoryUsage()
    });
});

// Serve index.html for all routes
app.get('*', (req, res) => {
    res.sendFile(__dirname + '/index.html');
});

// Socket.io Middleware
io.use(async (socket, next) => {
    try {
        const token = socket.handshake.auth.token;
        
        if (!token) {
            console.log('Socket connection rejected: No token provided');
            return next(new Error('Authentication required'));
        }
        
        // Check database connection
        if (mongoose.connection.readyState !== 1) {
            console.log('Socket connection rejected: Database not connected');
            return next(new Error('Database not available'));
        }
        
        const tokenDoc = await Token.findOne({ token }).populate('userId');
        
        if (!tokenDoc) {
            console.log('Socket connection rejected: Invalid token');
            return next(new Error('Invalid authentication token'));
        }
        
        if (tokenDoc.expiresAt < new Date()) {
            await Token.deleteOne({ _id: tokenDoc._id });
            console.log('Socket connection rejected: Token expired');
            return next(new Error('Session expired'));
        }
        
        // Update token expiry
        tokenDoc.expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
        await tokenDoc.save();
        
        socket.userId = tokenDoc.userId._id;
        socket.username = tokenDoc.userId.username;
        socket.token = token;
        
        console.log(`✅ Socket authenticated for user: ${socket.username}`);
        next();
    } catch (error) {
        console.error('Socket authentication error:', error);
        next(new Error('Authentication failed'));
    }
});

// Socket.io Events
io.on('connection', (socket) => {
    console.log(`✅ User connected: ${socket.username} (${socket.id})`);
    
    // Add to online users
    onlineUsers.set(socket.id, {
        username: socket.username,
        userId: socket.userId,
        socketId: socket.id,
        connectedAt: new Date()
    });
    
    userSockets.set(socket.username, socket.id);
    
    // Update last seen in database
    if (mongoose.connection.readyState === 1) {
        User.findByIdAndUpdate(socket.userId, { 
            lastSeen: new Date()
        }).exec();
    }
    
    // Broadcast updated users list
    broadcastUsersList();
    
    // Call Offer
    socket.on('call-offer', ({ to, offer, callType }) => {
        console.log(`📞 Call offer from ${socket.username} to ${to} (${callType})`);
        
        // Check if target is in a call
        if (activeCalls.has(to)) {
            socket.emit('call-busy', { from: to });
            return;
        }
        
        const targetSocketId = userSockets.get(to);
        if (!targetSocketId) {
            socket.emit('call-error', { message: 'User is offline' });
            return;
        }
        
        // Mark as in call
        activeCalls.set(socket.username, { with: to, type: callType });
        
        // Forward offer
        io.to(targetSocketId).emit('call-offer', {
            from: socket.username,
            offer: offer,
            callType: callType || 'video',
            timestamp: Date.now()
        });
        
        // Broadcast updated users list
        broadcastUsersList();
    });
    
    // Call Answer
    socket.on('call-answer', ({ to, answer }) => {
        console.log(`✅ Call answer from ${socket.username} to ${to}`);
        
        const targetSocketId = userSockets.get(to);
        if (targetSocketId) {
            // Mark both as in call
            activeCalls.set(to, { with: socket.username, type: 'video' });
            activeCalls.set(socket.username, { with: to, type: 'video' });
            
            io.to(targetSocketId).emit('call-answer', {
                from: socket.username,
                answer: answer,
                timestamp: Date.now()
            });
            
            // Broadcast updated users list
            broadcastUsersList();
        }
    });
    
    // ICE Candidate
    socket.on('ice-candidate', ({ to, candidate }) => {
        const targetSocketId = userSockets.get(to);
        if (targetSocketId) {
            io.to(targetSocketId).emit('ice-candidate', {
                candidate: candidate,
                timestamp: Date.now()
            });
        }
    });
    
    // Call Rejected
    socket.on('call-rejected', ({ to }) => {
        console.log(`❌ Call rejected by ${socket.username}`);
        
        const targetSocketId = userSockets.get(to);
        if (targetSocketId) {
            io.to(targetSocketId).emit('call-rejected', {
                from: socket.username,
                timestamp: Date.now()
            });
        }
        
        // Remove from active calls
        activeCalls.delete(socket.username);
        activeCalls.delete(to);
        
        // Broadcast updated users list
        broadcastUsersList();
    });
    
    // Call Ended
    socket.on('call-ended', ({ to }) => {
        console.log(`📴 Call ended by ${socket.username}`);
        
        const targetSocketId = userSockets.get(to);
        if (targetSocketId) {
            io.to(targetSocketId).emit('call-ended', {
                from: socket.username,
                timestamp: Date.now()
            });
        }
        
        // Remove from active calls
        activeCalls.delete(socket.username);
        activeCalls.delete(to);
        
        // Broadcast updated users list
        broadcastUsersList();
    });
    
    // Call Error
    socket.on('call-error', ({ to, message }) => {
        const targetSocketId = userSockets.get(to);
        if (targetSocketId) {
            io.to(targetSocketId).emit('call-error', { 
                message,
                timestamp: Date.now()
            });
        }
        
        // Remove from active calls
        activeCalls.delete(socket.username);
        activeCalls.delete(to);
        
        // Broadcast updated users list
        broadcastUsersList();
    });
    
    // Heartbeat/ping
    socket.on('heartbeat', () => {
        socket.emit('heartbeat-response', { 
            timestamp: Date.now(),
            serverTime: new Date().toISOString()
        });
    });
    
    // Disconnect
    socket.on('disconnect', (reason) => {
        console.log(`❌ User disconnected: ${socket.username} (${reason})`);
        
        // Remove from online users
        onlineUsers.delete(socket.id);
        userSockets.delete(socket.username);
        
        // End any active calls
        const callInfo = activeCalls.get(socket.username);
        if (callInfo) {
            const targetSocketId = userSockets.get(callInfo.with);
            if (targetSocketId) {
                io.to(targetSocketId).emit('call-ended', {
                    from: socket.username,
                    reason: 'disconnected',
                    timestamp: Date.now()
                });
            }
            activeCalls.delete(socket.username);
            activeCalls.delete(callInfo.with);
        }
        
        // Clean up token if database is connected
        if (socket.token && mongoose.connection.readyState === 1) {
            Token.deleteOne({ token: socket.token }).catch(console.error);
        }
        
        // Broadcast updated users list
        broadcastUsersList();
    });
});

// Helper function to broadcast users list
function broadcastUsersList() {
    const usersList = Array.from(onlineUsers.values()).map(user => {
        const callInfo = activeCalls.get(user.username);
        return {
            username: user.username,
            isOnline: true,
            inCall: !!callInfo,
            callType: callInfo?.type || null
        };
    });
    
    io.emit('users-update', usersList);
}

// Clean up expired tokens
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
}, 60 * 60 * 1000); // Run every hour

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM received. Closing server gracefully...');
    
    // Update all users as offline
    if (mongoose.connection.readyState === 1) {
        User.updateMany({}, { 
            lastSeen: new Date()
        }).exec();
    }
    
    server.close(() => {
        console.log('HTTP server closed');
        mongoose.connection.close(false, () => {
            console.log('MongoDB connection closed');
            process.exit(0);
        });
    });
});

// Start server
server.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📡 Environment: ${isProduction ? 'production' : 'development'}`);
    console.log(`🌐 WebSocket: ${isProduction ? 'wss://' : 'ws://'}${isProduction ? 'your-app.onrender.com' : 'localhost:' + PORT}`);
    console.log(`📊 MongoDB: ${mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected'}`);
    console.log('='.repeat(50));
    console.log('✅ Server is ready!');
    console.log('='.repeat(50));
});
