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

// Fix for Render: Trust proxy
if (isProduction) {
    app.set('trust proxy', 1);
    console.log('✅ Trust proxy enabled for Render');
}

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

// Rate limiting - FIXED for Render
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: isProduction ? 200 : 1000,
    message: 'Too many requests from this IP, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
        // Use IP from Render's proxy
        return req.ip;
    }
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

// Session check endpoint (public)
app.post('/api/check-session', async (req, res) => {
    try {
        // Get token from Authorization header or cookies
        let token = req.headers.authorization?.split(' ')[1];
        
        if (!token && req.cookies && req.cookies.token) {
            token = req.cookies.token;
        }
        
        if (!token) {
            return res.json({ 
                success: false, 
                message: 'No session token' 
            });
        }
        
        // Check if MongoDB is connected
        if (mongoose.connection.readyState !== 1) {
            return res.json({ 
                success: false, 
                message: 'Database not connected' 
            });
        }
        
        const tokenDoc = await Token.findOne({ token }).populate('userId');
        
        if (!tokenDoc) {
            return res.json({ 
                success: false, 
                message: 'Session not found' 
            });
        }
        
        // Check if token is expired
        if (tokenDoc.expiresAt < new Date()) {
            await Token.deleteOne({ _id: tokenDoc._id });
            return res.json({ 
                success: false, 
                message: 'Session expired' 
            });
        }
        
        // Update token expiry
        tokenDoc.expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
        await tokenDoc.save();
        
        const user = await User.findById(tokenDoc.userId._id);
        
        // Set cookie for future requests
        res.cookie('token', token, {
            httpOnly: true,
            secure: isProduction,
            sameSite: isProduction ? 'none' : 'lax',
            maxAge: 24 * 60 * 60 * 1000,
            path: '/'
        });
        
        res.json({ 
            success: true, 
            message: 'Session valid',
            username: user.username,
            token: token
        });
    } catch (error) {
        console.error('Session check error:', error);
        res.json({ 
            success: false, 
            message: 'Session check failed' 
        });
    }
});

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
            maxAge: 24 * 60 * 60 * 1000,
            path: '/'
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

app.post('/api/logout', async (req, res) => {
    try {
        let token = req.headers.authorization?.split(' ')[1];
        
        if (!token && req.cookies && req.cookies.token) {
            token = req.cookies.token;
        }
        
        if (token) {
            await Token.deleteOne({ token });
            console.log(`👋 User logged out`);
        }
        
        // Clear cookie
        res.clearCookie('token', {
            path: '/'
        });
        
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
        let token = socket.handshake.auth.token;
        
        // Try to get token from cookies if not in auth
        if (!token && socket.handshake.headers.cookie) {
            const cookies = socket.handshake.headers.cookie.split(';').reduce((acc, cookie) => {
                const [key, value] = cookie.trim().split('=');
                acc[key] = value;
                return acc;
            }, {});
            token = cookies.token;
        }
        
        if (!token) {
            console.log('Socket connection rejected: No token provided');
            return next(new Error('Authentication required'));
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
    User.findByIdAndUpdate(socket.userId, { 
        lastSeen: new Date()
    }).exec();
    
    // Broadcast updated users list
    broadcastUsersList();
    
    // WebRTC Events
    socket.on('call-offer', async ({ to, offer, callType }) => {
        console.log(`📞 Call offer from ${socket.username} to ${to} (${callType})`);
        
        // Check if already in a call
        if (activeCalls.has(socket.username)) {
            console.log(`⚠️ ${socket.username} is already in a call`);
            socket.emit('call-error', { message: 'You are already in a call' });
            return;
        }
        
        const targetSocketId = userSockets.get(to);
        if (!targetSocketId) {
            console.log(`⚠️ ${to} is offline`);
            socket.emit('call-error', { message: 'User is offline' });
            return;
        }
        
        // Check if target is in a call
        if (activeCalls.has(to)) {
            console.log(`⚠️ ${to} is busy in another call`);
            socket.emit('call-busy', { from: to });
            return;
        }
        
        // Mark caller as in call
        activeCalls.set(socket.username, { 
            with: to, 
            type: callType,
            timestamp: Date.now(),
            status: 'calling'
        });
        
        // Broadcast updated users list
        broadcastUsersList();
        
        // Forward offer with timeout
        const offerTimeout = setTimeout(() => {
            if (activeCalls.get(socket.username)?.status === 'calling') {
                console.log(`⏰ Call offer timeout for ${socket.username} to ${to}`);
                socket.emit('call-error', { message: 'Call timed out - no response' });
                activeCalls.delete(socket.username);
                broadcastUsersList();
            }
        }, 30000); // 30 second timeout
        
        // Store timeout reference
        socket.offerTimeout = offerTimeout;
        
        io.to(targetSocketId).emit('call-offer', {
            from: socket.username,
            offer: offer,
            callType: callType || 'video',
            timestamp: Date.now()
        });
        
        console.log(`📤 Call offer sent to ${to}`);
    });
    
    socket.on('call-answer', ({ to, answer }) => {
        console.log(`✅ Call answer from ${socket.username} to ${to}`);
        
        // Clear any pending offer timeout
        if (socket.offerTimeout) {
            clearTimeout(socket.offerTimeout);
            socket.offerTimeout = null;
        }
        
        const targetSocketId = userSockets.get(to);
        if (targetSocketId) {
            // Update call status for both users
            activeCalls.set(to, { 
                with: socket.username, 
                type: 'video',
                timestamp: Date.now(),
                status: 'connected'
            });
            
            activeCalls.set(socket.username, { 
                with: to, 
                type: 'video',
                timestamp: Date.now(),
                status: 'connected'
            });
            
            io.to(targetSocketId).emit('call-answer', {
                from: socket.username,
                answer: answer,
                timestamp: Date.now()
            });
            
            // Broadcast updated users list
            broadcastUsersList();
            
            console.log(`📞 Call connected: ${socket.username} <-> ${to}`);
        }
    });
    
    socket.on('ice-candidate', ({ to, candidate }) => {
        const targetSocketId = userSockets.get(to);
        if (targetSocketId) {
            io.to(targetSocketId).emit('ice-candidate', {
                candidate: candidate,
                timestamp: Date.now()
            });
        }
    });
    
    socket.on('call-rejected', ({ to }) => {
        console.log(`❌ Call rejected by ${socket.username}`);
        
        // Clear any pending offer timeout
        if (socket.offerTimeout) {
            clearTimeout(socket.offerTimeout);
            socket.offerTimeout = null;
        }
        
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
    
    socket.on('call-error', ({ to, message }) => {
        console.log(`❌ Call error from ${socket.username}: ${message}`);
        
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
        
        // Clear any pending timeouts
        if (socket.offerTimeout) {
            clearTimeout(socket.offerTimeout);
        }
        
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
            callType: callInfo?.type || null,
            callStatus: callInfo?.status || null
        };
    });
    
    io.emit('users-update', usersList);
}

// Clean up expired tokens
setInterval(async () => {
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
}, 60 * 60 * 1000); // Run every hour

// Start server
server.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📡 Environment: ${isProduction ? 'production' : 'development'}`);
    console.log(`🌐 WebSocket: ${isProduction ? 'wss://' : 'ws://'}${isProduction ? 'videocallapp-kld0.onrender.com' : 'localhost:' + PORT}`);
    console.log(`📊 MongoDB: ${mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected'}`);
    console.log('='.repeat(50));
    console.log('✅ Server is ready!');
    console.log('='.repeat(50));
});
