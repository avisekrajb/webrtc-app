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

// Fix for Render: Trust proxy
if (isProduction) {
    app.set('trust proxy', 1);
    console.log('✅ Trust proxy enabled for Render');
}

// Socket.io configuration
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
    legacyHeaders: false,
    keyGenerator: (req) => req.ip
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
})
.catch(err => {
    console.error('❌ MongoDB Atlas connection failed:', err.message);
});

// Schemas
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

const tokenSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    token: { type: String, required: true, unique: true },
    expiresAt: { type: Date, default: () => new Date(Date.now() + 24 * 60 * 60 * 1000) },
    createdAt: { type: Date, default: Date.now }
});

tokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const User = mongoose.model('User', userSchema);
const Token = mongoose.model('Token', tokenSchema);

// In-memory storage
const onlineUsers = new Map(); // socket.id -> {username, userId}
const userSockets = new Map(); // username -> socket.id
const activeCalls = new Map(); // username -> {with: username, status: 'calling'|'connected'}

// Routes
app.post('/api/check-session', async (req, res) => {
    try {
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
        
        const tokenDoc = await Token.findOne({ token }).populate('userId');
        
        if (!tokenDoc) {
            return res.json({ 
                success: false, 
                message: 'Session not found' 
            });
        }
        
        if (tokenDoc.expiresAt < new Date()) {
            await Token.deleteOne({ _id: tokenDoc._id });
            return res.json({ 
                success: false, 
                message: 'Session expired' 
            });
        }
        
        tokenDoc.expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
        await tokenDoc.save();
        
        const user = await User.findById(tokenDoc.userId._id);
        
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
            return res.status(400).json({ 
                success: false, 
                message: 'Username already exists' 
            });
        }
        
        res.status(500).json({ 
            success: false, 
            message: 'Registration failed' 
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
        
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid password' 
            });
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
        }
        
        res.clearCookie('token', { path: '/' });
        
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
        environment: isProduction ? 'production' : 'development',
        mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
        onlineUsers: onlineUsers.size,
        activeCalls: activeCalls.size
    });
});

// Serve index.html
app.get('*', (req, res) => {
    res.sendFile(__dirname + '/index.html');
});

// Socket.io
io.use(async (socket, next) => {
    try {
        let token = socket.handshake.auth.token;
        
        if (!token && socket.handshake.headers.cookie) {
            const cookies = socket.handshake.headers.cookie.split(';').reduce((acc, cookie) => {
                const [key, value] = cookie.trim().split('=');
                acc[key] = value;
                return acc;
            }, {});
            token = cookies.token;
        }
        
        if (!token) {
            return next(new Error('Authentication required'));
        }
        
        const tokenDoc = await Token.findOne({ token }).populate('userId');
        
        if (!tokenDoc || tokenDoc.expiresAt < new Date()) {
            return next(new Error('Invalid or expired token'));
        }
        
        tokenDoc.expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
        await tokenDoc.save();
        
        socket.userId = tokenDoc.userId._id;
        socket.username = tokenDoc.userId.username;
        socket.token = token;
        
        next();
    } catch (error) {
        next(new Error('Authentication failed'));
    }
});

io.on('connection', (socket) => {
    console.log(`✅ User connected: ${socket.username} (${socket.id})`);
    
    onlineUsers.set(socket.id, {
        username: socket.username,
        userId: socket.userId,
        socketId: socket.id
    });
    
    userSockets.set(socket.username, socket.id);
    
    User.findByIdAndUpdate(socket.userId, { 
        lastSeen: new Date()
    }).exec();
    
    broadcastUsersList();
    
    // Call offer
    socket.on('call-offer', ({ to, offer, callType }) => {
        console.log(`📞 Call offer from ${socket.username} to ${to}`);
        
        // Check if target is busy
        if (activeCalls.has(to)) {
            socket.emit('call-busy', { from: to });
            return;
        }
        
        const targetSocketId = userSockets.get(to);
        if (!targetSocketId) {
            socket.emit('call-error', { message: 'User is offline' });
            return;
        }
        
        // Mark as calling
        activeCalls.set(socket.username, { 
            with: to, 
            type: callType,
            status: 'calling',
            timestamp: Date.now()
        });
        
        // Forward offer
        io.to(targetSocketId).emit('call-offer', {
            from: socket.username,
            offer: offer,
            callType: callType || 'video',
            timestamp: Date.now()
        });
        
        // Set timeout for no answer
        setTimeout(() => {
            const callInfo = activeCalls.get(socket.username);
            if (callInfo && callInfo.status === 'calling') {
                console.log(`⏰ Call timeout for ${socket.username} to ${to}`);
                socket.emit('call-error', { message: 'Call timeout - no answer' });
                activeCalls.delete(socket.username);
                broadcastUsersList();
            }
        }, 30000); // 30 seconds
        
        broadcastUsersList();
    });
    
    // Call answer
    socket.on('call-answer', ({ to, answer }) => {
        console.log(`✅ Call answer from ${socket.username} to ${to}`);
        
        const targetSocketId = userSockets.get(to);
        if (targetSocketId) {
            // Update call status
            activeCalls.set(to, { 
                with: socket.username, 
                type: 'video',
                status: 'connected',
                timestamp: Date.now()
            });
            
            activeCalls.set(socket.username, { 
                with: to, 
                type: 'video',
                status: 'connected',
                timestamp: Date.now()
            });
            
            io.to(targetSocketId).emit('call-answer', {
                from: socket.username,
                answer: answer,
                timestamp: Date.now()
            });
            
            broadcastUsersList();
        }
    });
    
    // ICE candidate
    socket.on('ice-candidate', ({ to, candidate }) => {
        const targetSocketId = userSockets.get(to);
        if (targetSocketId) {
            io.to(targetSocketId).emit('ice-candidate', {
                candidate: candidate
            });
        }
    });
    
    // Call rejected
    socket.on('call-rejected', ({ to }) => {
        console.log(`❌ Call rejected by ${socket.username}`);
        
        const targetSocketId = userSockets.get(to);
        if (targetSocketId) {
            io.to(targetSocketId).emit('call-rejected', {
                from: socket.username
            });
        }
        
        activeCalls.delete(socket.username);
        activeCalls.delete(to);
        broadcastUsersList();
    });
    
    // Call ended
    socket.on('call-ended', ({ to }) => {
        console.log(`📴 Call ended by ${socket.username}`);
        
        const targetSocketId = userSockets.get(to);
        if (targetSocketId) {
            io.to(targetSocketId).emit('call-ended', {
                from: socket.username
            });
        }
        
        activeCalls.delete(socket.username);
        activeCalls.delete(to);
        broadcastUsersList();
    });
    
    // Disconnect
    socket.on('disconnect', () => {
        console.log(`❌ User disconnected: ${socket.username}`);
        
        onlineUsers.delete(socket.id);
        userSockets.delete(socket.username);
        
        // End any active calls
        const callInfo = activeCalls.get(socket.username);
        if (callInfo) {
            const targetSocketId = userSockets.get(callInfo.with);
            if (targetSocketId) {
                io.to(targetSocketId).emit('call-ended', {
                    from: socket.username,
                    reason: 'disconnected'
                });
            }
            activeCalls.delete(socket.username);
            activeCalls.delete(callInfo.with);
        }
        
        broadcastUsersList();
    });
});

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

// Clean expired tokens
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
}, 60 * 60 * 1000);

// Start server
server.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📡 Environment: ${isProduction ? 'production' : 'development'}`);
    console.log(`📊 MongoDB: ${mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected'}`);
    console.log('='.repeat(50));
    console.log('✅ Server is ready!');
    console.log('='.repeat(50));
});
