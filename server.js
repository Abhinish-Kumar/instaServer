const express = require("express");
const app = express();
const mongoose = require("mongoose");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

// Environment variables
require("dotenv").config();
const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key";

// Middleware
app.use(cookieParser());
app.use(express.json());
app.use(
  cors({
    origin: "https://abhinish-kumar.github.io",
    credentials: true,
  })
);

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = "uploads/";
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  },
});

const upload = multer({
  storage: storage,
  fileFilter: (req, file, cb) => {
    const allowedTypes = ["image/jpeg", "image/png", "image/gif"];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error("Only JPEG, PNG, and GIF images are allowed"));
    }
  },
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB
  },
});

// Serve static files
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// Database connection
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log("Connected to database");
  } catch (err) {
    console.error("Database connection error:", err);
    process.exit(1);
  }
};
connectDB();

// Models
const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      minlength: 3,
      maxlength: 30,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      lowercase: true,
      match: [/\S+@\S+\.\S+/, "is invalid"],
    },
    password: {
      type: String,
      required: true,
      minlength: 6,
    },
    profilePhoto: {
      type: String,
      default: null, // Changed to default null
    },
    bio: {
      type: String,
      default: "",
      maxlength: 150,
    },
    followers: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
    following: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
    posts: [{ type: mongoose.Schema.Types.ObjectId, ref: "Post" }],
  },
  { timestamps: true }
);

const postSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    caption: { type: String, trim: true, maxlength: 2200 },
    imageUrl: { type: String, required: true },
    likes: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
    comments: [
      {
        user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
        text: { type: String, required: true, maxlength: 300 },
        createdAt: { type: Date, default: Date.now },
      },
    ],
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);
const Post = mongoose.model("Post", postSchema);

// Auth middleware
const authenticate = async (req, res, next) => {
  try {
    const token = req.cookies.token;
    if (!token) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId).select("-password");
    if (!user) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    req.user = user;
    next();
  } catch (err) {
    console.error("Authentication error:", err);
    res.status(401).json({ error: "Unauthorized" });
  }
};

// Routes
app.post("/instaServer/api/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: "All fields are required" });
    }

    const existingUser = await User.findOne({
      $or: [{ username }, { email }],
    });
    if (existingUser) {
      return res
        .status(400)
        .json({ error: "Username or email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({
      username,
      email,
      password: hashedPassword,
    });

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, {
      expiresIn: "1d",
    });

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "none",
      maxAge: 24 * 60 * 60 * 1000, // 1 day
    });

    res.status(201).json({
      message: "Registration successful",
      user: {
        _id: user._id,
        username: user.username,
        email: user.email,
        profilePhoto: user.profilePhoto, // will be null
      },
    });
  } catch (err) {
    console.error("Registration error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/instaServer/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, {
      expiresIn: "1d",
    });

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "none",
      maxAge: 24 * 60 * 60 * 1000, // 1 day
    });

    res.json({
      message: "Login successful",
      user: {
        _id: user._id,
        username: user.username,
        email: user.email,
        profilePhoto: user.profilePhoto, // could be null
        bio: user.bio,
      },
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/instaServer/api/logout", (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "none",
  });
  res.json({ message: "Logout successful" });
});

app.get("/instaServer/api/dashboard", authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id)
      .select("-password")
      .populate("followers", "username profilePhoto")
      .populate("following", "username profilePhoto")
      .populate({
        path: "posts",
        populate: {
          path: "user",
          select: "username profilePhoto",
        },
      });

    res.json({ user });
  } catch (err) {
    console.error("Dashboard error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Profile routes
app.post(
  "/instaServer/api/users/updateProfilePic",
  authenticate,
  upload.single("profilePhoto"),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ error: "No file uploaded" });
      }

      const user = await User.findById(req.user._id);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      // Delete old profile photo if it exists
      if (user.profilePhoto) {
        const oldPhotoPath = path.join(__dirname, user.profilePhoto);
        if (fs.existsSync(oldPhotoPath)) {
          fs.unlinkSync(oldPhotoPath);
        }
      }

      const profilePhotoUrl = `/uploads/${req.file.filename}`;
      user.profilePhoto = profilePhotoUrl;
      await user.save();

      res.json({
        message: "Profile photo updated successfully",
        profilePhotoUrl,
      });
    } catch (err) {
      console.error("Profile photo update error:", err);
      res.status(500).json({ error: err.message || "Internal server error" });
    }
  }
);

app.put("/instaServer/api/users/updateBio", authenticate, async (req, res) => {
  try {
    const { bio } = req.body;
    const user = await User.findByIdAndUpdate(
      req.user._id,
      { bio },
      { new: true }
    ).select("-password");

    res.json({
      message: "Bio updated successfully",
      user,
    });
  } catch (err) {
    console.error("Bio update error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Posts routes
app.post(
  "/instaServer/api/posts",
  authenticate,
  upload.single("image"),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ error: "Image is required" });
      }

      const { caption } = req.body;
      const imageUrl = `/uploads/${req.file.filename}`;

      const post = await Post.create({
        user: req.user._id,
        caption,
        imageUrl,
      });

      // Add post to user's posts array
      await User.findByIdAndUpdate(req.user._id, {
        $push: { posts: post._id },
      });

      // Populate user data in the response
      const populatedPost = await Post.findById(post._id).populate(
        "user",
        "username profilePhoto"
      );

      res.status(201).json({
        message: "Post created successfully",
        post: populatedPost,
      });
    } catch (err) {
      console.error("Create post error:", err);
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

app.get("/instaServer/api/posts", authenticate, async (req, res) => {
  try {
    const posts = await Post.find()
      .populate("user", "username profilePhoto")
      .populate("likes", "username profilePhoto")
      .sort({ createdAt: -1 });

    res.json({ posts });
  } catch (err) {
    console.error("Get posts error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post(
  "/instaServer/api/posts/:postId/like",
  authenticate,
  async (req, res) => {
    try {
      const post = await Post.findById(req.params.postId);
      if (!post) {
        return res.status(404).json({ error: "Post not found" });
      }

      const isLiked = post.likes.includes(req.user._id);

      if (isLiked) {
        await Post.findByIdAndUpdate(req.params.postId, {
          $pull: { likes: req.user._id },
        });
      } else {
        await Post.findByIdAndUpdate(req.params.postId, {
          $push: { likes: req.user._id },
        });
      }

      const updatedPost = await Post.findById(req.params.postId)
        .populate("user", "username profilePhoto")
        .populate("likes", "username profilePhoto");

      res.json({
        message: isLiked ? "Post unliked" : "Post liked",
        post: updatedPost,
      });
    } catch (err) {
      console.error("Like post error:", err);
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

app.post(
  "/instaServer/api/posts/:postId/comment",
  authenticate,
  async (req, res) => {
    try {
      const { text } = req.body;
      if (!text) {
        return res.status(400).json({ error: "Comment text is required" });
      }

      const post = await Post.findByIdAndUpdate(
        req.params.postId,
        {
          $push: {
            comments: {
              user: req.user._id,
              text,
            },
          },
        },
        { new: true }
      ).populate("comments.user", "username profilePhoto");

      if (!post) {
        return res.status(404).json({ error: "Post not found" });
      }

      res.json({
        message: "Comment added successfully",
        comments: post.comments,
      });
    } catch (err) {
      console.error("Add comment error:", err);
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

// Follow routes
app.post(
  "/instaServer/api/follow/:targetUserId",
  authenticate,
  async (req, res) => {
    try {
      const targetUserId = req.params.targetUserId;

      if (req.user._id.toString() === targetUserId) {
        return res.status(400).json({ error: "Cannot follow yourself" });
      }

      const targetUser = await User.findById(targetUserId);
      if (!targetUser) {
        return res.status(404).json({ error: "User not found" });
      }

      const user = await User.findById(req.user._id);
      const isFollowing = user.following.includes(targetUserId);

      if (isFollowing) {
        // Unfollow
        user.following.pull(targetUserId);
        targetUser.followers.pull(req.user._id);
      } else {
        // Follow
        user.following.push(targetUserId);
        targetUser.followers.push(req.user._id);
      }

      await Promise.all([user.save(), targetUser.save()]);

      res.json({
        message: isFollowing
          ? "Unfollowed successfully"
          : "Followed successfully",
        isFollowing: !isFollowing,
        followersCount: targetUser.followers.length,
      });
    } catch (err) {
      console.error("Follow error:", err);
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

app.get("/instaServer/api/following", authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id)
      .populate("following", "username profilePhoto")
      .select("following");

    res.json({ following: user.following });
  } catch (err) {
    console.error("Get following error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/instaServer/api/followers", authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id)
      .populate("followers", "username profilePhoto")
      .select("followers");

    res.json({ followers: user.followers });
  } catch (err) {
    console.error("Get followers error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Search users
app.get("/instaServer/api/users/search", authenticate, async (req, res) => {
  try {
    const { query } = req.query;
    if (!query) {
      return res.status(400).json({ error: "Search query is required" });
    }

    const users = await User.find({
      $or: [
        { username: { $regex: query, $options: "i" } },
        { email: { $regex: query, $options: "i" } },
      ],
    }).select("username email profilePhoto");

    res.json({ users });
  } catch (err) {
    console.error("Search error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Get user profile
app.get("/instaServer/api/users/:userId", authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.params.userId)
      .select("-password")
      .populate("followers", "username profilePhoto")
      .populate("following", "username profilePhoto")
      .populate({
        path: "posts",
        populate: {
          path: "user",
          select: "username profilePhoto",
        },
      });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Check if the current user is following this user
    const isFollowing = user.followers.some(
      (follower) => follower._id.toString() === req.user._id.toString()
    );

    res.json({
      user,
      isFollowing,
    });
  } catch (err) {
    console.error("Get user error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: "Something went wrong!" });
});

// Start server
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
