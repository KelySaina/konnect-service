const express = require("express");
const multer = require("multer");
const { authenticate } = require("../middleware/auth");
const storageService = require("../services/storageService");
const { User } = require("../models");

const router = express.Router();

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (_req, file, cb) => {
    const allowed = ["image/jpeg", "image/png", "image/webp", "image/gif"];
    cb(null, allowed.includes(file.mimetype));
  },
});

// Upload/update current user's avatar
router.post("/users/me/avatar", authenticate, upload.single("avatar"), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: "No valid image file provided" });
  }

  let result;
  try {
    result = await storageService.uploadAvatar(
      req.file.buffer,
      req.file.originalname,
      req.file.mimetype
    );
  } catch (err) {
    console.error("[storage] Avatar upload failed:", err.message);
    return res.status(503).json({ error: "Storage service unavailable" });
  }

  const { key } = result;

  // Delete old avatar if exists
  if (req.user.avatar_url) {
    try {
      await storageService.deleteFile(req.user.avatar_url);
    } catch { /* ignore */ }
  }

  await req.user.update({ avatar_url: key });
  res.json({ avatar_url: `/api/files/${key}` });
});

// Delete current user's avatar
router.delete("/users/me/avatar", authenticate, async (req, res) => {
  if (req.user.avatar_url) {
    try {
      await storageService.deleteFile(req.user.avatar_url);
    } catch { /* ignore */ }
    await req.user.update({ avatar_url: null });
  }
  res.json({ avatar_url: null });
});

// Serve files publicly (avatars etc.)
router.get("/files/*", async (req, res) => {
  const key = req.params[0];
  if (!key || key.includes("..")) {
    return res.status(400).json({ error: "Invalid file path" });
  }
  try {
    const { stream, stat } = await storageService.getFileStream(key);
    res.set("Content-Type", stat.metaData?.["content-type"] || "application/octet-stream");
    res.set("Content-Length", stat.size);
    res.set("Cache-Control", "public, max-age=86400");
    stream.pipe(res);
  } catch (err) {
    if (err.code === "NoSuchKey" || err.code === "NotFound") {
      return res.status(404).json({ error: "File not found" });
    }
    console.error("[storage] File serve error:", err.message);
    res.status(500).json({ error: "Storage error" });
  }
});

module.exports = router;
