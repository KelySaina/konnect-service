const path = require("path");
const crypto = require("crypto");
const { minioClient, ensureBucket } = require("../config/minio");
const config = require("../config");

const BUCKET = config.minio.bucket;

/**
 * Upload a file buffer to MinIO.
 * @param {Buffer} buffer
 * @param {string} originalName
 * @param {string} folder - e.g. "avatars", "documents"
 * @param {string} contentType
 * @returns {Promise<{key: string, url: string}>}
 */
async function uploadFile(buffer, originalName, folder = "uploads", contentType = "application/octet-stream") {
  await ensureBucket();
  const ext = path.extname(originalName);
  const key = `${folder}/${crypto.randomUUID()}${ext}`;

  await minioClient.putObject(BUCKET, key, buffer, buffer.length, {
    "Content-Type": contentType,
  });

  return { key };
}

/**
 * Upload a user avatar (resizing should be done beforehand).
 */
async function uploadAvatar(buffer, originalName, contentType) {
  return uploadFile(buffer, originalName, "avatars", contentType);
}

/**
 * Get a presigned URL for private objects.
 * @param {string} key
 * @param {number} expiry - seconds (default 1h)
 */
async function getPresignedUrl(key, expiry = 3600) {
  return minioClient.presignedGetObject(BUCKET, key, expiry);
}

/**
 * Delete an object.
 */
async function deleteFile(key) {
  await minioClient.removeObject(BUCKET, key);
}

/**
 * List objects under a prefix.
 */
async function listFiles(prefix = "") {
  return new Promise((resolve, reject) => {
    const objects = [];
    const stream = minioClient.listObjects(BUCKET, prefix, true);
    stream.on("data", (obj) => objects.push(obj));
    stream.on("error", reject);
    stream.on("end", () => resolve(objects));
  });
}

/**
 * Stream an object from MinIO.
 * @param {string} key
 * @returns {Promise<{stream: ReadableStream, stat: object}>}
 */
async function getFileStream(key) {
  const stat = await minioClient.statObject(BUCKET, key);
  const stream = await minioClient.getObject(BUCKET, key);
  return { stream, stat };
}

module.exports = { BUCKET, uploadFile, uploadAvatar, getPresignedUrl, deleteFile, listFiles, getFileStream };
