const { Client } = require("minio");
const config = require("./index");

const minioClient = new Client({
  endPoint: config.minio.endPoint,
  port: config.minio.port,
  useSSL: config.minio.useSSL,
  accessKey: config.minio.accessKey,
  secretKey: config.minio.secretKey,
});

async function ensureBucket() {
  const exists = await minioClient.bucketExists(config.minio.bucket);
  if (!exists) {
    await minioClient.makeBucket(config.minio.bucket);
    // Set bucket policy for public read on avatars
    const policy = {
      Version: "2012-10-17",
      Statement: [
        {
          Effect: "Allow",
          Principal: { AWS: ["*"] },
          Action: ["s3:GetObject"],
          Resource: [`arn:aws:s3:::${config.minio.bucket}/avatars/*`],
        },
      ],
    };
    await minioClient.setBucketPolicy(config.minio.bucket, JSON.stringify(policy));
    console.log(`Bucket "${config.minio.bucket}" created`);
  }
}

module.exports = { minioClient, ensureBucket };
