/**
 * Global error handler middleware.
 */
function errorHandler(err, req, res, _next) {
  console.error(`[error] ${req.method} ${req.path}:`, err.message);

  if (err.name === "SequelizeValidationError" || err.name === "SequelizeUniqueConstraintError") {
    return res.status(400).json({
      error: "validation_error",
      message: err.errors ? err.errors.map((e) => e.message).join(", ") : err.message,
    });
  }

  if (err.status) {
    return res.status(err.status).json({ error: err.error || "error", message: err.message });
  }

  // Don't leak internal details in production
  const message = process.env.NODE_ENV === "production" ? "Internal server error" : err.message;
  res.status(500).json({ error: "internal_error", message });
}

module.exports = errorHandler;
