# Universal Bitcoin - Multi-stage Dockerfile
# 
# Optimized Docker image for Universal Bitcoin proof-of-reserves system.
# Supports both development and production environments.

# Base Node.js image
FROM node:20-alpine AS base

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apk add --no-cache \
    git \
    curl \
    bash \
    tzdata \
    && rm -rf /var/cache/apk/*

# Set timezone
ENV TZ=UTC

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nextjs -u 1001

# Copy package files
COPY package*.json ./

# Development stage
FROM base AS development

# Install all dependencies (including dev dependencies)
RUN npm ci --include=dev

# Copy source code
COPY . .

# Change ownership to nodejs user
RUN chown -R nodejs:nodejs /app
USER nodejs

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/api/v1/health || exit 1

# Start development server
CMD ["npm", "run", "dev"]

# Production dependencies stage
FROM base AS prod-deps

# Install only production dependencies
RUN npm ci --only=production && npm cache clean --force

# Production stage
FROM base AS production

# Install dumb-init for proper signal handling
RUN apk add --no-cache dumb-init

# Copy production dependencies
COPY --from=prod-deps /app/node_modules ./node_modules

# Copy source code
COPY --chown=nodejs:nodejs . .

# Remove unnecessary files
RUN rm -rf \
    .git \
    .gitignore \
    .dockerignore \
    README.md \
    docker-compose.yml \
    Dockerfile \
    .env.example \
    tests/ \
    docs/ \
    scripts/

# Set production environment
ENV NODE_ENV=production
ENV PORT=3000

# Switch to non-root user
USER nodejs

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/api/v1/health || exit 1

# Start production server with dumb-init
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "src/index.js"]

# Build stage for creating optimized build
FROM base AS build

# Install all dependencies
RUN npm ci --include=dev

# Copy source code
COPY . .

# Run any build steps (placeholder for future build process)
# RUN npm run build

# Final production image
FROM production AS final

# Copy built assets (if any)
# COPY --from=build /app/dist ./dist

# Labels for metadata
LABEL maintainer="Universal Bitcoin Team <team@universalbitcoin.org>"
LABEL description="Universal Bitcoin proof-of-reserves system with Guardian Angels security"
LABEL version="1.0.0"
LABEL org.opencontainers.image.source="https://github.com/universalbitcoin/api"
LABEL org.opencontainers.image.documentation="https://docs.universalbitcoin.org"
LABEL org.opencontainers.image.licenses="MIT"

# Final configuration
ENV NODE_ENV=production
ENV PORT=3000
EXPOSE 3000

# Use node user for security
USER nodejs

# Start the application
CMD ["node", "src/index.js"]