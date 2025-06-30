#!/bin/bash

# Universal Bitcoin - Quick Start Script
# 
# Automates the setup and startup of the Universal Bitcoin development environment.

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Main setup function
main() {
    echo "🚀 Universal Bitcoin - Quick Start Setup"
    echo "========================================"
    echo ""
    
    # Check prerequisites
    print_status "Checking prerequisites..."
    
    if ! command_exists docker; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    if ! command_exists docker-compose; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    print_success "Prerequisites check passed"
    echo ""
    
    # Setup environment file
    print_status "Setting up environment configuration..."
    
    if [ ! -f .env ]; then
        print_status "Creating .env file from template..."
        cp .env.example .env
        print_warning "Please review and update the .env file with your actual values"
        print_warning "Especially update JWT secrets, master seed, and API keys for production use"
    else
        print_status ".env file already exists"
    fi
    
    echo ""
    
    # Build and start services
    print_status "Building and starting Universal Bitcoin services..."
    
    # Stop any existing containers
    print_status "Stopping any existing containers..."
    docker-compose down --volumes 2>/dev/null || true
    
    # Build the application image
    print_status "Building Universal Bitcoin application..."
    docker-compose build app
    
    # Start the services
    print_status "Starting all services (PostgreSQL, Redis, Application)..."
    docker-compose up -d postgres redis
    
    # Wait for services to be ready
    print_status "Waiting for services to be ready..."
    sleep 10
    
    # Start the main application
    docker-compose up -d app
    
    # Wait for application to start
    print_status "Waiting for application to start..."
    sleep 5
    
    # Check health
    print_status "Checking service health..."
    
    max_attempts=30
    attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if curl -f http://localhost:3000/api/v1/health >/dev/null 2>&1; then
            break
        fi
        
        print_status "Attempt $attempt/$max_attempts - waiting for application..."
        sleep 2
        attempt=$((attempt + 1))
    done
    
    if [ $attempt -gt $max_attempts ]; then
        print_error "Application failed to start within expected time"
        print_status "Checking logs..."
        docker-compose logs app
        exit 1
    fi
    
    print_success "Universal Bitcoin is running successfully!"
    echo ""
    
    # Display service information
    echo "🎉 Setup Complete!"
    echo "=================="
    echo ""
    echo "📡 API Endpoints:"
    echo "   Main API: http://localhost:3000"
    echo "   Health Check: http://localhost:3000/api/v1/health"
    echo "   API Info: http://localhost:3000/api/v1/info"
    echo "   Validation: http://localhost:3000/api/v1/validate"
    echo "   Reserves: http://localhost:3000/api/v1/reserves"
    echo ""
    echo "🗄️  Database Admin:"
    echo "   pgAdmin: http://localhost:8080"
    echo "   Username: admin@universalbitcoin.org"
    echo "   Password: development_password"
    echo ""
    echo "🔧 Redis Admin (optional):"
    echo "   Start with: docker-compose --profile admin up -d redis-commander"
    echo "   Redis Commander: http://localhost:8081"
    echo ""
    echo "📊 Monitoring (optional):"
    echo "   Start with: docker-compose --profile logging up -d elasticsearch kibana"
    echo "   Kibana: http://localhost:5601"
    echo ""
    echo "🐳 Docker Commands:"
    echo "   View logs: docker-compose logs -f app"
    echo "   Stop services: docker-compose down"
    echo "   Restart: docker-compose restart app"
    echo "   Clean restart: docker-compose down --volumes && ./scripts/start.sh"
    echo ""
    echo "🔧 Development:"
    echo "   The application supports hot reloading in development mode"
    echo "   Edit files and the application will automatically restart"
    echo ""
    
    # Test the API
    print_status "Running basic API tests..."
    
    echo "Testing health endpoint..."
    if curl -s http://localhost:3000/api/v1/health | jq . >/dev/null 2>&1; then
        print_success "Health check passed"
    else
        print_warning "Health check failed (jq not installed for JSON formatting)"
    fi
    
    echo "Testing info endpoint..."
    if curl -s http://localhost:3000/api/v1/info >/dev/null 2>&1; then
        print_success "API info endpoint accessible"
    else
        print_warning "API info endpoint not accessible"
    fi
    
    echo "Testing reserves endpoint..."
    if curl -s http://localhost:3000/api/v1/reserves >/dev/null 2>&1; then
        print_success "Reserves endpoint accessible"
    else
        print_warning "Reserves endpoint not accessible"
    fi
    
    echo ""
    print_success "Universal Bitcoin is ready for development! 🎯"
    echo ""
    echo "Next steps:"
    echo "1. Review the API documentation at http://localhost:3000/api/v1/info"
    echo "2. Test the validation endpoint with a sample request"
    echo "3. Check the Guardian Angels status in the logs"
    echo "4. Configure your blockchain RPC endpoints in .env"
    echo ""
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --help, -h     Show this help message"
    echo "  --clean        Clean all volumes and restart from scratch"
    echo "  --logs         Show application logs after startup"
    echo "  --stop         Stop all services"
    echo ""
}

# Parse command line arguments
case "${1:-}" in
    --help|-h)
        show_usage
        exit 0
        ;;
    --clean)
        print_status "Cleaning all volumes and restarting..."
        docker-compose down --volumes
        docker system prune -f
        main
        ;;
    --logs)
        main
        print_status "Showing application logs..."
        docker-compose logs -f app
        ;;
    --stop)
        print_status "Stopping all Universal Bitcoin services..."
        docker-compose down
        print_success "All services stopped"
        exit 0
        ;;
    "")
        main
        ;;
    *)
        print_error "Unknown option: $1"
        show_usage
        exit 1
        ;;
esac