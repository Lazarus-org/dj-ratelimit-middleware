from typing import Any, Callable, Optional, Union
import time
import json
import logging
from redis import Redis
from redis.exceptions import RedisError
from django.conf import settings
from django.core.cache import cache
from django.http import HttpRequest, HttpResponse

from .exec import RateLimitExceeded

logger = logging.getLogger(__name__)


class RateLimitMiddleware:
    """Django middleware for rate limiting requests using Redis.
    
    This middleware tracks requests per IP address using Redis sorted sets.
    When a client exceeds the configured rate limit, they receive a 429 response.
    
    Attributes:
        rate_limit (int): Maximum number of requests allowed within the time window
        time_window (int): Time window in seconds for rate limiting
        exempt_paths (list[str]): URL paths exempt from rate limiting
        exempt_ips (list[str]): IP addresses exempt from rate limiting
    """

    def __init__(self, get_response: Callable) -> None:
        """Initialize the middleware.
        
        Args:
            get_response: Django response callback
            
        Raises:
            RedisError: If Redis connection fails
        """
        self.get_response = get_response
        
        try:
            # Initialize Redis connection using settings
            self.redis_client = Redis(
                host=getattr(settings, 'RATELIMIT_REDIS_HOST', 'localhost'),
                port=getattr(settings, 'RATELIMIT_REDIS_PORT', 6379),
                db=getattr(settings, 'RATELIMIT_REDIS_DB', 0),
                password=getattr(settings, 'RATELIMIT_REDIS_PASSWORD', None),
                socket_timeout=getattr(settings, 'RATELIMIT_REDIS_TIMEOUT', 1),
                decode_responses=True
            )
            # Test connection
            self.redis_client.ping()
        except RedisError as e:
            logger.error(f"Failed to connect to Redis: {e}")
            # Fallback to more permissive settings if Redis is unavailable
            self.rate_limit = getattr(settings, 'RATELIMIT_FALLBACK_RATE', 1000)
            self.time_window = getattr(settings, 'RATELIMIT_FALLBACK_WINDOW', 60)
        else:
            # Get settings with defaults
            self.rate_limit = getattr(settings, 'RATELIMIT_RATE', 60)
            self.time_window = getattr(settings, 'RATELIMIT_WINDOW', 60)
            
        self.exempt_paths = getattr(settings, 'RATELIMIT_EXEMPT_PATHS', [])
        self.exempt_ips = getattr(settings, 'RATELIMIT_EXEMPT_IPS', [])
        
        # Additional settings
        self.include_user_agent = getattr(settings, 'RATELIMIT_INCLUDE_USER_AGENT', False)
        self.enable_headers = getattr(settings, 'RATELIMIT_ENABLE_HEADERS', True)

    def get_client_ip(self, request: HttpRequest) -> str:
        """Extract client IP address from request.
        
        Handles X-Forwarded-For header for clients behind a proxy.
        
        Args:
            request: Django HTTP request
            
        Returns:
            str: Client IP address
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '')
        return ip

    def get_rate_limit_key(self, request: HttpRequest) -> str:
        """Generate Redis key for rate limiting.
        
        Args:
            request: Django HTTP request
            
        Returns:
            str: Redis key for rate limiting
        """
        key_parts = ['ratelimit', self.get_client_ip(request)]
        
        if self.include_user_agent:
            user_agent = request.META.get('HTTP_USER_AGENT', '')
            key_parts.append(user_agent)
            
        return ':'.join(key_parts)

    def should_be_limited(self, request: HttpRequest) -> tuple[bool, int]:
        """Check if request should be rate limited.
        
        Args:
            request: Django HTTP request
            
        Returns:
            tuple[bool, int]: (should_limit, current_request_count)
            
        Raises:
            RedisError: If Redis operation fails
        """
        # Check if path is exempt
        path = request.path_info.lstrip('/')
        if any(path.startswith(exempt) for exempt in self.exempt_paths):
            return False, 0

        # Check if IP is exempt
        client_ip = self.get_client_ip(request)
        if client_ip in self.exempt_ips:
            return False, 0

        try:
            # Generate a unique key for this IP/User-Agent
            key = self.get_rate_limit_key(request)
            
            pipe = self.redis_client.pipeline()
            now = time.time()
            
            # Clean old requests
            pipe.zremrangebyscore(key, 0, now - self.time_window)
            
            # Count requests in current window
            pipe.zcard(key)
            
            # Add current request
            pipe.zadd(key, {str(now): now})
            
            # Set expiry
            pipe.expire(key, self.time_window)
            
            # Execute pipeline
            _, request_count, *_ = pipe.execute()
            
            return request_count > self.rate_limit, request_count
            
        except RedisError as e:
            logger.error(f"Redis error in rate limiting: {e}")
            # Be permissive on Redis errors
            return False, 0

    def add_rate_limit_headers(self, response: HttpResponse, request_count: int) -> None:
        """Add rate limit headers to response.
        
        Args:
            response: Django HTTP response
            request_count: Current request count
        """
        if self.enable_headers:
            response['X-RateLimit-Limit'] = str(self.rate_limit)
            response['X-RateLimit-Remaining'] = str(max(0, self.rate_limit - request_count))
            response['X-RateLimit-Reset'] = str(self.time_window)

    def __call__(self, request: HttpRequest) -> HttpResponse:
        """Process the request and apply rate limiting.
        
        Args:
            request: Django HTTP request
            
        Returns:
            HttpResponse: Django HTTP response
        """
        try:
            should_limit, request_count = self.should_be_limited(request)
            
            if should_limit:
                response = HttpResponse(
                    json.dumps({
                        'error': 'Rate limit exceeded',
                        'detail': f'Please try again in {self.time_window} seconds'
                    }),
                    content_type='application/json',
                    status=429
                )
                response['Retry-After'] = str(self.time_window)
                self.add_rate_limit_headers(response, request_count)
                return response

            response = self.get_response(request)
            self.add_rate_limit_headers(response, request_count)
            return response
            
        except Exception as e:
            logger.error(f"Error in rate limiting middleware: {e}")
            # On unexpected errors, let the request through
            return self.get_response(request) 