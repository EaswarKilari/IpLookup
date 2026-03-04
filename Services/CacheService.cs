using System.Text.Json;
using StackExchange.Redis;

namespace IpLookup.Services;

public interface ICacheService
{
    Task<T?> GetAsync<T>(string key) where T : class;
    Task SetAsync<T>(string key, T value, TimeSpan expiration) where T : class;
    Task<bool> ExistsAsync(string key);
    Task RemoveAsync(string key);
}

public class RedisCacheService : ICacheService
{
    private readonly IConnectionMultiplexer? _redis;
    private readonly ILogger<RedisCacheService> _logger;
    private readonly bool _isConnected;

    public RedisCacheService(IConfiguration configuration, ILogger<RedisCacheService> logger)
    {
        _logger = logger;

        var connectionString = configuration["Redis:ConnectionString"];
        if (string.IsNullOrEmpty(connectionString))
        {
            _logger.LogWarning("Redis connection string not configured. Caching disabled.");
            _isConnected = false;
            return;
        }

        try
        {
            var options = ConfigurationOptions.Parse(connectionString);
            options.AbortOnConnectFail = false;
            options.ConnectTimeout = 5000;
            options.SyncTimeout = 5000;

            _redis = ConnectionMultiplexer.Connect(options);
            _isConnected = _redis.IsConnected;

            if (_isConnected)
            {
                _logger.LogInformation("Connected to Redis");
            }
            else
            {
                _logger.LogWarning("Redis connection failed. Caching disabled.");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to connect to Redis");
            _isConnected = false;
        }
    }

    public async Task<T?> GetAsync<T>(string key) where T : class
    {
        if (!_isConnected || _redis == null)
            return null;

        try
        {
            var db = _redis.GetDatabase();
            var value = await db.StringGetAsync(key);

            if (value.IsNullOrEmpty)
                return null;

            return JsonSerializer.Deserialize<T>(value!);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting key {Key} from cache", key);
            return null;
        }
    }

    public async Task SetAsync<T>(string key, T value, TimeSpan expiration) where T : class
    {
        if (!_isConnected || _redis == null)
            return;

        try
        {
            var db = _redis.GetDatabase();
            var json = JsonSerializer.Serialize(value);
            await db.StringSetAsync(key, json, expiration);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error setting key {Key} in cache", key);
        }
    }

    public async Task<bool> ExistsAsync(string key)
    {
        if (!_isConnected || _redis == null)
            return false;

        try
        {
            var db = _redis.GetDatabase();
            return await db.KeyExistsAsync(key);
        }
        catch
        {
            return false;
        }
    }

    public async Task RemoveAsync(string key)
    {
        if (!_isConnected || _redis == null)
            return;

        try
        {
            var db = _redis.GetDatabase();
            await db.KeyDeleteAsync(key);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error removing key {Key} from cache", key);
        }
    }
}

// In-memory fallback cache for when Redis is unavailable
public class MemoryCacheService : ICacheService
{
    private readonly Dictionary<string, (object Value, DateTime Expiration)> _cache = new();
    private readonly object _lock = new();
    private readonly ILogger<MemoryCacheService> _logger;

    public MemoryCacheService(ILogger<MemoryCacheService> logger)
    {
        _logger = logger;
        _logger.LogInformation("Using in-memory cache (Redis unavailable)");
    }

    public Task<T?> GetAsync<T>(string key) where T : class
    {
        lock (_lock)
        {
            if (_cache.TryGetValue(key, out var entry))
            {
                if (entry.Expiration > DateTime.UtcNow)
                {
                    return Task.FromResult((T?)entry.Value);
                }
                _cache.Remove(key);
            }
        }
        return Task.FromResult<T?>(null);
    }

    public Task SetAsync<T>(string key, T value, TimeSpan expiration) where T : class
    {
        lock (_lock)
        {
            _cache[key] = (value, DateTime.UtcNow.Add(expiration));

            // Simple cleanup - remove expired entries if cache is getting large
            if (_cache.Count > 1000)
            {
                var expiredKeys = _cache.Where(x => x.Value.Expiration <= DateTime.UtcNow)
                    .Select(x => x.Key).ToList();
                foreach (var k in expiredKeys)
                    _cache.Remove(k);
            }
        }
        return Task.CompletedTask;
    }

    public Task<bool> ExistsAsync(string key)
    {
        lock (_lock)
        {
            if (_cache.TryGetValue(key, out var entry))
            {
                return Task.FromResult(entry.Expiration > DateTime.UtcNow);
            }
        }
        return Task.FromResult(false);
    }

    public Task RemoveAsync(string key)
    {
        lock (_lock)
        {
            _cache.Remove(key);
        }
        return Task.CompletedTask;
    }
}
