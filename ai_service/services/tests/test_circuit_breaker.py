import pytest
from services.circuit_breaker import RedisCircuitBreaker, CircuitBreakerConfig

@pytest.mark.asyncio
async def test_circuit_opens_on_failures(fake_redis):
    breaker = RedisCircuitBreaker(
        fake_redis,
        CircuitBreakerConfig(min_requests=3, error_rate_threshold=0.5),
    )

    name = "test"

    await breaker.record_failure(name)
    await breaker.record_failure(name)
    await breaker.record_failure(name)

    assert await breaker.is_open(name) is True
