"""Export sample detectors for framework demonstration."""

from caliper.detectors.process.tested_by import TestedByAnnotationDetector
from caliper.detectors.reliability.cache_eviction import CacheEvictionDetector
from caliper.detectors.security.jwt_audience import JWTAudienceDetector
from caliper.detectors.security.secret_str import SecretStrDetector

__all__ = [
    "JWTAudienceDetector",
    "SecretStrDetector",
    "CacheEvictionDetector",
    "TestedByAnnotationDetector",
]
