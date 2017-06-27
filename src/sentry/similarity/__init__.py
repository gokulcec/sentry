from __future__ import absolute_import

from django.conf import settings

from sentry.similarity.features import (
    ExceptionFeature,
    MessageFeature,
    FeatureSet,
    get_application_chunks,
)
from sentry.similarity.index import MinHashIndex
from sentry.utils import redis
from sentry.utils.datastructures import BidirectionalMapping
from sentry.utils.iterators import shingle


features = FeatureSet(
    MinHashIndex(
        redis.clusters.get(
            getattr(
                settings,
                'SENTRY_SIMILARITY_INDEX_REDIS_CLUSTER',
                'default',
            ),
        ),
        0xFFFF,
        8,
        2,
        60 * 60 * 24 * 30,
        3,
    ),
    BidirectionalMapping({
        'exception:message:character-shingles': 'a',
        'exception:stacktrace:application-chunks': 'b',
        'exception:stacktrace:pairs': 'c',
        'message:message:character-shingles': 'd',
    }),
    {
        'exception:message:character-shingles': ExceptionFeature(
            lambda exception: shingle(
                13,
                exception.value,
            ),
        ),
        'exception:stacktrace:application-chunks': ExceptionFeature(
            lambda exception: get_application_chunks(exception),
        ),
        'exception:stacktrace:pairs': ExceptionFeature(
            lambda exception: shingle(
                2,
                exception.stacktrace.frames,
            ),
        ),
        'message:message:character-shingles': MessageFeature(
            lambda message: shingle(
                13,
                message.message,
            ),
        ),
    }
)
