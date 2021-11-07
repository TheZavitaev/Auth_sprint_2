import functools
import os

import jaeger_client
from flask_opentracing import FlaskTracer
from jaeger_client import Config


def _setup_jaeger():
    return Config(
        config={
            'sampler': {
                'type': 'const',
                'param': 1
            },
            'local_agent': {
                'enabled': os.getenv('JAEGER_TRACING', False),
                'reporting_port': os.environ.get(
                    'JAEGER_AGENT_PORT', jaeger_client.config.DEFAULT_REPORTING_PORT
                ),
                'reporting_host': os.environ.get('JAEGER_AGENT_HOST', 'jaeger'),
            },
            'logging': os.environ.get('JAEGER_LOGGING', False),
        },
        service_name='movies-api',
        validate=True,
    ).initialize_tracer()


tracer: FlaskTracer = None


# Decorator
def trace(fn):
    @functools.wraps(fn)
    def decorated(*args, **kwargs):
        with tracer.start_span(operation_name=fn.__name__) as span:
            return fn(*args, **kwargs)
    return decorated
