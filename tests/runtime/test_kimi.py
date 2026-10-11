import io
import json
import ssl
import urllib.error
from unittest.mock import Mock

import pytest

from protection_gateway.runtime.config import RuntimeConfig, local_environment
from protection_gateway.runtime.errors import RuntimeUnavailable
from protection_gateway.runtime.model_broker import ModelConfig
from protection_gateway.runtime.providers import KimiTransport
from protection_gateway.runtime import providers


def test_dotenv_is_data_environment_wins_and_secret_repr_is_scrubbed(tmp_path, monkeypatch):
    for name in ('KIMI_API_KEY', 'PG_MODEL_PROVIDER', 'PG_MODEL'):
        monkeypatch.delenv(name, raising=False)
    path = tmp_path / '.env'
    path.write_text('KIMI_API_KEY="test-key"\nPG_MODEL=kimi-k3\n')
    monkeypatch.setenv('PG_MODEL_REASONING_EFFORT', 'high')
    config = RuntimeConfig.from_env(local_environment(path))
    assert config.model.model == 'kimi-k3' and config.model.reasoning_effort == 'high'
    assert config.model_api_key == 'test-key' and 'test-key' not in repr(config)
    path.write_text('KIMI_API_KEY=$(touch sentinel)\n')
    assert local_environment(path)['KIMI_API_KEY'] == '$(touch sentinel)'
    assert not (tmp_path / 'sentinel').exists()


def test_k3_transport_pins_endpoint_uses_json_and_hashes_reasoning():
    config = ModelConfig(provider='kimi', model='kimi-k3')
    assert config.hash() != ModelConfig(provider='kimi', model='kimi-k3', reasoning_effort='high').hash()
    transport = KimiTransport(config, 'test-key')
    class Opener:
        def open(self, request, timeout):
            assert request.full_url == 'https://api.moonshot.ai/v1/chat/completions'
            body = json.loads(request.data)
            assert body['model'] == 'kimi-k3' and body['reasoning_effort'] == 'low'
            assert body['response_format'] == {'type': 'json_object'}
            assert 'temperature' not in body and 'top_p' not in body
            assert request.get_header('Authorization') == 'Bearer test-key'
            return io.BytesIO(json.dumps({'choices': [{'finish_reason': 'length', 'message': {'content': '{}'}}],
                                         'usage': {'prompt_tokens': 3, 'completion_tokens': 4}}).encode())
    transport._opener = Opener()
    result = transport.generate(config, system='test', user='{}', max_output_tokens=10, timeout=1)
    assert result['stop_reason'] == 'length' and result['usage']['output_tokens'] == 4


def test_provider_error_never_contains_response_body_or_key():
    config = ModelConfig(provider='kimi', model='kimi-k3')
    transport = KimiTransport(config, 'private-test-key')
    class Opener:
        def open(self, request, timeout):
            raise urllib.error.HTTPError(request.full_url, 401, 'private-test-key', {}, io.BytesIO(b'sensitive body'))
    transport._opener = Opener()
    with pytest.raises(RuntimeUnavailable) as caught:
        transport.generate(config, system='test', user='{}', max_output_tokens=10, timeout=1)
    assert caught.value.reason_code == 'MODEL_PROVIDER_UNAUTHENTICATED'
    assert 'private' not in str(caught.value) and 'sensitive' not in str(caught.value)


def test_macos_missing_python_ca_uses_os_bundle_without_disabling_verification(monkeypatch):
    context = Mock()
    context.get_ca_certs.return_value = []
    monkeypatch.setattr(providers.ssl, 'create_default_context', lambda: context)
    monkeypatch.setattr(providers.sys, 'platform', 'darwin')
    monkeypatch.setattr(providers.Path, 'is_file', lambda self: True)
    monkeypatch.delenv('SSL_CERT_FILE', raising=False)
    monkeypatch.delenv('SSL_CERT_DIR', raising=False)
    assert providers._tls_context() is context
    context.load_verify_locations.assert_called_once_with(cafile='/etc/ssl/cert.pem')
    assert 'verify_mode' not in context.__dict__ and 'check_hostname' not in context.__dict__


@pytest.mark.parametrize('configured', ['certificates', 'SSL_CERT_FILE', 'SSL_CERT_DIR', 'other_platform'])
def test_existing_or_explicit_trust_configuration_is_preserved(monkeypatch, configured):
    context = Mock()
    context.get_ca_certs.return_value = [{}] if configured == 'certificates' else []
    monkeypatch.setattr(providers.ssl, 'create_default_context', lambda: context)
    monkeypatch.setattr(providers.sys, 'platform', 'linux' if configured == 'other_platform' else 'darwin')
    monkeypatch.delenv('SSL_CERT_FILE', raising=False)
    monkeypatch.delenv('SSL_CERT_DIR', raising=False)
    if configured in {'SSL_CERT_FILE', 'SSL_CERT_DIR'}:
        monkeypatch.setenv(configured, '/configured/trust')
    assert providers._tls_context() is context
    context.load_verify_locations.assert_not_called()


def test_certificate_failure_has_safe_specific_reason():
    config = ModelConfig(provider='kimi', model='kimi-k3')
    transport = KimiTransport(config, 'private-test-key')
    class Opener:
        def open(self, request, timeout):
            raise urllib.error.URLError(ssl.SSLCertVerificationError('private-test-key'))
    transport._opener = Opener()
    with pytest.raises(RuntimeUnavailable, match='MODEL_PROVIDER_TLS_ERROR') as caught:
        transport.generate(config, system='test', user='{}', max_output_tokens=10, timeout=1)
    assert 'private-test-key' not in str(caught.value)
