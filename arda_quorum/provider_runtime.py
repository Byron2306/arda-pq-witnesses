"""Load operator-pinned public configuration and provider-held runtime secrets."""
import os
from pathlib import Path
import re
from .quorum import strict_load,sha,need,hex64,unbase64,enrollment
from .provider_witness import ReviewWitness

SECRET={'github':'ARDA_GITHUB_SIGNER_PKCS8_B64','hf':'ARDA_HF_SIGNER_PKCS8_B64'}
CONFIG_FIELDS={'schema','provider','policy_file_sha256','stage_request_sha256','source_manifest_sha256','image_digest','runtime_identity'}

def load_runtime(provider,root=None,environ=None,clock=None):
    root=Path(root) if root is not None else Path(__file__).resolve().parents[1]
    env=dict(os.environ if environ is None else environ)
    need(provider in SECRET,'fixed_provider_required')
    if provider=='hf':
        text=env.get('ARDA_PROVIDER_CONFIG_JSON');need(type(text) is str and len(text)<=16384,'hf_public_configuration_missing')
        config_raw=text.encode()
    else:config_raw=(root/'operator-config'/f'{provider}.json').read_bytes()
    need(hex64(env.get('ARDA_PROVIDER_CONFIG_SHA256')) and sha(config_raw)==env['ARDA_PROVIDER_CONFIG_SHA256'],'operator_provider_configuration_pin')
    config=strict_load(config_raw)
    need(type(config) is dict and config.keys()==CONFIG_FIELDS and config['schema']=='arda.pq.provider_config.v1' and config['provider']==provider,'provider_configuration_fields')
    need(type(config['image_digest']) is str and re.fullmatch('sha256:[0-9a-f]{64}',config['image_digest'])
         and env.get('ARDA_IMAGE_DIGEST')==config['image_digest'],'provider_image_configuration_binding')
    identity=config['runtime_identity']
    if provider=='github':
        need(type(identity) is dict and identity.keys()=={'repository','workflow_ref','commit_sha'},'github_identity_fields')
        need(type(identity['repository']) is str and re.fullmatch('[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',identity['repository'])
             and type(identity['workflow_ref']) is str and identity['workflow_ref'].startswith(identity['repository']+'/.github/workflows/')
             and type(identity['commit_sha']) is str and re.fullmatch('[0-9a-f]{40}',identity['commit_sha']),'github_identity_format')
        need(env.get('GITHUB_ACTIONS')=='true' and env.get('GITHUB_REPOSITORY')==identity['repository']
             and env.get('GITHUB_WORKFLOW_REF')==identity['workflow_ref'] and env.get('GITHUB_SHA')==identity['commit_sha'],'github_runtime_identity_binding')
    else:
        need(type(identity) is dict and identity.keys()=={'space_id'} and type(identity['space_id']) is str
             and re.fullmatch('[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',identity['space_id'])
             and env.get('SPACE_ID')==identity['space_id'],'hf_runtime_identity_binding')
    public=root/'providers/public-r13'
    if provider=='hf':
        text=env.get('ARDA_ENROLLMENT_JSON');need(type(text) is str and len(text)<=65536,'hf_public_enrollment_missing')
        policy_bytes=text.encode()
    else:policy_bytes=(root/'operator-config/enrollment.json').read_bytes()
    need(sha(policy_bytes)==config['policy_file_sha256'],'provider_enrollment_file_pin')
    import time
    from .enrollment import secret_name
    admitted=enrollment(strict_load(policy_bytes),int((clock or time.time)()))
    selected=secret_name(provider,admitted[provider][0]['key_sha256'])
    named=env.get(selected);legacy=env.get(SECRET[provider])
    need(named is None or legacy is None or named==legacy,'conflicting_provider_signing_secrets')
    value=named if named is not None else legacy
    need(type(value) is str,'provider_private_key_secret_missing')
    private=unbase64(value,16384)
    return ReviewWitness(provider=provider,policy_bytes=policy_bytes,
        policy_file_sha256=config['policy_file_sha256'],stage_bytes=(root/'inputs/generation14-staging-request.json').read_bytes(),
        stage_request_sha256=config['stage_request_sha256'],verifier_pem=(public/'verifier-public.pem').read_bytes(),
        ak_pem=(public/'ak-public.pem').read_bytes(),approved_pcrs=strict_load((public/'approved-pcrs.json').read_bytes()),
        private_key_der=private,source_root=root,source_manifest_bytes=(root/'REVIEWED_SOURCE_FILES.json').read_bytes(),
        source_manifest_sha256=config['source_manifest_sha256'],clock=clock)
