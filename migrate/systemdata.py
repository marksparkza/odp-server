import logging
import os
import pathlib
from datetime import datetime, timezone

import yaml
from alembic import command
from alembic.config import Config
from dotenv import load_dotenv
from sqlalchemy import delete, select, text
from sqlalchemy.exc import ProgrammingError

from odp.const import (
    ODPCatalog,
    ODPCollectionTag,
    ODPMetadataSchema,
    ODPRecordTag,
    ODPScope,
    ODPSystemRole,
    ODPTagSchema,
    ODPVocabulary,
    ODPVocabularySchema,
)
from odp.const.db import SchemaType, ScopeType
from odp.const.hydra import GrantType, HydraScope
from odp.db import Base, Session, engine
from odp.db.models import Catalog, Client, Collection, Role, Schema, Scope, Tag, Vocabulary, VocabularyTerm
from odp.lib.hydra import HydraAdminAPI
from odp.lib.schema import schema_md5
from sadco.const import SADCOScope

datadir = pathlib.Path(__file__).parent / 'systemdata'
logger = logging.getLogger(__name__)


def initialize():
    logger.info('Initializing static system data...')

    load_dotenv(pathlib.Path(os.getcwd()) / '.env')  # for a local run; in a container there's no .env

    init_database_schema()

    with Session.begin():
        init_system_scopes()
        init_standard_scopes()
        init_sadco_scopes()
        init_system_roles()
        init_schemas()
        init_vocabularies()
        init_tags()
        init_catalogs()
        init_clients()

    logger.info('Done.')


def init_database_schema():
    """Create or update the ODP database schema."""
    cwd = os.getcwd()
    os.chdir(pathlib.Path(__file__).parent)
    try:
        alembic_cfg = Config('alembic.ini')
        try:
            with engine.connect() as conn:
                conn.execute(text('select version_num from alembic_version'))
            schema_exists = True
        except ProgrammingError:  # from psycopg2.errors.UndefinedTable
            schema_exists = False

        if schema_exists:
            command.upgrade(alembic_cfg, 'head')
        else:
            Base.metadata.create_all(engine)
            command.stamp(alembic_cfg, 'head')
            logger.info('Created the ODP database schema.')
    finally:
        os.chdir(cwd)


def init_system_scopes():
    """Create or update the set of available ODP system scopes."""
    for scope_id in (scope_ids := [s.value for s in ODPScope]):
        if not Session.get(Scope, (scope_id, ScopeType.odp)):
            scope = Scope(id=scope_id, type=ScopeType.odp)
            scope.save()

    Session.execute(
        delete(Scope).
        where(Scope.type == ScopeType.odp).
        where(Scope.id.not_in(scope_ids))
    )


def init_standard_scopes():
    """Create or update the set of available standard OAuth2 scopes."""
    for scope_id in (scope_ids := [s.value for s in HydraScope]):
        if not Session.get(Scope, (scope_id, ScopeType.oauth)):
            scope = Scope(id=scope_id, type=ScopeType.oauth)
            scope.save()

    Session.execute(
        delete(Scope).
        where(Scope.type == ScopeType.oauth).
        where(Scope.id.not_in(scope_ids))
    )


def init_sadco_scopes():
    """Create or update the set of available SADCO API scopes."""
    for scope_id in (scope_ids := [s.value for s in SADCOScope]):
        if not Session.get(Scope, (scope_id, ScopeType.client)):
            scope = Scope(id=scope_id, type=ScopeType.client)
            scope.save()

    Session.execute(
        delete(Scope).
        where(Scope.type == ScopeType.client).
        where(Scope.id.like('sadco.%')).
        where(Scope.id.not_in(scope_ids))
    )


def init_system_roles():
    """Create or update system roles."""
    with open(datadir / 'roles.yml') as f:
        role_data = yaml.safe_load(f)

    for role_id in (role_ids := [r.value for r in ODPSystemRole]):
        role = Session.get(Role, role_id) or Role(id=role_id)
        role_spec = role_data[role_id]
        role.scopes = [
            Session.execute(select(Scope).where(Scope.id == scope_id)).scalar_one()
            for scope_id in _expand_scopes(role_spec['scopes'])
        ]
        role.save()

    if orphaned_yml_roles := [role_id for role_id in role_data if role_id not in role_ids]:
        logger.warning(f'Orphaned role definitions in roles.yml {orphaned_yml_roles}')


def init_schemas():
    """Create or update schema definitions."""
    with open(datadir / 'schemas.yml') as f:
        schema_data = yaml.safe_load(f)

    for schema_id in (schema_ids := [s.value for s in ODPMetadataSchema] +
                                    [s.value for s in ODPTagSchema] +
                                    [s.value for s in ODPVocabularySchema]):
        schema_spec = schema_data[schema_id]
        schema_type = schema_spec['type']
        schema = Session.get(Schema, (schema_id, schema_type)) or Schema(id=schema_id, type=schema_type)
        schema.uri = schema_spec['uri']

        if (md5 := schema_md5(schema.uri)) != schema.md5:
            schema.md5 = md5
            schema.timestamp = datetime.now(timezone.utc)
            logger.info(f'Updated MD5 and timestamp for schema {schema_id}')

        schema.save()

    if orphaned_yml_schemas := [schema_id for schema_id in schema_data if schema_id not in schema_ids]:
        logger.warning(f'Orphaned schema definitions in schemas.yml {orphaned_yml_schemas}')

    if orphaned_db_schemas := Session.execute(select(Schema.id).where(Schema.id.not_in(schema_ids))).scalars().all():
        logger.warning(f'Orphaned schema definitions in schema table {orphaned_db_schemas}')


def init_tags():
    """Create or update tag definitions."""
    with open(datadir / 'tags.yml') as f:
        tag_data = yaml.safe_load(f)

    for tag_id in (tag_ids := [t.value for t in ODPRecordTag] + [t.value for t in ODPCollectionTag]):
        tag_spec = tag_data[tag_id]
        tag_type = tag_spec['type']
        tag = Session.get(Tag, (tag_id, tag_type)) or Tag(id=tag_id, type=tag_type)
        tag.cardinality = tag_spec['cardinality']
        tag.public = tag_spec['public']
        tag.scope_id = tag_spec['scope_id']
        tag.scope_type = ScopeType.odp
        tag.schema_id = tag_spec['schema_id']
        tag.schema_type = SchemaType.tag
        tag.vocabulary_id = tag_spec.get('vocabulary_id')
        tag.save()

    if orphaned_yml_tags := [tag_id for tag_id in tag_data if tag_id not in tag_ids]:
        logger.warning(f'Orphaned tag definitions in tags.yml {orphaned_yml_tags}')

    if orphaned_db_tags := Session.execute(select(Tag.id).where(Tag.id.not_in(tag_ids))).scalars().all():
        logger.warning(f'Orphaned tag definitions in tag table {orphaned_db_tags}')


def init_vocabularies():
    """Create or update vocabulary definitions.

    If `static_terms` are declared in the .yml, the vocabulary is flagged
    as static, and its terms are maintained here without audit logging.
    """
    with open(datadir / 'vocabularies.yml') as f:
        vocabulary_data = yaml.safe_load(f)

    for vocabulary_id in (vocabulary_ids := [v.value for v in ODPVocabulary]):
        vocabulary_spec = vocabulary_data[vocabulary_id]
        vocabulary = Session.get(Vocabulary, vocabulary_id) or Vocabulary(id=vocabulary_id)
        vocabulary.scope_id = vocabulary_spec['scope_id']
        vocabulary.scope_type = ScopeType.odp
        vocabulary.schema_id = vocabulary_spec['schema_id']
        vocabulary.schema_type = SchemaType.vocabulary
        vocabulary.save()

        if static_terms := vocabulary_spec.get('static_terms'):
            vocabulary.static = True
            term_ids = []
            for term_spec in static_terms:
                term_ids += [term_id := term_spec['id']]
                term = Session.get(VocabularyTerm, (vocabulary_id, term_id)) or VocabularyTerm(
                    vocabulary_id=vocabulary_id,
                    term_id=term_id,
                )
                term.data = term_spec
                term.save()

                Session.execute(
                    delete(VocabularyTerm).
                    where(VocabularyTerm.vocabulary_id == vocabulary_id).
                    where(VocabularyTerm.term_id.not_in(term_ids))
                )
        else:
            vocabulary.static = False

    if orphaned_yml_vocabularies := [vocabulary_id for vocabulary_id in vocabulary_data if vocabulary_id not in vocabulary_ids]:
        logger.warning(f'Orphaned vocabulary definitions in vocabularies.yml {orphaned_yml_vocabularies}')

    if orphaned_db_vocabularies := Session.execute(select(Vocabulary.id).where(Vocabulary.id.not_in(vocabulary_ids))).scalars().all():
        logger.warning(f'Orphaned vocabulary definitions in vocabulary table {orphaned_db_vocabularies}')


def init_catalogs():
    """Create or update catalog definitions."""
    with open(datadir / 'catalogs.yml') as f:
        catalog_data = yaml.safe_load(f)

    for catalog_id in (catalog_ids := [c.value for c in ODPCatalog]):
        catalog_spec = catalog_data[catalog_id]
        catalog = Session.get(Catalog, catalog_id) or Catalog(id=catalog_id)
        catalog.url = os.environ[catalog_spec['url_env']]
        catalog.save()

    if orphaned_yml_catalogs := [catalog_id for catalog_id in catalog_data if catalog_id not in catalog_ids]:
        logger.warning(f'Orphaned catalog definitions in catalogs.yml {orphaned_yml_catalogs}')

    if orphaned_db_catalogs := Session.execute(select(Catalog.id).where(Catalog.id.not_in(catalog_ids))).scalars().all():
        logger.warning(f'Orphaned catalog definitions in catalog table {orphaned_db_catalogs}')


def init_clients():
    """Create or update preconfigured clients."""
    hydra_admin_api = HydraAdminAPI(os.environ['HYDRA_ADMIN_URL'])

    with open(datadir / 'clients.yml') as f:
        client_data = yaml.safe_load(f)

    for client_id, client_spec in client_data.items():
        client = Session.get(Client, client_id) or Client(id=client_id)
        client.scopes = [
            Session.execute(select(Scope).where(Scope.id == scope_id)).scalar_one()
            for scope_id in _expand_scopes(client_spec['scopes'])
        ]
        if collection_keys := client_spec.get('collections'):
            client.collection_specific = True
            client.collections = Session.execute(
                select(Collection).where(Collection.key.in_(collection_keys))
            ).scalars().all()
        else:
            client.collection_specific = False

        client.save()

        opts = dict(
            name=client_spec['name'],
            secret=os.environ[client_spec['secret_env']],
            scope_ids=_expand_scopes(client_spec['scopes']),
            grant_types=client_spec['grant_types'],
        )
        if url_env := client_spec.get('url_env'):
            url = os.environ[url_env]
            opts |= dict(
                response_types=client_spec['response_types'],
                redirect_uris=[url + '/oauth2/logged_in'],
                post_logout_redirect_uris=[url + '/oauth2/logged_out'],
            )
        if (token_lifespan := client_spec.get('token_lifespan')) and \
                GrantType.CLIENT_CREDENTIALS in client_spec['grant_types']:
            opts |= dict(
                client_credentials_grant_access_token_lifespan=token_lifespan,
            )

        hydra_admin_api.create_or_update_client(client_id, **opts)


def _expand_scopes(scope_ids):
    ret = []
    for scope_id in scope_ids:
        if scope_id == 'odp.*':
            ret += [s.value for s in ODPScope]
        else:
            ret += [scope_id]
    return ret
