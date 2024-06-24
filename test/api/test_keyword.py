from random import randint

import pytest
from sqlalchemy import select

from odp.const import ODPScope
from odp.db.models import Keyword, KeywordAudit
from test import TestSession
from test.api import assert_conflict, assert_forbidden, assert_new_timestamp, assert_not_found, assert_unprocessable
from test.factories import FactorySession, KeywordFactory, fake


@pytest.fixture
def keyword_batch(request):
    """Create and commit a batch of Keyword instances, which
    may include sub-keywords, recursively. Return a tuple of
    (top-level keywords, all keywords).
    """
    keywords_top = KeywordFactory.create_batch(randint(3, 5))
    keywords_flat = FactorySession.execute(select(Keyword)).scalars().all()
    return keywords_top, keywords_flat


def keyword_build(**attr):
    """Build and return an uncommitted Keyword instance."""
    return KeywordFactory.stub(
        child_schema=None,
        child_schema_id=None,
        **attr,
    )


def assert_db_state(keywords_flat):
    """Verify that the keyword table contains the given keyword batch."""
    result = TestSession.execute(select(Keyword)).scalars().all()
    result.sort(key=lambda k: k.key)
    keywords_flat.sort(key=lambda k: k.key)
    assert len(result) == len(keywords_flat)
    for n, row in enumerate(result):
        kw = keywords_flat[n]
        assert row.key == kw.key
        assert row.data == kw.data
        assert row.status == kw.status
        assert row.parent_key == kw.parent_key
        assert row.child_schema_id == kw.child_schema_id
        assert row.child_schema_type == ('keyword' if kw.child_schema_id else None)


def assert_audit_log(grant_type, *entries):
    result = TestSession.execute(select(KeywordAudit)).scalars().all()
    assert len(result) == len(entries)
    for n, row in enumerate(result):
        assert row.client_id == 'odp.test.client'
        assert row.user_id == ('odp.test.user' if grant_type == 'authorization_code' else None)
        assert row.command == entries[n]['command']
        assert_new_timestamp(row.timestamp)
        keyword = entries[n]['keyword']
        assert row._key == keyword.key
        assert row._data == keyword.data
        assert row._status == keyword.status
        assert row._child_schema_id == keyword.child_schema_id


def assert_no_audit_log():
    assert TestSession.execute(select(KeywordAudit)).first() is None


def assert_json_result(response, json, keyword, recurse=False):
    """Verify that the API result matches the given keyword object."""
    assert response.status_code == 200
    assert json['key'] == keyword.key
    assert json['data'] == keyword.data
    assert json['status'] == keyword.status

    schema = None
    parent = FactorySession.get(Keyword, keyword.parent_key)
    while parent is not None:
        if schema := parent.child_schema:
            break
        parent = parent.parent

    assert json['schema_id'] == (schema.id if schema else None)

    if recurse:
        assert (child_keywords := json['child_keywords']) is not None
        assert len(child_keywords) == len(keyword.children)
        for i, child_keyword in enumerate(child_keywords):
            assert_json_result(response, child_keyword, keyword.children[i], True)
    else:
        assert 'child_keywords' not in json


def assert_json_results(response, json, keywords_top, recurse=False):
    """Verify that the API result list matches the given keyword batch."""
    items = json['items']
    assert json['total'] == len(items) == len(keywords_top)
    items.sort(key=lambda i: i['key'])
    keywords_top.sort(key=lambda k: k.key)
    for n, keyword in enumerate(keywords_top):
        assert_json_result(response, items[n], keyword, recurse)


@pytest.mark.require_scope(ODPScope.KEYWORD_READ)
def test_list_vocabularies(
        api,
        scopes,
        keyword_batch,
):
    keywords_top, keywords_flat = keyword_batch
    authorized = ODPScope.KEYWORD_READ in scopes

    r = api(scopes).get('/keyword/')

    if authorized:
        assert_json_results(r, r.json(), keywords_top)
    else:
        assert_forbidden(r)

    assert_db_state(keywords_flat)
    assert_no_audit_log()


@pytest.mark.require_scope(ODPScope.KEYWORD_READ)
@pytest.mark.parametrize('recurse', [False, True])
def test_list_keywords(
        api,
        scopes,
        keyword_batch,
        recurse,
):
    keywords_top, keywords_flat = keyword_batch
    authorized = ODPScope.KEYWORD_READ in scopes
    client = api(scopes)

    r = client.get(f'/keyword/{keywords_top[2].key}/?recurse={recurse}')
    if authorized:
        assert_json_results(r, r.json(), keywords_top[2].children, recurse)
    else:
        assert_forbidden(r)

    try:
        r = client.get(f'/keyword/{keywords_top[1].children[1].key}/?recurse={recurse}')
        if authorized:
            assert_json_results(r, r.json(), keywords_top[1].children[1].children, recurse)
        else:
            assert_forbidden(r)
    except IndexError:
        pass

    try:
        r = client.get(f'/keyword/{keywords_top[0].children[0].children[0].key}/?recurse={recurse}')
        if authorized:
            assert_json_results(r, r.json(), keywords_top[0].children[0].children[0].children, recurse)
        else:
            assert_forbidden(r)
    except IndexError:
        pass

    assert_db_state(keywords_flat)
    assert_no_audit_log()


@pytest.mark.parametrize('recurse', [False, True])
def test_list_keywords_not_found(
        api,
        keyword_batch,
        recurse,
):
    keywords_top, keywords_flat = keyword_batch
    scopes = [ODPScope.KEYWORD_READ]
    client = api(scopes)

    r = client.get(f'/keyword/foo/?recurse={recurse}')
    assert_not_found(r, "Parent keyword 'foo' does not exist")

    r = client.get(f'/keyword/{(key := keywords_top[2].key)}/foo/?recurse={recurse}')
    assert_not_found(r, f"Parent keyword '{key}/foo' does not exist")

    try:
        r = client.get(f'/keyword/{(key := keywords_top[1].children[1].key)}/foo/?recurse={recurse}')
        assert_not_found(r, f"Parent keyword '{key}/foo' does not exist")
    except IndexError:
        pass

    assert_db_state(keywords_flat)
    assert_no_audit_log()


@pytest.mark.require_scope(ODPScope.KEYWORD_READ)
@pytest.mark.parametrize('recurse', [False, True])
def test_get_keyword(
        api,
        scopes,
        keyword_batch,
        recurse,
):
    keywords_top, keywords_flat = keyword_batch
    authorized = ODPScope.KEYWORD_READ in scopes
    client = api(scopes)

    r = client.get(f'/keyword/{keywords_top[2].key}?recurse={recurse}')
    if authorized:
        assert_json_result(r, r.json(), keywords_top[2], recurse)
    else:
        assert_forbidden(r)

    try:
        r = client.get(f'/keyword/{keywords_top[1].children[1].key}?recurse={recurse}')
        if authorized:
            assert_json_result(r, r.json(), keywords_top[1].children[1], recurse)
        else:
            assert_forbidden(r)
    except IndexError:
        pass

    try:
        r = client.get(f'/keyword/{keywords_top[0].children[0].children[0].key}?recurse={recurse}')
        if authorized:
            assert_json_result(r, r.json(), keywords_top[0].children[0].children[0], recurse)
        else:
            assert_forbidden(r)
    except IndexError:
        pass

    assert_db_state(keywords_flat)
    assert_no_audit_log()


@pytest.mark.parametrize('recurse', [False, True])
def test_get_keyword_not_found(
        api,
        keyword_batch,
        recurse,
):
    keywords_top, keywords_flat = keyword_batch
    scopes = [ODPScope.KEYWORD_READ]
    client = api(scopes)

    r = client.get(f'/keyword/foo?recurse={recurse}')
    assert_not_found(r, "Keyword 'foo' does not exist")

    r = client.get(f'/keyword/{(key := keywords_top[2].key)}/foo?recurse={recurse}')
    assert_not_found(r, f"Keyword '{key}/foo' does not exist")

    try:
        r = client.get(f'/keyword/{(key := keywords_top[1].children[1].key)}/foo?recurse={recurse}')
        assert_not_found(r, f"Keyword '{key}/foo' does not exist")
    except IndexError:
        pass

    assert_db_state(keywords_flat)
    assert_no_audit_log()


@pytest.mark.require_scope(ODPScope.KEYWORD_SUGGEST)
def test_suggest_keyword(
        api,
        scopes,
        keyword_batch,
):
    keywords_top, keywords_flat = keyword_batch
    authorized = ODPScope.KEYWORD_SUGGEST in scopes
    client = api(scopes)

    keyword_1 = keyword_build(
        parent_key=keywords_top[2].key,
        data={'abbr': fake.word(), 'title': fake.company()},
        status='proposed',
    )
    r = client.post(f'/keyword/{keyword_1.key}', json=dict(
        data=keyword_1.data,
    ))

    if authorized:
        assert_json_result(r, r.json(), keyword_1)
        assert_db_state(keywords_flat + [keyword_1])
        assert_audit_log(
            api.grant_type,
            dict(command='insert', keyword=keyword_1),
        )

        keyword_2 = keyword_build(
            parent_key=keyword_1.key,
            data={'abbr': fake.word(), 'title': fake.company()},
            status='proposed',
        )
        r = client.post(f'/keyword/{keyword_2.key}', json=dict(
            data=keyword_2.data,
        ))

        assert_json_result(r, r.json(), keyword_2)
        assert_db_state(keywords_flat + [keyword_1, keyword_2])
        assert_audit_log(
            api.grant_type,
            dict(command='insert', keyword=keyword_1),
            dict(command='insert', keyword=keyword_2),
        )

    else:
        assert_forbidden(r)
        assert_db_state(keywords_flat)
        assert_no_audit_log()


def test_suggest_keyword_not_found(
        api,
        keyword_batch,
):
    keywords_top, keywords_flat = keyword_batch
    scopes = [ODPScope.KEYWORD_SUGGEST]
    client = api(scopes)

    r = client.post('/keyword/foo/bar', json=dict(
        data={'abbr': fake.word(), 'title': fake.company()},
    ))
    assert_not_found(r, "Parent keyword 'foo' does not exist")

    r = client.post(f'/keyword/{(key := keywords_top[2].key)}/foo/bar', json=dict(
        data={'abbr': fake.word(), 'title': fake.company()},
    ))
    assert_not_found(r, f"Parent keyword '{key}/foo' does not exist")

    assert_db_state(keywords_flat)
    assert_no_audit_log()


def test_suggest_keyword_no_parent(
        api,
        keyword_batch,
):
    keywords_top, keywords_flat = keyword_batch
    scopes = [ODPScope.KEYWORD_SUGGEST]
    r = api(scopes).post('/keyword/foo', json=dict(
        data={'abbr': fake.word(), 'title': fake.company()},
    ))
    assert_unprocessable(r, "key must be suffixed to a parent key")
    assert_db_state(keywords_flat)
    assert_no_audit_log()


def test_suggest_keyword_conflict(
        api,
        keyword_batch,
):
    keywords_top, keywords_flat = keyword_batch
    scopes = [ODPScope.KEYWORD_SUGGEST]
    client = api(scopes)

    for n in (1, 2, 3):
        for kw in keywords_flat:
            if kw.key.count('/') == n:
                r = client.post(f'/keyword/{kw.key}', json=dict(
                    data={'abbr': fake.word(), 'title': fake.company()},
                ))
                assert_conflict(r, f"Keyword '{kw.key}' already exists")
                break

    assert_db_state(keywords_flat)
    assert_no_audit_log()


def test_suggest_keyword_invalid_data(
        api,
        keyword_batch,
):
    keywords_top, keywords_flat = keyword_batch
    scopes = [ODPScope.KEYWORD_SUGGEST]
    r = api(scopes).post(f'/keyword/{keywords_top[2].key}/foo', json=dict(
        data={'title': fake.company()},  # missing required property 'abbr'
    ))
    assert_unprocessable(r, valid=False)
    assert_db_state(keywords_flat)
    assert_no_audit_log()
