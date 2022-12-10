import logging

from sqlalchemy import select

from odp.catalog.datacite import DataCitePublisher
from odp.catalog.mims import MIMSPublisher
from odp.catalog.saeon import SAEONPublisher
from odp.const import ODPCatalog
from odp.db import Session
from odp.db.models import Catalog

logger = logging.getLogger(__name__)

publishers = {
    ODPCatalog.SAEON: SAEONPublisher,
    ODPCatalog.DATACITE: DataCitePublisher,
    ODPCatalog.MIMS: MIMSPublisher,
}


def publish():
    logger.info('PUBLISHING STARTED')
    try:
        for catalog_id in Session.execute(select(Catalog.id)).scalars():
            publisher = publishers[catalog_id]
            publisher(catalog_id).run()

        logger.info('PUBLISHING FINISHED')

    except Exception as e:
        logger.critical(f'PUBLISHING ABORTED: {str(e)}')
