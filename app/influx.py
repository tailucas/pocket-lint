from . import APP_NAME

from pylib import (
    app_config,
    creds,
    device_name_base,
    log
)

from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import WriteApi, ASYNCHRONOUS


class InfluxDB(object):
    def __init__(self) -> None:
        self._influxdb_bucket = app_config.get('influxdb', 'bucket')
        log.info(f'Starting InfluxDB client to {creds.influxdb_url} using bucket {creds.influxdb_org}::{self._influxdb_bucket}...')
        self._influxdb = InfluxDBClient(
            url=creds.influxdb_url,
            token=creds.influxdb_token,
            org=creds.influxdb_org)
        self._influxdb_rw: WriteApi = self._influxdb.write_api(write_options=ASYNCHRONOUS)


    def write(self, point_name: str, field_name: str, field_value):
        try:
            log.debug(f'Writing InfluxDB point {point_name=}, application={APP_NAME}, device={device_name_base}: {field_name}={field_value!s}')
            self._influxdb_rw.write(
                bucket=self._influxdb_bucket,
                record=Point(point_name).tag("application", APP_NAME).tag("device", device_name_base).field(field_name, field_value))
        except Exception:
            log.warning(f'Unable to post to InfluxDB.', exc_info=True)

influxdb = InfluxDB()
