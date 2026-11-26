import concurrent.futures
import time
import unittest
from unittest.mock import patch
from svcdash import runtimes


class RuntimeCacheTest(unittest.TestCase):
    def test_concurrent_readers_share_a_completed_scan(self):
        data={'agents':[]}
        def scan():
            runtimes._rt_cache.update(t=time.time(),data=data)
            return data
        with patch.dict(runtimes._rt_cache,{'t':0,'data':None}),patch.object(runtimes,'_scan_runtimes',side_effect=scan) as collect:
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                values=list(pool.map(lambda _:runtimes.scan_runtimes(),range(4)))
            self.assertTrue(all(value is data for value in values))
            collect.assert_called_once()
