import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from svcdash import pullrequests as pr


class PullRequestsTest(unittest.TestCase):
    def test_classification(self):
        for fields, expected in [
            ({'state':'MERGED','ci':'FAILURE'},'merged'),
            ({'state':'CLOSED'},'closed'),
            ({'isDraft':True,'ci':'FAILURE'},'draft'),
            ({'reviewDecision':'CHANGES_REQUESTED'},'action'),
            ({'ci':'FAILURE'},'action'),
            ({'mergeable':'CONFLICTING'},'action'),
            ({'reviewDecision':'APPROVED','mergeable':'MERGEABLE','ci':'SUCCESS'},'ready'),
            ({'reviewDecision':'APPROVED','mergeable':'UNKNOWN'},'review'),
            ({'reviewDecision':'APPROVED','mergeable':'MERGEABLE','ci':'PENDING'},'review'),
        ]:
            with self.subTest(fields=fields): self.assertEqual(pr.classify(fields),expected)

    def test_failure_preserves_snapshot_and_public_excludes_private(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(pr,'PATH',Path(tmp)/'prs.json'):
            pr.PATH.write_text(json.dumps({'ok':True,'updated_at':1,'items':[{'private':True},{'private':False}]}))
            with patch.object(pr.subprocess,'check_output',side_effect=TimeoutError):
                result=pr.collect(True)
            self.assertEqual(len(result['items']),2)
            self.assertEqual(result['updated_at'],1)
            self.assertTrue(result['stale'])
            self.assertEqual(len(pr.read_snapshot(public=True)['items']),1)


if __name__=='__main__': unittest.main()
