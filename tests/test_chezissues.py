import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from svcdash import chezissues as ci


class ChezIssuesTest(unittest.TestCase):
    def test_public_allowlist_and_hidden_labels(self):
        items=[{'number':1,'title':'Test','body':'Summary','state':'CLOSED','comments':[{'body':'PRIVATE COMMENT'}],'labels':[]},
               {'title':'Hidden','labels':['No-Publish']}, {'title':'Hidden','labels':['private']}]
        public=ci.public_items(items)
        self.assertEqual(public,[{'title':'Test','excerpt':'Summary','state':'CLOSED'}])
        self.assertNotIn('PRIVATE COMMENT',json.dumps(public))

    def test_failure_keeps_last_success(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(ci,'PATH',Path(tmp)/'issues.json'):
            ci.PATH.write_text(json.dumps({'ok':True,'updated_at':1,'items':[{'number':7,'comments':[{'body':'kept'}]}]}))
            with patch.object(ci.subprocess,'check_output',side_effect=TimeoutError):
                result=ci.collect(True)
            self.assertEqual(result['items'][0]['comments'][0]['body'],'kept')
            self.assertEqual(result['updated_at'],1)
            self.assertTrue(ci.read_snapshot()['stale'])
            self.assertEqual(ci.PATH.stat().st_mode & 0o777,0o600)

    def test_all_issue_pages_and_long_comment_threads(self):
        issue={'number':1,'labels':{'nodes':[{'name':'todo'}]},'assignees':{'nodes':[]},'comments':{'pageInfo':{'hasNextPage':True},'nodes':[]}}
        page1={'data':{'repository':{'issues':{'nodes':[issue],'pageInfo':{'hasNextPage':True,'endCursor':'next'}}}}}
        page2={'data':{'repository':{'issues':{'nodes':[],'pageInfo':{'hasNextPage':False}}}}}
        comments=[[{'body':'first','html_url':'https://github.com/a/b/issues/1#comment-1','created_at':'date','updated_at':'date','user':{'login':'a'}}],[{'body':'last','html_url':'https://github.com/a/b/issues/1#comment-2','created_at':'date','updated_at':'date','user':None}]]
        with tempfile.TemporaryDirectory() as tmp,patch.object(ci,'PATH',Path(tmp)/'issues.json'),patch.object(ci.subprocess,'check_output',side_effect=[json.dumps(page1),json.dumps(comments),json.dumps(page2)]) as gh:
            data=ci.collect(True)
        self.assertTrue(data['ok'])
        self.assertEqual(len(data['items'][0]['comments']),2)
        self.assertEqual(data['items'][0]['comments'][-1]['body'],'last')
        self.assertIn('cursor=next',gh.call_args_list[-1].args[0])

if __name__=='__main__': unittest.main()
