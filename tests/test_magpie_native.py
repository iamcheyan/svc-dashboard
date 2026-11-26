import io
import json
import unittest
from unittest.mock import patch
from svcdash import magpie_native as native


class Response(io.BytesIO):
    headers={'Content-Type':'application/json'}


class NativeReadOnlyTest(unittest.TestCase):
    def test_writes_never_reach_magpie(self):
        with patch.object(native.urllib.request,'urlopen') as upstream:
            for path in ['groups/save','provider/route','usage/clear','settings/lan','tune/apply','../settings','gateway/unrest','archive/export','sessions/export','usage/requests/export']:
                self.assertEqual(native.read(path)[0],403)
            upstream.assert_not_called()

    def test_live_trace_is_unmodified_and_long_poll_query_survives(self):
        sample={'seq':3,'mine':True,'routes':[{'tokens':100,'prompt':{'tokens':100},'sessionTitle':'private live title'}]}
        with patch.object(native.magpie,'_discover_magpie_key',return_value='test'),patch.object(native.urllib.request,'urlopen',return_value=Response(json.dumps(sample).encode())) as upstream:
            code,_,raw=native.read('gateway/trace','after=2&wait=1')
        self.assertEqual(code,200)
        self.assertEqual(json.loads(raw),sample)
        self.assertTrue(upstream.call_args.args[0].full_url.endswith('/api/gateway/trace?after=2&wait=1'))
        self.assertEqual(upstream.call_args.args[0].get_method(),'GET')

    def test_post_shaped_title_read_drops_extra_fields(self):
        with patch.object(native.magpie,'_discover_magpie_key',return_value='test'),patch.object(native.urllib.request,'urlopen',return_value=Response(b'{}')) as upstream:
            native.read('gateway/session-titles','payload='+native.urllib.parse.quote(json.dumps({'ids':[1],'admin':'ignored'})))
        request=upstream.call_args.args[0]
        self.assertEqual(request.get_method(),'POST')
        self.assertEqual(json.loads(request.data),{'ids':[1]})

    def test_source_redaction_preserves_expressions_but_masks_credentials(self):
        from svcdash.privacy import sanitize_text
        source = 'const token = ****** || 0) + 1; const secret = ******; firstToken: ******'
        self.assertEqual(sanitize_text(source,source_code=True),source)
        credential='******'
        masked=sanitize_text('const token = "'+credential+'";',source_code=True)
        self.assertNotIn(credential,masked)
        self.assertIn('"******"',masked)

    def test_asset_redaction_covers_macos_windows_and_expression_properties(self):
        from svcdash.privacy import sanitize_text
        source = 'const x = { secret: out.secret, password: token.value.trim() };'
        self.assertEqual(sanitize_text(source,source_code=True),'const x = { "secret": out.secret, "password": token.value.trim() };')
        for path in ['/Users/private-account/project', r'C:\Users\private-account\project', r'C:\\Users\\private-account\\project']:
            self.assertNotIn('private-account',sanitize_text(path,source_code=True))

    def test_public_snapshot_omits_conversations_and_identifiers(self):
        def data(path):
            if path.startswith('gateway/trace'):
                return {'mine':True,'seq':7,'routes':[{'id':7,'tokens':500,'sessionTitle':'private-title','folder':'private-folder','session':'private-session','prompt':{'tokens':500,'parts':[{'kind':'files','items':[{'name':'private-file','tokens':20}]}]},'order':[{'id':'private-account','who':'private-user','used':25}]}]}
            if path=='sessions':return {'sessions':[{'agent':'codex','id':'private-session','title':'private-title','cwd':'/private/project'}]}
            if path.startswith('sessions/stats'):return {'keys':['codex:private-session']}
            return {}
        with patch.object(native,'_json',side_effect=data):out=native.public_snapshot()
        text=json.dumps(out)
        for secret in ['private-title','private-folder','private-session','private-file','private-account','private-user']:self.assertNotIn(secret,text)
        self.assertEqual(out['ranges']['sessions/stats?days=7']['keys'][0],'codex:'+out['sessions']['sessions'][0]['id'])
        self.assertEqual(out['trace']['routes'][0]['tokens'],500)
        self.assertEqual(out['trace']['routes'][0]['order'][0]['used'],25)

if __name__=='__main__':unittest.main()
