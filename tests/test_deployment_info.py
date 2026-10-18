import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from deployment_info import check_deployment, file_hashes, write_manifest


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.root=Path(self.tmp.name)
        self.source=self.root/'source'
        self.source.mkdir()
        for name in ('SKILL.md','README.md','LICENSE'):
            (self.source/name).write_text('fixture',encoding='utf-8')
        self.dest=self.root/'deployed'
        shutil.copytree(self.source,self.dest)

    def tearDown(self):
        self.tmp.cleanup()

    def test_no_git_records_unknown_source_and_detects_later_edit(self):
        report=write_manifest(self.source,self.dest)
        self.assertEqual(report['status'],'matches_deployment')
        self.assertIsNone(report['source_commit'])
        self.assertIsNone(report['source_dirty'])
        (self.dest/'SKILL.md').write_text('changed',encoding='utf-8')
        self.assertEqual(check_deployment(self.dest)['changed_files'],['SKILL.md'])

    def test_source_provenance_survives_copy_without_git(self):
        with patch('deployment_info.source_revision',return_value=('a'*40,True)):
            write_manifest(self.source,self.dest)
        report=check_deployment(self.dest)
        self.assertEqual(report['source_commit'],'a'*40)
        self.assertTrue(report['source_dirty'])
        self.assertFalse((self.dest/'.git').exists())

    def test_mismatch_does_not_stamp_success(self):
        (self.dest/'README.md').unlink()
        with self.assertRaises(ValueError):
            write_manifest(self.source,self.dest)
        self.assertFalse((self.dest/'deployment.json').exists())

    def test_no_manifest_is_unknown_and_run_data_is_excluded(self):
        self.assertEqual(check_deployment(self.dest)['status'],'provenance_unavailable')
        (self.dest/'out').mkdir()
        (self.dest/'out'/'private.md').write_text('private fixture',encoding='utf-8')
        (self.dest/'run.json').write_text('{}',encoding='utf-8')
        self.assertEqual(file_hashes(self.source),file_hashes(self.dest))
        write_manifest(self.source,self.dest)
        manifest=json.loads((self.dest/'deployment.json').read_text(encoding='utf-8'))
        self.assertNotIn('private',json.dumps(manifest))


if __name__=='__main__':
    unittest.main()
