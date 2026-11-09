import json

import pytest
import zipfile
from threading import Event

from redforge.core import initialize
from redforge.fileguard import create_baseline, verify_baseline
from redforge.bundle import export_bundle, verify_bundle


def test_file_baseline_reports_changes_without_following_symlinks(tmp_path):
    engagement = tmp_path / 'engagement'
    directory = tmp_path / 'files'
    directory.mkdir()
    (directory / 'alpha.txt').write_text('one')
    (directory / 'gone.txt').write_text('old')
    (directory / 'link.txt').symlink_to(directory / 'alpha.txt')
    initialize(engagement, 'Test')
    manifest = create_baseline(engagement, 'sample', directory)
    assert list(json.loads(manifest.read_text())['files']) == ['alpha.txt', 'gone.txt']
    assert verify_baseline(engagement, 'sample')['ok']
    bundle = export_bundle(engagement, tmp_path / 'bundle.zip')
    with zipfile.ZipFile(bundle) as archive:
        assert 'file-baselines/sample.json' in archive.namelist()
    assert verify_bundle(bundle)['ok']
    (directory / 'alpha.txt').write_text('two')
    (directory / 'gone.txt').unlink()
    (directory / 'new.txt').write_text('new')
    result = verify_baseline(engagement, 'sample')
    assert result['changed'] == ['alpha.txt']
    assert result['missing'] == ['gone.txt']
    assert result['untracked'] == ['new.txt']


def test_file_baseline_name_cannot_traverse(tmp_path):
    initialize(tmp_path, 'Test')
    with pytest.raises(ValueError, match='name'):
        create_baseline(tmp_path, '../outside', tmp_path)


def test_file_baseline_can_be_cancelled(tmp_path):
    engagement = tmp_path / 'engagement'
    directory = tmp_path / 'files'
    directory.mkdir()
    (directory / 'file.txt').write_text('data')
    initialize(engagement, 'Test')
    stopped = Event()
    stopped.set()
    with pytest.raises(InterruptedError, match='cancelled'):
        create_baseline(engagement, 'sample', directory, cancel=stopped)
    assert not (engagement / 'file-baselines' / 'sample.json').exists()
