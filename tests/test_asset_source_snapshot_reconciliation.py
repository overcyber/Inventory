from models import Asset, AssetObservation, AssetSourceState
from services.asset_core import ingest_observation, reconcile_source_snapshot


def test_reconcile_full_source_snapshot_deactivates_wazuh_only_asset(app):
    with app.app_context():
        asset = ingest_observation(
            'wazuh', '001',
            {'agent_info': {'id': '001'}},
            {
                'hostname': 'HOST-001',
                'wazuh_agent_id': '001',
                'agent_status': 'active',
                'agent_status_raw': 'active',
                'device_status': 'Ativo',
                'network_status': 'reachable',
                'source': ['wazuh'],
                'confidence': 0.99,
            },
        )
        asset_id = asset.id
        assert AssetSourceState.query.filter_by(
            asset_id=asset_id, source='wazuh').count() == 1
        assert AssetObservation.query.filter_by(
            asset_id=asset_id, source='wazuh').count() == 1

        result = reconcile_source_snapshot('wazuh', [])

        refreshed = Asset.query.get(asset_id)
        assert result['stale_source_states_removed'] == 1
        assert result['assets_deactivated'] == 1
        assert refreshed.active is False
        assert AssetSourceState.query.filter_by(
            asset_id=asset_id, source='wazuh').count() == 0
        # History is intentionally preserved.
        assert AssetObservation.query.filter_by(
            asset_id=asset_id, source='wazuh').count() == 1
