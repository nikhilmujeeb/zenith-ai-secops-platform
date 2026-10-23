#!/usr/bin/env python3
"""Generate reproducible clean or adversarial SecOps JSONL fixtures.

Expected correlation labels are returned separately and are never embedded in
the event objects sent to the correlation engine.
"""
import argparse
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

SOURCES = ['cctv', 'anpr', 'face_recognition', 'mobile_phone', 'seatbelt',
           'red_light', 'radar', 'access_control', 'perimeter', 'device_health',
           'operator_report', 'emergency_alarm', 'gps_fleet', 'network_log', 'weather']
ZONES = ['Gate-A', 'Gate-B', 'Depot-1', 'Perimeter-North', 'Command-Center']
EVENT_TYPES = ['speed_violation', 'vehicle_detected', 'device_online',
               'intrusion_alert', 'access_denied', 'mobile_phone_detected',
               'person_detected']


def generate_fixture(count, seed=41, adversarial=True, id_prefix='evt-'):
    """Return event objects and a separate truth-label document."""
    if count < 1:
        raise ValueError('count must be at least 1')
    rng = random.Random(seed)
    base = datetime(2026, 1, 15, 8, tzinfo=timezone.utc)
    events = []
    labels = {'version': 1, 'seed': seed, 'base_event_count': count,
              'expected_groups': [], 'must_not_link_pairs': []}

    for i in range(count):
        dt = base + timedelta(seconds=rng.randrange(0, 86400))
        source = SOURCES[i % len(SOURCES)]
        zone = ZONES[rng.randrange(len(ZONES))]
        event = {
            'event_id': f'{id_prefix}{i:07d}', 'source_type': source,
            'device_id': f'{source}-{rng.randrange(1, 81):02d}',
            'event_type': rng.choice(EVENT_TYPES),
            'occurred_at': dt.isoformat().replace('+00:00', 'Z'),
            'received_at': (dt + timedelta(seconds=rng.randrange(0, 80))).isoformat().replace('+00:00', 'Z'),
            'location': {'latitude': 25.2048 + rng.uniform(-.04, .04),
                         'longitude': 55.2708 + rng.uniform(-.04, .04), 'zone': zone},
            'severity': rng.choices(['critical', 'high', 'medium', 'low'], [2, 14, 34, 50])[0],
            'confidence': round(rng.uniform(.35, .99), 2), 'payload': {}
        }

        if adversarial:
            slot = i % 1000
            cluster = i // 1000
            cluster_time = base + timedelta(minutes=cluster * 30)
            if slot in (0, 1, 2):
                source, event_type = [('cctv', 'vehicle_present'),
                                      ('anpr', 'vehicle_detected'),
                                      ('radar', 'vehicle_absent')][slot]
                dt = cluster_time + timedelta(seconds=slot * 20)
                event.update({
                    'source_type': source, 'device_id': f'{source}-cluster-{cluster:03d}',
                    'event_type': event_type,
                    'occurred_at': dt.isoformat().replace('+00:00', 'Z'),
                    'received_at': (dt + timedelta(seconds=4)).isoformat().replace('+00:00', 'Z'),
                    'location': {'latitude': 25.2048, 'longitude': 55.2708, 'zone': 'Gate-A'},
                    'severity': 'high', 'confidence': .84,
                    'payload': {'vehicle_id': f'VEH-{cluster:04d}'}
                })
            elif slot == 3:
                event.update({'source_type': 'device_health', 'device_id': f'camera-{cluster:03d}',
                              'event_type': 'device_offline', 'severity': 'critical',
                              'confidence': .99, 'payload': {'last_heartbeat_seconds': 240}})
            elif slot == 4:
                # Same place and time as the labelled group, but a distinct entity.
                # The correlation engine must not join it on proximity alone.
                dt = cluster_time + timedelta(seconds=10)
                event.update({'source_type': 'cctv', 'device_id': f'unrelated-{cluster:03d}',
                              'event_type': 'vehicle_present',
                              'occurred_at': dt.isoformat().replace('+00:00', 'Z'),
                              'received_at': (dt + timedelta(seconds=4)).isoformat().replace('+00:00', 'Z'),
                              'location': {'latitude': 25.2048, 'longitude': 55.2708, 'zone': 'Gate-A'},
                              'severity': 'high', 'confidence': .88,
                              'payload': {'vehicle_id': f'OTHER-{cluster:04d}'}})
            elif slot == 5:
                event['occurred_at'] = 'not-a-timestamp'
                event['received_at'] = '2026-01-15T08:00:00Z'
            elif slot == 6:
                event.pop('device_id', None)
                event.pop('event_type', None)
            elif slot == 7:
                event['location'] = {'latitude': 999, 'longitude': 270, 'zone': 'Unknown'}
            elif slot == 8:
                event['confidence'] = 1.4
                event['payload'] = ['unexpected', 'array']
            elif slot == 9:
                dt = cluster_time + timedelta(minutes=8)
                event.update({'source_type': 'operator_report', 'device_id': f'unverified-report-{cluster:03d}',
                              'event_type': 'suspicious_activity_report',
                              'occurred_at': dt.isoformat().replace('+00:00', 'Z'),
                              'received_at': (dt + timedelta(seconds=5)).isoformat().replace('+00:00', 'Z'),
                              'location': {}, 'severity': 'high', 'confidence': .72, 'payload': {}})
            elif slot == 10:
                dt = cluster_time + timedelta(minutes=5)
                event.update({'source_type': 'cctv', 'device_id': f'location-conflict-a-{cluster:03d}',
                              'event_type': 'vehicle_detected',
                              'occurred_at': dt.isoformat().replace('+00:00', 'Z'),
                              'received_at': (dt + timedelta(seconds=4)).isoformat().replace('+00:00', 'Z'),
                              'location': {'latitude': 25.2048, 'longitude': 55.2708, 'zone': 'Gate-A'},
                              'severity': 'high', 'confidence': .86,
                              'payload': {'vehicle_id': f'LOC-{cluster:04d}'}})
            elif slot == 12:
                dt = cluster_time + timedelta(minutes=6)
                event.update({'source_type': 'anpr', 'device_id': f'location-conflict-b-{cluster:03d}',
                              'event_type': 'vehicle_detected',
                              'occurred_at': dt.isoformat().replace('+00:00', 'Z'),
                              'received_at': (dt + timedelta(seconds=4)).isoformat().replace('+00:00', 'Z'),
                              'location': {'latitude': 25.24, 'longitude': 55.31, 'zone': 'Depot-1'},
                              'severity': 'high', 'confidence': .86,
                              'payload': {'vehicle_id': f'LOC-{cluster:04d}'}})
                labels['must_not_link_pairs'].append([f'{id_prefix}{i - 2:07d}', f'{id_prefix}{i:07d}'])
            elif 20 <= slot < 30:
                dt = base + timedelta(minutes=cluster * 30, seconds=(slot - 20) * 20)
                event.update({'source_type': 'access_control', 'device_id': f'spike-reader-{cluster:03d}',
                              'event_type': 'access_denied',
                              'occurred_at': dt.isoformat().replace('+00:00', 'Z'),
                              'received_at': (dt + timedelta(seconds=3)).isoformat().replace('+00:00', 'Z'),
                              'location': {'latitude': 25.2048, 'longitude': 55.2708, 'zone': 'Gate-A'},
                              'severity': 'medium', 'confidence': .9, 'payload': {}})
            elif 30 <= slot < 45:
                offset = slot - 30
                received = base + timedelta(minutes=cluster * 30, seconds=offset * 30)
                occurred = base + timedelta(minutes=cluster * 30, seconds=(14 - offset) * 30)
                event.update({'source_type': 'network_log', 'device_id': f'out-of-order-{cluster:03d}',
                              'event_type': 'authentication_failure',
                              'occurred_at': occurred.isoformat().replace('+00:00', 'Z'),
                              'received_at': received.isoformat().replace('+00:00', 'Z'),
                              'location': {'zone': 'Command-Center'}, 'severity': 'medium',
                              'confidence': .95, 'payload': {'session_group': f'SESSION-{cluster:03d}'}})
            elif slot == 11:
                event['received_at'] = (dt + timedelta(hours=2)).isoformat().replace('+00:00', 'Z')
            elif i % 1400 == 5:
                event['confidence'] = .31

        events.append(event)

        if adversarial and i % 1000 == 0 and i + 4 < count:
            group = [f'{id_prefix}{i + offset:07d}' for offset in (0, 1, 2)]
            unrelated = f'{id_prefix}{i + 4:07d}'
            labels['expected_groups'].append(group)
            labels['must_not_link_pairs'].extend([[eid, unrelated] for eid in group])

        # Re-submit exact source records with the same ID; the API should audit
        # these attempts and keep the first stored event unchanged.
        if adversarial and i % 2000 == 0:
            events.append(dict(event))

    return events, labels


def generate(count, seed=41, adversarial=True):
    """Backwards-compatible event-only helper used by tests and scripts."""
    return generate_fixture(count, seed, adversarial)[0]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--count', type=int, default=100)
    parser.add_argument('--seed', type=int, default=41)
    parser.add_argument('--output', default='data/sample_events.jsonl')
    parser.add_argument('--clean', action='store_true')
    args = parser.parse_args()
    events, _ = generate_fixture(args.count, args.seed, not args.clean)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('w', encoding='utf8') as stream:
        for event in events:
            stream.write(json.dumps(event, ensure_ascii=False, separators=(',', ':')) + '\n')
    print(f'Wrote {len(events)} events to {output}')


if __name__ == '__main__':
    main()

