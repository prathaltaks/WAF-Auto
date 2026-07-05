import socketio
import time

sio = socketio.Client()

@sio.event
def connect():
    print('connected')

@sio.on('attack_result')
def on_attack(d):
    print('attack_result', d)

@sio.on('phase_start')
def on_phase_start(d):
    print('phase_start', d)

@sio.on('phase_done')
def on_phase_done(d):
    print('phase_done', d)

@sio.on('test_complete')
def on_complete(d):
    print('test_complete', 'report keys:', list(d.keys()) if d else None)

sio.connect('http://127.0.0.1:8080', wait_timeout=5)
sio.emit('start_test', {'profile_id': 1, 'phases': [4], 'attack_delay': 0.01})
for _ in range(60):
    time.sleep(0.5)
sio.disconnect()
