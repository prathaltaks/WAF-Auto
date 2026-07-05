import socketio
import time

sio = socketio.Client()

def on_connect():
    print('connected')


def on_attack(d):
    print('attack_result', d)


def on_phase_start(d):
    print('phase_start', d)


def on_phase_done(d):
    print('phase_done', d)


def on_test_complete(d):
    print('test_complete', d)

sio.on('connect', on_connect)
sio.on('attack_result', on_attack)
sio.on('phase_start', on_phase_start)
sio.on('phase_done', on_phase_done)
sio.on('test_complete', on_test_complete)

sio.connect('http://127.0.0.1:8080', wait_timeout=5)
print('emitting start_test')
sio.emit('start_test', {'profile_id': 1, 'phases': [4], 'attack_delay': 0.01})
for _ in range(60):
    time.sleep(0.5)

sio.disconnect()
