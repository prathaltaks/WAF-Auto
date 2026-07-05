import socketio
import time

sio = socketio.Client()

@sio.event
def connect():
    print('connected')

@sio.on('connect')
def on_connect():
    print('connected event')

@sio.on('log_line')
def on_log(d):
    print('log_line', d)

@sio.on('phase_start')
def on_phase_start(d):
    print('phase_start', d)

@sio.on('phase_done')
def on_phase_done(d):
    print('phase_done', d)

@sio.on('attack_result')
def on_attack(d):
    print('attack_result', d)

@sio.on('test_complete')
def on_complete(d):
    print('test_complete', 'present' if d else 'none')

@sio.on('test_error')
def on_error(d):
    print('test_error', d)

sio.connect('http://127.0.0.1:8080', transports=['polling'], wait_timeout=10)
print('connected:', sio.connected)
sio.emit('start_test', {'profile_id': 1, 'phases': [4], 'attack_delay': 0.01})
for i in range(120):
    time.sleep(0.5)
    if not sio.connected:
        break
sio.disconnect()
