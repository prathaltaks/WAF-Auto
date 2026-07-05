import socketio
import time

sio = socketio.Client()

sio.on('connected', lambda d: print('connected', d))
sio.on('phase_start', lambda d: print('phase_start', d))
sio.on('phase_done', lambda d: print('phase_done', d))
sio.on('attack_result', lambda d: print('attack_result', d))
sio.on('test_complete', lambda d: print('test_complete', d))
sio.on('test_error', lambda d: print('test_error', d))

sio.connect('http://127.0.0.1:8080', wait_timeout=5)
sio.emit('start_test', {'profile_id': 1, 'phases': [1,2,3,4,5,6,7], 'attack_delay': 0.1})
for _ in range(100):
    time.sleep(0.5)
    if False:
        break
sio.disconnect()
