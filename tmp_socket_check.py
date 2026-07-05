import socketio
import time
import json

received = []

sio = socketio.Client()

sio.on('connected', lambda data: print('EVENT connected', data))
sio.on('phase_start', lambda data: print('EVENT phase_start', data))
sio.on('phase_done', lambda data: print('EVENT phase_done', data))
sio.on('log_line', lambda data: print('EVENT log_line', data))
sio.on('attack_result', lambda data: print('EVENT attack_result', data))
sio.on('test_complete', lambda data: print('EVENT test_complete', data.get('verdict') if isinstance(data, dict) else data))
sio.on('test_error', lambda data: print('EVENT test_error', data))

sio.connect('http://127.0.0.1:8080', wait_timeout=5)
sio.emit('start_test', {'profile_id': 1, 'phases': [1,2,3,4,5,6,7], 'attack_delay': 0.1})
time.sleep(20)
sio.disconnect()
