import socketio
import time

received = []

sio = socketio.Client()

def record(event_name):
    def handler(data):
        received.append((event_name, data))
        print(event_name, data)
    return handler

sio.on('phase_start', record('phase_start'))
sio.on('phase_done', record('phase_done'))
sio.on('log_line', record('log_line'))
sio.on('attack_result', record('attack_result'))
sio.on('report_ready', record('report_ready'))
sio.on('test_complete', record('test_complete'))
sio.on('test_error', record('test_error'))

sio.connect('http://127.0.0.1:8080', wait_timeout=5)
sio.emit('start_test', {'profile_id': 1, 'phases': [1,2,3,4,5,6,7], 'attack_delay': 0.1})
for _ in range(80):
    if any(event == 'test_complete' for event, _ in received):
        break
    time.sleep(0.5)
sio.disconnect()
print('FINAL_EVENTS', [e for e, _ in received if e in {'phase_start','phase_done','report_ready','test_complete'}])
