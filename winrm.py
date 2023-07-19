import winrm

s = winrm.Session('server', auth=('username', 'password'))
r = s.run_cmd('ipconfig', ['/all'])

print r.status_code
print r.std_out