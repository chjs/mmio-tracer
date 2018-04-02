from operator import eq

filepath = 'logs/load_a.log'

write_with_memcpy = {}
write_with_memcpy_file = {}
write_without_memcpy = {}
write_without_memcpy_file = {}
memop = {}

f = open(filepath, 'r')

line = f.readline()
while (line != ''):
    line = line.replace('\n', '')
    log = line.replace(' ', '').split(',')

    if log[1] == 'thread-begin':
        tid = log[0]
        memop[tid] = 'no-file'
        write_with_memcpy[tid] = 0
        write_without_memcpy[tid] = 0

    elif log[1] == 'memcpy-call':
        tid = log[0]
        filename = log[5]
        memop[tid] = filename

    elif log[1] == 'memcpy-return':
        tid = log[0]
        memop[tid] = 'no-file'

    elif log[1] == 'WRITE':
        tid = log[0]
        ip = log[2]
        addr = log[3]
        pgoff = log[4]
        filename = log[5]
        if memop[tid] == filename:
            write_with_memcpy[tid] = write_with_memcpy[tid] + 1
            if filename in write_with_memcpy_file:
                write_with_memcpy_file[filename] = write_with_memcpy_file[filename] + 1
            else:
                write_with_memcpy_file[filename] = 1
        else:
            write_without_memcpy[tid] = write_without_memcpy[tid] + 1

            if filename in write_without_memcpy_file:
                write_without_memcpy_file[filename] = write_without_memcpy_file[filename] + 1
            else:
                write_without_memcpy_file[filename] = 1
    line = f.readline()

sum = 0
for k in write_with_memcpy.keys():
    sum += write_with_memcpy[k]
print 'WRITE with memcpy = %d' % sum
print write_with_memcpy
print write_with_memcpy_file
print ''

sum = 0
for k in write_without_memcpy.keys():
    sum += write_without_memcpy[k]
print 'WRITE without memcpy = %d' % sum
print write_without_memcpy
print write_without_memcpy_file
f.close()
