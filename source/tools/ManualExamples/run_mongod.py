import os
'''
cmd = 'sudo rm -rf /mnt/ramdisk/mongodb'
os.system(cmd)

cmd = 'sudo mkdir /mnt/ramdisk/mongodb'
os.system(cmd)

cmd = 'sudo chown jchoi:jchoi /mnt/ramdisk -R'
os.system(cmd)
'''

cmd = '../../../pin -t obj-intel64/mmio_tracer.so -- /home/jchoi/Workplace/eval-nvmsync/mongo/mongod --dbpath /mnt/ramdisk/mongodb --storageEngine mmapv1 --nojournal'
os.system(cmd)
