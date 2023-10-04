# -*- coding: utf-8 -*-
"""

"""

import pyopencl as cl
import numpy as np
import binascii
import os

class sha256_opencl:

    def __init__(self,platform):
        
        platforms = cl.get_platforms()
        if (platform > len(platforms)):
            assert("Selected platform %d doesn't exist" % platform)

        hash=b'\x00'*32
        hash_len=32
        
        # Get platforms
        devices = platforms[platform].get_devices()
        self.workgroupsize=60000
        
        #Create context for GPU/CPU
        print("Using Platform %d:" % platform)
        self.ctx = cl.Context(devices)
        for device in devices:
            print('--------------------------------------------------------------------------')
            print(' Device - Name: '+ device.name)
            print(' Device - Type: '+ cl.device_type.to_string(device.type))
            print(' Device - Compute Units: {0}'.format(device.max_compute_units))
            print(' Device - Max Work Group Size: {0:.0f}'.format(device.max_work_group_size))
            if (device.max_work_group_size<self.workgroupsize):
                self.workgroupsize=device.max_work_group_size

        print ("\nUsing work group size of %d\n" % self.workgroupsize)

        # Create queue for each kernel execution
        self.queue = cl.CommandQueue(self.ctx)

        # Kernel function
        src=""
        os.environ['PYOPENCL_COMPILER_OUTPUT'] = '0'

    def compile(self,type):
        fname = ""
        self.type=type
        
        if (self.type == 'sha256'):
            fname = ("sha256.cl")
        else:
            print('Type: ' + self.type + ' not supported!')
            exit(0)

        with open(fname, "r") as rf:
            src = rf.read()

        # Kernel function instantiation
        self.prg = cl.Program(self.ctx, src).build()

    def run(self,passwordlist):
        if type(passwordlist)!=list:
            assert("Parameter passwordlist has to be an array")
        if len(passwordlist)==0:
            assert ("Password list is empty")
        if type(passwordlist[0])!=bytes:
            assert ("Password in passwordlist has to be type of utf-8 string or bytes")
        pos=0
        mf = cl.mem_flags
        totalpws=len(passwordlist)
        results = []
        while (totalpws>0):
            pwarray = np.empty(0, dtype=np.uint32)
            if (totalpws<self.workgroupsize):
                pwcount=totalpws
            else:
                pwcount=self.workgroupsize

            pwdim = (pwcount,)

            for pw in passwordlist[pos:pos+pwcount]:
                pwlen = int(len(pw))
                if (pwlen>int(32)): #Only chars up to length 32 supported
                    continue
                modlen=len(pw)%4
                if modlen!=0:
                    pw=pw+(b'\0'*(4-modlen))
                n_pw = np.frombuffer(pw, dtype=np.uint32)
                n_pwlen = np.array([pwlen], dtype=np.uint32)
                password = np.array([0]*9,dtype=np.uint32)
                z=0
                for i in range(0,len(n_pwlen)):
                    password[z]=n_pwlen[i]
                    z+=1
                max=9-len(n_pwlen)
                if max>len(n_pw):
                    max=len(n_pw)
                for i in range(0,max):
                    password[z+i]=n_pw[i]
                pwarray = np.append(pwarray, password)

            result = np.zeros(int(32 / 4) * pwcount, dtype=np.uint32)

            #Allocate memory for variables on the device
            pass_g =  cl.Buffer(self.ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=pwarray)
            result_g = cl.Buffer(self.ctx, mf.WRITE_ONLY, result.nbytes)
            
            #Call Kernel. Automatically takes care of block/grid distribution
            if (self.type=="sha256"):
                hashlen=0x20
                self.prg.func_sha256(self.queue,pwdim,None,pass_g,result_g)
                #SHA256 does support longer lengths, but inputbuffer and hash are limited to 32 chars
            cl.enqueue_copy(self.queue, result, result_g)
            totalpws-=pwcount
            pos+=pwcount
            hexvalue = binascii.hexlify(result)
            for value in range(0, len(hexvalue), 64):
                results.append(hexvalue[value:value + 64].decode()[0:hashlen*2])
        return results
    
    def print_device_info() :
        print('\n' + '=' * 60 + '\nOpenCL Platforms and Devices')
    
        for platform in cl.get_platforms():
            print('=' * 60)
            print('Platform - Name: ' + platform.name)
            print('Platform - Vendor: ' + platform.vendor)
            print('Platform - Version: ' + platform.version)
            print('Platform - Profile: ' + platform.profile)
    
        for device in platform.get_devices():
            print(' ' + '-' * 56)
            print(' Device - Name: ' \
            + device.name)
            print(' Device - Type: ' \
            + cl.device_type.to_string(device.type))
            print(' Device - Max Clock Speed: {0} Mhz'\
            .format(device.max_clock_frequency))
            print(' Device - Compute Units: {0}'\
            .format(device.max_compute_units))
            print(' Device - Local Memory: {0:.0f} KB'\
            .format(device.local_mem_size/1024.0))
            print(' Device - Constant Memory: {0:.0f} KB'\
            .format(device.max_constant_buffer_size/1024.0))
            print(' Device - Global Memory: {0:.0f} GB'\
            .format(device.global_mem_size/1073741824.0))
            print(' Device - Max Buffer/Image Size: {0:.0f} MB'\
            .format(device.max_mem_alloc_size/1048576.0))
            print(' Device - Max Work Group Size: {0:.0f}'\
            .format(device.max_work_group_size))
            print('\n')