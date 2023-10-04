# -*- coding: utf-8 -*-
"""

@author: iceland
"""

import pyopencl as cl
import sha256_class as opencl

# =============================================================================
# def read_pass_file():
#     with open('4_letter_words.txt') as f:
#         pass_list = f.read().rstrip('\n').split('\n')
#     return pass_list
# 
# pass_list = read_pass_file()
# passwordlist = [bytes(line,'utf-8') for line in pass_list]
# =============================================================================

def gpu_sha256(opencl_ctx,passwordlist):
    opencl_ctx.compile('sha256')
    result = opencl_ctx.run(passwordlist)
#    print(result[0])
#    print(result[1])
    return result
        
opencl.sha256_opencl.print_device_info()
# test using given pass phrase
passwordlist = [b'this is my password', b'dont touch my coins', b'0a5ff07fd8883f80cb04f3840d0efe']

platform = 0
opencl_ctx = opencl.sha256_opencl(platform)
results = gpu_sha256(opencl_ctx,passwordlist)
print(results)