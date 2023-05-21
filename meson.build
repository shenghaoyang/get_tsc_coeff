project('get_tsc_coeff', 'c',
  version : '0.1',
  default_options : ['warning_level=3', 'c_std=gnu17', 'optimization=g'])

libbpf = dependency('libbpf')
exe = executable('get_tsc_coeff', 'get_tsc_coeff.c',
  install : true, dependencies: [libbpf])

test('basic', exe)
