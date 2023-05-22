project('get_tsc_coeff', 'c',
  version : '0.1',
  default_options : ['warning_level=3', 'c_std=c17', 'optimization=2'])

add_project_arguments('-D_POSIX_C_SOURCE=200809L', language: 'c')

libbpf = dependency('libbpf', version: '>=1.0',
  static: get_option('libbpf_static'))
exe = executable('get_tsc_coeff', 'get_tsc_coeff.c',
  install : true, dependencies: [libbpf])

test('basic', exe)
