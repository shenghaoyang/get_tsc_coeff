`get_tsc_coeff`
---------------

Nasty tool that reads coefficients used to convert TSC tick deltas into
nanosecond deltas, from the `vvar` data page mapped by the kernel into a
process.

(why would you _ever_ need this?)

# Build

The project uses the `meson` build system.

Make sure `libbpf` and its dependencies are available, and then build like any
other `meson` C project.

`libbpf` is only used to process kernel `BTF`, in a rudimentary
"kernel compatability check" to ensure the tool won't run on kernels that are
definitely incompatible.


    meson setup builddir
    ninja -C builddir

To attempt linking `libbpf` statically, setup the build director with:

    meson setup -Dlibbpf_static=true builddir

Watch out for warnings about static versions of `libbpf`'s own dependencies not
being found.

# Run

This program relies on a bunch of private `vvar` details. It may return bogus
values or crash. You have been warned.

    # obtain the coefficients used to map TSC ticks to CLOCK_MONOTONIC
    # nanoseconds
    builddir/get_tsc_coeff
    reading CLOCK_MONOTONIC coefficients
    ns = (tsc * 4909275) >> 24

    # obtain the coefficients used to map TSC ticks to CLOCK_MONOTONIC_RAW
    builddir/get_tsc_coeff raw
    reading CLOCK_MONOTONIC_RAW coefficients
    ns = (tsc * 4909064) >> 24
