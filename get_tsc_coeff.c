/**
 * Reads the TSC conversion factors from the kernel, used to convert
 * TSC ticks into nanoseconds with respect to the frequency \c CLOCK_MONOTONIC
 * or \c CLOCK_MONOTONIC_RAW is running at.
 *
 * Works on Kernel 6.3.3, x86_64, without time namespacing.
 *
 * Absolutely no guarantees that the values provided are accurate on other
 * kernel versions - it depends heavily on private implementation details.
 */

#include <bpf/btf.h>
#include <bpf/libbpf_legacy.h>
#include <errno.h>
#include <inttypes.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef __x86_64__
#error only works on x86_64
#endif

#define barrier() __asm__ __volatile__("" : : : "memory")
#define VDSO_VVAR_OFFSET (UINT64_C(128))

/**
 * First few fields of the \c vdso_data structure.
 */
struct vdso_data_hdr {
  uint32_t seq;
  int32_t clock_mode;
  uint64_t _pad[2];
  uint32_t mult;
  uint32_t shift;
  // Remaining fields omitted.
};

/**
 * Information about the running kernel, gathered via BTF.
 */
struct kernel_data {
  size_t vdso_data_size_bytes;
  const struct btf_member *seq_info;
  const struct btf_member *clock_mode_info;
  const struct btf_member *mult_info;
  const struct btf_member *shift_info;

  const struct btf_enum *clock_mode_tsc;
};

/**
 * Obtain the start address of the \c vvar data page mapped into the process'
 * address space by the kernel.
 *
 * \retval NULL if the start address could not be determined.
 */
void *get_vvar_start() {
  void *out = NULL;

  size_t linebuf_sz = 4096;
  char *linebuf = malloc(linebuf_sz);
  if (!linebuf)
    goto alloc_fail;

  FILE *const smaps = fopen("/proc/self/smaps", "r");
  if (!smaps)
    goto fopen_fail;

  for (ssize_t ret = 0; (ret = getline(&linebuf, &linebuf_sz, smaps)) != -1;) {
    if (!strstr(linebuf, "[vvar]\n"))
      continue;

    errno = 0;
    char *endptr;
    uintmax_t vvar_start = strtoumax(linebuf, &endptr, 16);
    if ((errno != 0) || (endptr == linebuf))
      break;

    out = (void *)((uintptr_t)vvar_start);
    break;
  }

  fclose(smaps);
fopen_fail:
  free(linebuf);
alloc_fail:
  return out;
}

/**
 * Read the header of the first \c vdso_data structure located in the \c [vvar]
 * data page.
 *
 * \param out where to write the header to.
 * \param vvar_start start address of the \c [vvar] data page.
 * \param kdata information about the running kernel.
 * \param raw whether to read the structure for the \c *_RAW clocks.
 */
void read_vdso_data(struct vdso_data_hdr *out, void *vvar_start,
                    const struct kernel_data *kdata, bool raw) {
  const volatile struct vdso_data_hdr *mapped =
      (void *)((uintptr_t)vvar_start + (uintptr_t)VDSO_VVAR_OFFSET +
               (uintptr_t)(raw ? kdata->vdso_data_size_bytes : 0));

  uint32_t seq, seq2;
  do {
    seq = mapped->seq;
    // Do we even need this
    // Does volatile even work well on x86_64?
    barrier();

    out->seq = seq;
    out->clock_mode = mapped->clock_mode;
    out->mult = mapped->mult;
    out->shift = mapped->shift;
    seq2 = mapped->seq;
  } while (seq != seq2);
}

/**
 * Obtain the \c mult and \c shift coefficients from the vDSO data page.
 *
 * \param[out] mult where to write the \c mult coefficient to.
 * \param[out] shift where to write the \c shift coefficient to.
 * \param kdata information about the running kernel.
 * \param read data read from the \c vvar page.
 *
 * \retval \c false if TSC is not used for timekeeping or time namespaces are
 *  in use.
 * \retval \c true if coefficients were read successfully.
 */
bool get_tsc_mult_shift(uint32_t *mult, uint32_t *shift,
                        const struct kernel_data *kdata,
                        const struct vdso_data_hdr *read) {
  if (read->clock_mode != kdata->clock_mode_tsc->val)
    return false;

  *mult = read->mult;
  *shift = read->shift;

  return true;
}

static const struct btf_member *lookup_member(const struct btf *btf,
                                              const struct btf_type *type,
                                              const char *name) {
  size_t members = btf_vlen(type);
  if (!members)
    return NULL;

  const struct btf_member *m = btf_members(type);
  for (size_t i = 0; i < members; ++i) {
    const char *mname = btf__str_by_offset(btf, m[i].name_off);
    if (!mname)
      continue;

    if (strcmp(name, mname))
      continue;

    return m + i;
  }

  return NULL;
}

static const struct btf_enum *lookup_enum_member(const struct btf *btf,
                                                 const struct btf_type *type,
                                                 const char *name) {
  size_t members = btf_vlen(type);
  if (!members)
    return NULL;

  const struct btf_enum *m = btf_enum(type);
  for (size_t i = 0; i < members; ++i) {
    const char *mname = btf__str_by_offset(btf, m[i].name_off);
    if (!mname)
      continue;

    if (strcmp(name, mname))
      continue;

    return m + i;
  }

  return NULL;
}

bool gather_kernel_data(struct kernel_data *out, const struct btf *vmlinux) {
  errno = 0;
  int btf_vdso_data_id =
      btf__find_by_name_kind(vmlinux, "vdso_data", BTF_KIND_STRUCT);
  if (errno)
    return false;

  int resolved = btf__resolve_type(vmlinux, btf_vdso_data_id);
  if (resolved < 0)
    return false;

  const struct btf_type *vdso_data = btf__type_by_id(vmlinux, resolved);
  if (!vdso_data)
    return false;

  out->vdso_data_size_bytes = vdso_data->size;

  static const char *member_names[] = {"seq", "clock_mode", "mult", "shift"};
  const struct btf_member **members[] = {&out->seq_info, &out->clock_mode_info,
                                         &out->mult_info, &out->shift_info};
  for (size_t i = 0; i < (sizeof(member_names) / sizeof(member_names[0]));
       ++i) {
    const struct btf_member *memb =
        lookup_member(vmlinux, vdso_data, member_names[i]);
    if (!memb)
      return false;
    *members[i] = memb;
  }

  errno = 0;
  int btf_vdso_clock_mode_id =
      btf__find_by_name_kind(vmlinux, "vdso_clock_mode", BTF_KIND_ENUM);
  if (errno)
    return false;

  resolved = btf__resolve_type(vmlinux, btf_vdso_clock_mode_id);
  if (resolved < 0)
    return false;

  const struct btf_type *vdso_clock_mode = btf__type_by_id(vmlinux, resolved);
  if (!vdso_clock_mode)
    return false;

  out->clock_mode_tsc =
      lookup_enum_member(vmlinux, vdso_clock_mode, "VDSO_CLOCKMODE_TSC");
  if (!out->clock_mode_tsc)
    return false;

  return true;
}

static bool validate_non_bitfield_integral_struct_member(
    const struct btf *vmlinux, const struct btf_member *memb,
    size_t want_offset_bits, unsigned int want_width_bits, bool want_signed) {

  int resolved = btf__resolve_type(vmlinux, memb->type);
  if (resolved < 0)
    return false;
  const struct btf_type *type = btf__type_by_id(vmlinux, resolved);

  if (!type)
    return false;

  if (BTF_INFO_KFLAG(type->info))
    // Is bitfield
    return false;

  if (memb->offset != want_offset_bits)
    return false;

  if (BTF_INFO_KIND(type->info) != BTF_KIND_INT)
    // Not integral
    return false;

  bool is_signed = (btf_int_encoding(type) & BTF_INT_SIGNED);
  if (want_signed != is_signed)
    return false;

  if (want_width_bits != btf_int_bits(type))
    return false;

  return true;
}

bool validate_kernel_data(const struct btf *vmlinux,
                          const struct kernel_data *kdata) {
  struct vdso_data_hdr dummy;

  return (
      validate_non_bitfield_integral_struct_member(
          vmlinux, kdata->seq_info, offsetof(struct vdso_data_hdr, seq) << 3,
          sizeof(dummy.seq) << 3, false) &&
      validate_non_bitfield_integral_struct_member(
          vmlinux, kdata->clock_mode_info,
          offsetof(struct vdso_data_hdr, clock_mode) << 3,
          sizeof(dummy.clock_mode) << 3, true) &&
      validate_non_bitfield_integral_struct_member(
          vmlinux, kdata->mult_info, offsetof(struct vdso_data_hdr, mult) << 3,
          sizeof(dummy.mult) << 3, false) &&
      validate_non_bitfield_integral_struct_member(
          vmlinux, kdata->shift_info,
          offsetof(struct vdso_data_hdr, shift) << 3, sizeof(dummy.shift) << 3,
          false));
}

int main(__attribute__((unused)) int argc,
         __attribute__((unused)) char **argv) {
  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

  int ret = 1;
  bool raw = ((argc >= 2) && !strcmp(argv[1], "raw"));
  fprintf(stderr, "reading %s coefficients\n",
          raw ? "CLOCK_MONOTONIC_RAW" : "CLOCK_MONOTONIC");

  struct btf *vmlinux = btf__load_vmlinux_btf();
  if (!vmlinux) {
    perror("fatal: cannot open vmlinux BTF");
    goto fail_open_btf;
  }

  struct kernel_data kdata;
  if (!gather_kernel_data(&kdata, vmlinux)) {
    fputs("fatal: data in vDSO not as expected\n", stderr);
    goto fail_gather_kernel_info;
  }

  if (!validate_kernel_data(vmlinux, &kdata)) {
    fputs("fatal: data in vDSO not as expected\n", stderr);
    goto fail_gather_kernel_info;
  }

  void *vvar_start = get_vvar_start();
  if (!vvar_start) {
    fputs("fatal: unable to obtain [vvar] start address\n", stderr);
    goto fail_vdso;
  }

  struct vdso_data_hdr hdr;
  read_vdso_data(&hdr, vvar_start, &kdata, raw);

  uint32_t mult, shift;
  if (!get_tsc_mult_shift(&mult, &shift, &kdata, &hdr)) {
    fputs("fatal: (clocksource != TSC) || (time_ns != initial)\n", stderr);
    goto fail_coeff;
  }

  printf("ns = (tsc * %" PRIu32 ") >> %" PRIu32 "\n", mult, shift);
  ret = 0;

fail_coeff:
fail_vdso:
fail_gather_kernel_info:
  btf__free(vmlinux);
fail_open_btf:
  return ret;
}
