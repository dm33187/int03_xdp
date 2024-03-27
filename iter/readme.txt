For reference:
File bpf_iter_tcp4.c was changed to iter_tcp4.bpf.c
It was originally taken from the repo:
https://github.com/torvalds/linux.git
It was then modified to output total_retrans and segs_out to help 
with figuring out number of retransmission on a transfer.

The following header files were also taken from repo to help with compiling the file:

bpf_iter.h - ./tools/testing/selftests/bpf/progs/bpf_iter.h
bpf_tracing_net.h - ./tools/testing/selftests/bpf/progs/bpf_tracing_net.h
vmlinux.h - ./tools/testing/selftests/bpf/tools/build/bpftool/vmlinux.h
