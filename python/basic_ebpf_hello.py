from bcc import BPF

program = r"""

int hello(void *ctx){
    bpf_trace_printk("Hello, World!\n");
    return 0;
}
"""

# put the ebpf program into the BPF module
b = BPF(text=program)
# get the syscall name for the execve syscall
syscall = b.get_syscall_fnname("execve")
# attach the kprobe to the execve syscall
b.attach_kprobe(event=syscall, fn_name="hello")
# print the trace
b.trace_print()
