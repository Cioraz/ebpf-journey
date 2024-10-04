from bcc import BPF
from time import sleep

program = r"""
// Sets a hash table to store the counter for each user ID called counter_table
BPF_HASH(counter_table);

int hello(void *ctx){
    u64 uid;
    u64 counter=0;
    u64 *search_ptr;
    
    // gets the user ID that is running process that triggered this probe event
    uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    search_ptr = counter_table.lookup(&uid);

    if (search_ptr != NULL){
        counter = *search_ptr;
    }

    counter++;
    counter_table.update(&uid,&counter);
    return 0;
}
"""

b=BPF(text=program)
syscall=b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")

while True:
    sleep(2)
    string=""
    for k,v in b["counter_table"].items():
        string += f"uid: {k.value} counter: {v.value}\t"
    print(string)
