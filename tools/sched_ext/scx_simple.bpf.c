/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A simple scheduler.
 *
 * By default, it operates as a simple global weighted vtime scheduler and can
 * be switched to FIFO scheduling. It also demonstrates the following niceties.
 *
 * - Statistics tracking how many tasks are queued to local and global dsq's.
 * - Termination notification for userspace.
 *
 * While very simple, this scheduler should work reasonably well on CPUs with a
 * uniform L3 cache topology. While preemption is not implemented, the fact that
 * the scheduling queue is shared across all CPUs means that whatever is at the
 * front of the queue is likely to be executed fairly quickly given enough
 * number of CPUs. The FIFO scheduling mode may be beneficial to some workloads
 * but comes with the usual problems with FIFO scheduling where saturating
 * threads can easily drown out interactive ones.
 *
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

#define ENQUEUE_RESTORE		0x02
#define ENQUEUE_MIGRATED        0x40
#define ENQUEUE_INITIAL                0x80

const volatile bool fifo_sched;
const volatile u32 task_limit = 2;

static u64 vtime_now;
UEI_DEFINE(uei);

/*
 * Built-in DSQs such as SCX_DSQ_GLOBAL cannot be used as priority queues
 * (meaning, cannot be dispatched to with scx_bpf_dsq_insert_vtime()). We
 * therefore create a separate DSQ with ID 0 that we dispatch to and consume
 * from. If scx_simple only supported global FIFO scheduling, then we could just
 * use SCX_DSQ_GLOBAL.
 */
#define SHARED_DSQ 0

// struct {
// 	__uint(type, BPF_MAP_TYPE_ARRAY);
// 	__uint(key_size, sizeof(u32));
// 	__uint(value_size, sizeof(u64));
// 	__uint(max_entries, 5);			/* [local, global] */
// } stats SEC(".maps");
s64 stats[5];
#define RINGBUF_SIZE (256 * 1024) /* 256 KB */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_SIZE);
} rb SEC(".maps");

/* Per-task scheduling context */
struct task_ctx { //scx_nest
	/*
	 * The last core that the task executed on. This is used to determine
	 * if the task should attach to the core that it will execute on next.
	 */
	s32 prev_cpu;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

// struct {
// 	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
// 	__uint(max_entries, 1);
// 	__type(key, int);
// 	__type(value, struct event);
// } heap SEC(".maps");
#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 512

struct event {
	int pid;
	int cpu;
	u64 stat;
	char comm[16];
	char func[16];
};

static s64 stat_inc(s32 idx)
{
	if (idx<=4 && idx>=0)
		return __sync_fetch_and_add(&stats[idx], 1);
	const char fmt_str[] = "stat_inc cpu:%d";
	bpf_trace_printk(fmt_str, sizeof(fmt_str), idx);
	return -1;
}

static s32 stat_dec(s32 idx)
{
	if (idx<=4 && idx>=0)
		return __sync_fetch_and_sub(&stats[idx], 1);
	return -1;
}

static s64 stat_read(s32 idx)
{
	if (idx<=4 && idx>=0)
		return stats[idx];
	return 0xdeadbeaf;
}

#ifndef NR_CPUS
#define NR_CPUS 4
#endif
s32 pick_avail_cpu(s32 cur)
{
	for (int i = 0; i < NR_CPUS; i++) {
		if ((i != cur) && (stat_read(i) < task_limit)) {
			return i;
		}
	}
	return -1;
}

s32 BPF_STRUCT_OPS(simple_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;
	s32 target_cpu;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

	s64 pre_stat = stat_read(prev_cpu);
	const char fmt_str0[] = "simple_select_cpu pid:%d prev_cpu:%d pre_stat:%d";
	bpf_trace_printk(fmt_str0, sizeof(fmt_str0), p->pid, prev_cpu, pre_stat);

	s64 stat0 = stat_read(cpu);
	if (/*is_idle && */stat0 < task_limit) {
		const char fmt_str[] = "simple_select_cpu pid:%d cpu:%d stat:%d";
		bpf_trace_printk(fmt_str, sizeof(fmt_str), p->pid, cpu, stat0);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
	} else {
		target_cpu = pick_avail_cpu(cpu);
		if (target_cpu >= 0) {
			s64 target_stat = stat_read(target_cpu);
			const char fmt_str[] = "simple_select_cpu pid:%d target_cpu:%d target_stat:%d";
			bpf_trace_printk(fmt_str, sizeof(fmt_str), p->pid, target_cpu, target_stat);
			/* dispatch to local */
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | target_cpu, SCX_SLICE_DFL, 0);
			return target_cpu;
		} else {
			const char fmt_str0[] = "%s %d pick_avail_cpu failed prev_cpu: %d";
			bpf_trace_printk(fmt_str0, sizeof(fmt_str0), p->comm, p->pid, prev_cpu);
		}
	}

	return cpu;
}

void BPF_STRUCT_OPS(simple_enqueue, struct task_struct *p, u64 enq_flags)
{
	stat_inc(4);	/* count global queueing */
	u64 stat0 = stat_read(4);
	const char fmt_str[] = "simple_enqueue global pid:%d %llu enq_flags:%llx";
	bpf_trace_printk(fmt_str, sizeof(fmt_str), p->pid, stat0, enq_flags);

	if (fifo_sched) {
		scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
	} else {
		u64 vtime = p->scx.dsq_vtime;

		/*
		 * Limit the amount of budget that an idling task can accumulate
		 * to one slice.
		 */
		if (time_before(vtime, vtime_now - SCX_SLICE_DFL))
			vtime = vtime_now - SCX_SLICE_DFL;

		scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, SCX_SLICE_DFL, vtime,
					 enq_flags);
	}
}

void BPF_STRUCT_OPS(simple_dispatch, s32 cpu, struct task_struct *prev)
{
	s64 stat0;
	stat0 = stat_read(cpu);
	if (prev) {
		const char fmt_str[] = "simple_dispatch prev_pid:%x stat:%d cpu:%d";
		bpf_trace_printk(fmt_str, sizeof(fmt_str), prev->pid, stat0, cpu);
	} else {
		const char fmt_str[] = "simple_dispatch stat:%d cpu:%d";
		bpf_trace_printk(fmt_str, sizeof(fmt_str), stat0, cpu);
	}
	if (stat0 >= task_limit) {
		// s32 target_cpu = pick_avail_cpu(cpu);
		
		// if (target_cpu >= 0 && target_cpu<=3) {
			if (prev) {
				/*
				* If the current task expired its time slice and no other task
				* wants to run, simply replenish its time slice and let it run for
				* another round on the same CPU.
				*/
				prev->scx.slice = SCX_SLICE_DFL;
			} else {
				const char fmt_str0[] = "dispatch failed cancel stat %llu cpu %d";
				bpf_trace_printk(fmt_str0, sizeof(fmt_str0), stat0, cpu);
				// scx_bpf_kick_cpu(target_cpu, SCX_KICK_PREEMPT);
				///////////////////////////////////////////////////////////
				if (scx_bpf_dispatch_nr_slots() < SCX_DSP_DFL_MAX_BATCH)
					scx_bpf_dispatch_cancel();
			}
			return;
		// }
	} else {
		stat0 = stat_read(4);
		if (stat0) {
			stat_dec(4);
		}
		if (!scx_bpf_dsq_move_to_local(SHARED_DSQ)) {
			const char fmt_str0[] = "dispatch none stat %llu cpu %d";
			bpf_trace_printk(fmt_str0, sizeof(fmt_str0), stat0, cpu);
		}
	}
}

void BPF_STRUCT_OPS(simple_dequeue, struct task_struct *p, u64 deq_flags)
{
	s32 cpu = scx_bpf_task_cpu(p);
	stat_dec(cpu);
	u64 stat = stat_read(cpu);
	const char fmt_str[] = "simple_dequeue pid:%d stat %llu deq_flags:%llx";
	bpf_trace_printk(fmt_str, sizeof(fmt_str), p->pid, stat, deq_flags);
}

void BPF_STRUCT_OPS(simple_running, struct task_struct *p)
{
	struct task_ctx *tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!tctx)
		return;

	s32 cpu = scx_bpf_task_cpu(p);
	if (cpu != tctx->prev_cpu) { //not from runnable
		s64 pre = stat_inc(cpu);
		if (pre >= task_limit) {//|| pre < 0 
			const char fmt_str[] = "simple_running inc failed pid:%x pre:%lld pre_cpu|cpu:%x";
			bpf_trace_printk(fmt_str, sizeof(fmt_str), p->pid, pre, tctx->prev_cpu<<4|cpu);
///////////////////////////////////////////////////////////////////////////////////////////////
			stat_dec(cpu);
			p->scx.slice = 0;
			return;
		}
		s64 stat0 = stat_read(cpu);

		stat_dec(tctx->prev_cpu);
		s64 stat1 = stat_read(tctx->prev_cpu);
		// const char fmt_str1[] = "simple_running pid|pre_cpu|cpu:%x pre_stat:%llu stat:%llu";
		// bpf_trace_printk(fmt_str1, sizeof(fmt_str1), p->pid<<8|(tctx->prev_cpu&0xf)<<4|cpu, stat1, stat0);
		const char fmt_str1[] = "simple_running pre_cpu|cpu:%x pre_stat:%lld pid|stat:%llx";
		bpf_trace_printk(fmt_str1, sizeof(fmt_str1), tctx->prev_cpu<<4|cpu, stat1, p->pid<<8|stat0);
	}
	if (fifo_sched)
		return;

	/*
	 * Global vtime always progresses forward as tasks start executing. The
	 * test and update can be performed concurrently from multiple CPUs and
	 * thus racy. Any error should be contained and temporary. Let's just
	 * live with it.
	 */
	if (time_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

void BPF_STRUCT_OPS(simple_stopping, struct task_struct *p, bool runnable)
{
	struct task_ctx *tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!tctx)
		return;

	s32 cpu = scx_bpf_task_cpu(p);
	// if (cpu != tctx->prev_cpu) {
		const char fmt_str[] = "simple_stopping pid:%x pre_cpu|cpu:%x runnable:%d";
		bpf_trace_printk(fmt_str, sizeof(fmt_str), p->pid, tctx->prev_cpu<<4|cpu, runnable);
	// }
	tctx->prev_cpu = cpu;
	if (fifo_sched)
		return;

	/*
	 * Scale the execution time by the inverse of the weight and charge.
	 *
	 * Note that the default yield implementation yields by setting
	 * @p->scx.slice to zero and the following would treat the yielding task
	 * as if it has consumed all its slice. If this penalizes yielding tasks
	 * too much, determine the execution time by taking explicit timestamps
	 * instead of depending on @p->scx.slice.
	 */
	p->scx.dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;
}

void BPF_STRUCT_OPS(simple_enable, struct task_struct *p)
{
	// const char fmt_str[] = "%s simple_enable on_cpu:%d";
	// bpf_trace_printk(fmt_str, sizeof(fmt_str), p->comm, p->on_cpu);
	// stat_inc(p->on_cpu);
	p->scx.dsq_vtime = vtime_now;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(simple_init)
{
	const char fmt_str[] = "simple_init";
	bpf_trace_printk(fmt_str, sizeof(fmt_str));
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(simple_exit, struct scx_exit_info *ei)
{
	const char fmt_str[] = "simple_exit";
	bpf_trace_printk(fmt_str, sizeof(fmt_str));
	UEI_RECORD(uei, ei);
}

s32 BPF_STRUCT_OPS(simple_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	const char fmt_str[] = "simple_init_task task_cpu:%d pid:%x comm:%s";
	bpf_trace_printk(fmt_str, sizeof(fmt_str), scx_bpf_task_cpu(p), p->pid, p->comm);

	// if (p->flags & PF_VCPU) {

	// }

	struct task_ctx *tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;
	tctx->prev_cpu = -1;
	// __u64 avail_data;
	// struct event *e;
	// // int zero = 0;
	// // e = bpf_map_lookup_elem(&heap, &zero);
	// // if (!e) /* can't happen */
	// // 	return 0;

	// avail_data = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
    // if (RINGBUF_SIZE - avail_data >= sizeof(struct event))
	// {
	// 	e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
	// 	if (e)
	// 	{
	// 		e->pid = bpf_get_current_pid_tgid() >> 32;
	// 		e->cpu = p->on_cpu;
	// 		e->stat = stat_read(p->on_cpu);
	// 		bpf_probe_read_kernel_str(e->comm, sizeof(e->comm), p->comm);
	// 		bpf_probe_read_kernel_str(e->func, sizeof(e->func), "simple_init_task");
	// 		// bpf_ringbuf_output(&rb, &e, sizeof(e), 0);
	// 		bpf_ringbuf_submit(e, 0);
	// 	} else {
	// 		const char fmt_str[] = "simple_init_task ringbuf failed";
	// 		bpf_trace_printk(fmt_str, sizeof(fmt_str));
	// 	}
	// } else {
	// 	const char fmt_str[] = "simple_init_task ringbuf not avail";
	// 	bpf_trace_printk(fmt_str, sizeof(fmt_str));
	// }

	return 0;
}

void BPF_STRUCT_OPS(simple_runnable, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!tctx)
		return;
	s32 cpu = scx_bpf_task_cpu(p);
	if (enq_flags & SCX_ENQ_MIGRATED) {
		stat_inc(cpu);
		stat_dec(tctx->prev_cpu);

		s64 stat0 = stat_read(cpu);
		s64 pre_stat = stat_read(tctx->prev_cpu);

		const char fmt_str[] = "simple_runnable SCX_ENQ_MIGRATED pre_cpu|task_cpu:%x pid:%x pre_stat|stat:%llx";
		bpf_trace_printk(fmt_str, sizeof(fmt_str), tctx->prev_cpu<<4|cpu, p->pid, pre_stat<<8|stat0);
	} else if (enq_flags & SCX_ENQ_INITIAL) {
		stat_inc(cpu);
		s64 stat0 = stat_read(cpu);
		const char fmt_str[] = "simple_runnable SCX_ENQ_INITIAL pre_cpu|task_cpu:%x pid:%x stat0:%llx";
		bpf_trace_printk(fmt_str, sizeof(fmt_str), tctx->prev_cpu<<4|cpu, p->pid, stat0);
	} else if (enq_flags & ENQUEUE_RESTORE) { //DEQUEUE_SAVE
		s64 pre_stat = stat_inc(cpu);
		if (pre_stat >= task_limit) {
			// stat_dec(cpu);
			p->scx.slice = 0;
			const char fmt_str[] = "simple_runnable ENQUEUE_RESTORE failed pre_cpu|task_cpu:%x pid:%x pre_stat:%llx";
			bpf_trace_printk(fmt_str, sizeof(fmt_str), tctx->prev_cpu<<4|cpu, p->pid, pre_stat);
			tctx->prev_cpu = cpu;
			return;
			// s32 target_cpu = pick_avail_cpu(cpu);
			// if (target_cpu >= 0) {
			// 	s64 target_stat = stat_read(target_cpu);
			// 	const char fmt_str[] = "simple_runnable ENQUEUE_RESTORE pid:%d target_cpu:%d target_stat:%d";
			// 	bpf_trace_printk(fmt_str, sizeof(fmt_str), p->pid, target_cpu, target_stat);
			// 	/* dispatch to local */
			// 	// scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | target_cpu, SCX_SLICE_DFL, 0);
			// 	u64 vtime = p->scx.dsq_vtime;

			// 	/*
			// 	* Limit the amount of budget that an idling task can accumulate
			// 	* to one slice.
			// 	*/
			// 	if (time_before(vtime, vtime_now - SCX_SLICE_DFL))
			// 		vtime = vtime_now - SCX_SLICE_DFL;

			// 	scx_bpf_dsq_insert_vtime(p, SCX_DSQ_LOCAL_ON | target_cpu, SCX_SLICE_DFL, vtime, enq_flags);
			// 	return;
			// }
		}
		s64 stat0 = stat_read(cpu);
		const char fmt_str[] = "simple_runnable ENQUEUE_RESTORE pre_cpu|task_cpu:%x pid:%x stat0:%llx";
		bpf_trace_printk(fmt_str, sizeof(fmt_str), tctx->prev_cpu<<4|cpu, p->pid, stat0);
	} else {
		const char fmt_str[] = "simple_runnable pre_cpu|task_cpu:%x pid:%x enq_flags:%llx";
		bpf_trace_printk(fmt_str, sizeof(fmt_str), tctx->prev_cpu<<4|cpu, p->pid, enq_flags);
	}
	tctx->prev_cpu = cpu;
}

void BPF_STRUCT_OPS(simple_quiescent, struct task_struct *p, u64 deq_flags)
{
	struct task_ctx *tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!tctx)
		return;
	s32 cpu = scx_bpf_task_cpu(p);
	const char fmt_str[] = "simple_quiescent pre_cpu|task_cpu:%x pid:%x deq_flags:%llx";
	bpf_trace_printk(fmt_str, sizeof(fmt_str), tctx->prev_cpu<<4|cpu, p->pid, deq_flags);
	/************ update state in runnable *****************
	if (stat_read(cpu))
		stat_dec(cpu);
	********************************************************/
	// tctx->prev_cpu = cpu;
}

SCX_OPS_DEFINE(simple_ops,
		   .init_task		= (void *)simple_init_task,
	       .select_cpu		= (void *)simple_select_cpu,
	       .enqueue			= (void *)simple_enqueue,
		   .dequeue			= (void *)simple_dequeue,
	       .dispatch		= (void *)simple_dispatch,
		   .runnable		= (void *)simple_runnable,
		   .quiescent		= (void *)simple_quiescent,
	       .running			= (void *)simple_running,
	       .stopping		= (void *)simple_stopping,
	       .enable			= (void *)simple_enable,
	       .init			= (void *)simple_init,
	       .exit			= (void *)simple_exit,
	       .name			= "simple");
