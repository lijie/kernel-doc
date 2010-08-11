/* --- 数据结构 --- */

/* 就是fd_set, 使用select的话, 我们也会用到这个结构
 * fds_bits是一组Bit, __FDSET_LONGS 默认是 1024 / 8 * sizeof(long) */
typedef struct {
	unsigned long fds_bits [__FDSET_LONGS];
} __kernel_fd_set;

/* fdtable描述了fd与struct file的对应关系 */
struct fdtable {
	/* 当前进程能够使用的最大fd */
	unsigned int max_fds;
	/* 一个数组, fd[fd] = struct file
	 * 用来快速通过fd定位struct file */
	struct file ** fd;      /* current fd array */
	/* bit位, 记录了所有具有O_CLONEXEC flag的fd */
	fd_set *close_on_exec;
	/* bit位, 记录了所有打开的fd */
	fd_set *open_fds;
	/* rcu相关内容跟VFS无直接关系, 我们不讨论 */
	struct rcu_head rcu;
	struct fdtable *next;
};

/*
 * The embedded_fd_set is a small fd_set,
 * suitable for most tasks (which open <= BITS_PER_LONG files)
 */
/* 迷你版fd_set, 当进程打开的文件数小于BITS_PER_LONG时,
 * 内核优先使用embedded_fd_set, 而不是fd_set,
 * 这有很多好处,(我总结的...非官方):
 * 1. 节约内存
 * 2. L1_Cache友好, 一个unsigned long可以一次性load到cache_line中
 * 3. 使用超过32(or 64 in 64bit cpu)个fd的进程是少数...
 */
struct embedded_fd_set {
	unsigned long fds_bits[1];
};

/*
 * Open file table structure
 */
/* files结构, 保存了fdtable, 
 * 然后还提供一些L1 cache友好的特点来帮助快速索引fd和struct file */
struct files_struct {
  /*
   * read mostly part
   */
	atomic_t count;
	/* 
	 * 这样的声明很奇怪, 要一个fdtable指针, 还要一个fdtable变量...
	 * 我们在讲dup_fd()时会详细说明, 这里简单的说说,
	 * 默认情况下, fdt = &fdtab, fdtab初始化为使用迷你版fd_set,
	 * 即embedded_fd_set, 最多只能打开BITS_PER_LONG个文件.
	 * 如果进程要使用更多的fd, 内核就会抛弃下面的fdtab, 进而动态分配
	 * 更大的fdtab, 支持更大的fd_set, 满足应用需求.
	 */
	struct fdtable *fdt;
	struct fdtable fdtab;
  /*
   * written part on a separate cache line in SMP
   */
	/* 后面那个奇怪的____xxx的意思是:
	 * file_lock这个变量在内存里的位置, 必须是cacheline对齐的,
	 * cacheline是多大呢, 呃, 这个是可配的, x86环境下常见的是64bytes,
	 * cacheline我的理解是进入L1 Cache的一个基本单位,
	 * CPU每次都会load一个(或者多个?)cacheline大小的数据到L1 cache中. */
	spinlock_t file_lock ____cacheline_aligned_in_smp;
	int next_fd;
	/* 这些都是赋给fdtable的初值, 也就是fd数目小于BITS_PER_LONG的理想状态. */
	struct embedded_fd_set close_on_exec_init;
	struct embedded_fd_set open_fds_init;
	struct file * fd_array[NR_OPEN_DEFAULT];
};

/* --- 代码分析 --- */

/* 
 * 这就是大名鼎鼎的open()了, 看起来蛮简洁的
 */
SYSCALL_DEFINE3(open, const char __user *, filename, int, flags, int, mode)
{
	long ret;

	/* 64bit系统下, O_LARGEFILE总是默认打开 */
	if (force_o_largefile())
		flags |= O_LARGEFILE;

	/* 这里完成真正的open动作
	 * AT_FDCWD的意思是, 如果filename使用的是相对路径,
	 * 则指定为当前目录的相对路径, 如果filename是绝对路径,
	 * 该参数会被忽略.
	 * 详细的说明, 可以参考man 2 openat
	 */
	ret = do_sys_open(AT_FDCWD, filename, flags, mode);
	/* avoid REGPARM breakage on x86: */
	asmlinkage_protect(3, ret, filename, flags, mode);
	return ret;
}

/* 
 * 该函数可以看出open需要做的几件事情
 * 1. 找到一个可用的fd
 * 2. 分配到一个struct file结构, 并与fd关联
 * 3. 发出一个事件通知别"人", 一个文件被open了
 * 我们会仔细分析这3大步骤的~
 */
long do_sys_open(int dfd, const char __user *filename, int flags, int mode)
{
	/* 内核会从slab中分配一段内存, 然后从用户空间把
	 * 文件路径这段字符串copy过来. */
	char *tmp = getname(filename);
	int fd = PTR_ERR(tmp);

	if (!IS_ERR(tmp)) {
		/* 寻找到一个可用的fd
		 * 具体细节在alloc_fd()函数中描述
		 * 该函数其实就是调用alloc_fd(0, flags) */
		fd = get_unused_fd_flags(flags);
		if (fd >= 0) {
			/* 分配一个struct file结构,
			 * 这是一个非常非常复杂的操作... */
			struct file *f = do_filp_open(dfd, tmp, flags, mode, 0);
			if (IS_ERR(f)) {
				put_unused_fd(fd);
				fd = PTR_ERR(f);
			} else {
				/* 用于trace整个内核空间的fs变化 */
				fsnotify_open(f->f_path.dentry);
				/* 将fd和分配的file结构关联起来
				 * fdtable有一个指针数组fd, 
				 * 每个项都是指向一个struct file的指针,
				 * 所以这个函数本质上就是:
				 * current->files->fdt->fd[fd] = f */
				fd_install(fd, f);
			}
		}
		/* 完毕, 释放内存 */
		putname(tmp);
	}
	return fd;
}

/*
 * allocate a file descriptor, mark it busy.
 */
/*
 * 该函数用于分配一个可用的fd
 * start 指定从哪里开始查找,
 * 因为fd是一个从0开始的整数, start一般来说都是0
 */
int alloc_fd(unsigned start, unsigned flags)
{
	/*
	 * files_struct 保存了当前进程的一些文件信息,
	 * 比如所有已经打开的文件的fd...
	 */
	struct files_struct *files = current->files;
	unsigned int fd;
	int error;
	/* fdtable看名字也知道, 是一个表,
	 * 记录了fd和struct file的对应关系 */
	struct fdtable *fdt;

	/*
	 * 我认为有必要讨论一下这个锁, 我的理解不一定对.
	 * spin_lock只有在多核和抢占(我们不深究抢占模式)下才有意义,
	 * 这里我认为这个锁是防止其它CPU来访问我们的files,
	 * 但是files = current->files, 看起来每个files是进程独立的,
	 * 而同一个进程, 在同一个时刻, 只会在一个CPU上运行,
	 * 这样看起来, files似乎不存在多CPU之间竞争的问题.
	 *
	 * 我看到这里时也疑惑了一下, 后来仔细想想, 多线程啊!
	 * 多个线程之间共享同一个files, 也就是它们持有同一个fdt,
	 * 多CPU环境下, 一个进程的多个线程同时open, 是会有竞争的.
	 */
	spin_lock(&files->file_lock);
repeat:
	/* 这句就是 fdt = files->fdt, 获取current的fdtable */
	fdt = files_fdtable(files);
	/* OK 我们从start开始找 */
	fd = start;
	/* next_fd一般就是上一次分配的fd+1
	 * 很多情况下, 这个next_fd就是我们想要的... */
	if (fd < files->next_fd)
		fd = files->next_fd;

	/* 
	 * 其实一看就知道这几行代码是要找一个,
	 * 离fd最近的, 大于或等于fd, 没有被使用的fd.
	 * open_fds 其实就是一个fd_set, 用过select的同学一定熟悉.
	 * fds_bits就是一组bit位, 0表示未使用, 1表示已经使用.
	 * max_fds大家都知道默认是1024, 但是可以扩展.
	 */
	if (fd < fdt->max_fds)
		fd = find_next_zero_bit(fdt->open_fds->fds_bits,
					   fdt->max_fds, fd);

	/* 如果fds_bits已经全部使用完毕, 那就是fd >= max_fds
	 * 这时就需要扩增我们的fdt了 */
	error = expand_files(files, fd);
	if (error < 0)
		goto out;

	/*
	 * If we needed to expand the fs array we
	 * might have blocked - try again.
	 */
	/* 不成功, 不罢休... */
	if (error)
		goto repeat;

	/* 如果需要, 更新next_fd */
	if (start <= files->next_fd)
		files->next_fd = fd + 1;

	/* 将对应的bit标记为已经使用 */
	FD_SET(fd, fdt->open_fds);

	/* 像O_CLOEXEC这样重要的标志位, 内核也使用了专门的
	 * 一个fd_set来保存  */
	if (flags & O_CLOEXEC)
		FD_SET(fd, fdt->close_on_exec);
	else
		FD_CLR(fd, fdt->close_on_exec);
	error = fd;
#if 1
	/* Sanity check */
	if (rcu_dereference_raw(fdt->fd[fd]) != NULL) {
		printk(KERN_WARNING "alloc_fd: slot %d not NULL!\n", fd);
		rcu_assign_pointer(fdt->fd[fd], NULL);
	}
#endif

out:
	spin_unlock(&files->file_lock);
	return error;
}
