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
	/* 应用计数, 可能有多个进程使用当前的files结构 */
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
	 * max_fds默认是BITS_PER_LONG, 但是可以扩展.
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


/* --- 查找文件 --- */

/* --- 数据结构 --- */

/* 这个是VFS中最为重要的数据结构之一,
 * dentry, 一般称之位dentry cache或者dcache, 它的结构比较复杂,
 * 保存的数据很多, 作用也用多, 但是它有几个特点:
 * dentry完全保存在内存中, 不会写入磁盘.
 * dentry的存在完全是为了提高性能, 它cache了很多数据,
 * 比如某个目录的dcache, 保存了它的父目录, (部分)子目录, 对应的inode结构,
 * 并且提供hash来实现快速查找.
 * 总之目前我们可以这么认为: 查找某个文件, 就是找这个文件的dcache. */
struct dentry {
	/* 引用计数 */
	atomic_t d_count;
	/* ??? */
	unsigned int d_flags;		/* protected by d_lock */
	spinlock_t d_lock;		/* per dentry lock */
	int d_mounted;
	/* 对应的inode */
	struct inode *d_inode;		/* Where the name belongs to - NULL is
					 * negative */
	/*
	 * The next three fields are touched by __d_lookup.  Place them here
	 * so they all fit in a cache line.
	 */
	/* hash链用于查找 */
	struct hlist_node d_hash;	/* lookup hash list */
	/* 父dentry */
	struct dentry *d_parent;	/* parent directory */
	/* 对应的目录或文件的名字 */
	struct qstr d_name;

	struct list_head d_lru;		/* LRU list */
	/*
	 * d_child and d_rcu can share memory
	 */
	union {
		struct list_head d_child;	/* child of parent list */
	 	struct rcu_head d_rcu;
	} d_u;
	/* 子dentry链表 */
	struct list_head d_subdirs;	/* our children */
	/* 多个dentry可能指向同一个inode, 比如硬连接.
	 * 这种情况下, 多个dentry通过d_alias链接到inode的一个链表头上. */
	struct list_head d_alias;	/* inode alias list */
	/* ??? */
	unsigned long d_time;		/* used by d_revalidate */
	/* 由文件系统指定, 一般为NULL */
	const struct dentry_operations *d_op;
	struct super_block *d_sb;	/* The root of the dentry tree */
	void *d_fsdata;			/* fs-specific data */

	/* 如果对应的目录或者文件名小于DNAME_INLINE_LEN_MIN,
	 * 则该数组用来保存文件名, 即d_name.name = d_iname.
	 * 否则, 内核会从slab分配一段内存来保存文件名. */
	unsigned char d_iname[DNAME_INLINE_LEN_MIN];	/* small names */
};

/* quick string
 * 该结构在内核中用来表达一个文件或者目录的名字,
 * 根据pathname找着文件时, 为了提高查询效率,
 * 内核使用到了hash.
 */
struct qstr {
	/* 字符串hash后的值 */
	unsigned int hash;
	/* 字符串的实际长度 */
	unsigned int len;
	/* 真正的字符串本身 */
	const unsigned char *name;
};

/* path就是表示某个文件的路径了,
 * 其实拿到dentry后, 就已经可以知道当前文件的完整路径了,
 * 但是dentry本身是VFS里面的概念, 与具体的文件系统无直接
 * 关系, 所以它并没有保存文件所在的挂载点的信息, 比如
 * 当前文件使用的哪种文件系统等等. 
 * path将二者组合起来,方便使用.
 */
struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
};

/* 这个结构怎么说呢...
 * 我们在根据pathname寻找dcache的过程中, 会用到下面一些数据,
 * 于是把这些数据组织起来, 就叫nameidata了... */
struct nameidata {
	struct path	path;
	struct qstr	last;
	struct path	root;
	unsigned int	flags;
	int		last_type;
	unsigned	depth;
	char *saved_names[MAX_NESTED_LINKS + 1];

	/* Intent data */
	union {
		struct open_intent open;
	} intent;
};

/*
 * Note that the low bits of the passed in "open_flag"
 * are not the same as in the local variable "flag". See
 * open_to_namei_flags() for more details.
 */
struct file *do_filp_open(int dfd, const char *pathname,
		int open_flag, int mode, int acc_mode)
{
	struct file *filp;
	struct nameidata nd;
	int error;
	struct path path;
	int count = 0;
	int flag = open_to_namei_flags(open_flag);
	int force_reval = 0;

	if (!(open_flag & O_CREAT))
		mode = 0;

	/*
	 * O_SYNC is implemented as __O_SYNC|O_DSYNC.  As many places only
	 * check for O_DSYNC if the need any syncing at all we enforce it's
	 * always set instead of having to deal with possibly weird behaviour
	 * for malicious applications setting only __O_SYNC.
	 */
	if (open_flag & __O_SYNC)
		open_flag |= O_DSYNC;

	if (!acc_mode)
		acc_mode = MAY_OPEN | ACC_MODE(open_flag);

	/* O_TRUNC implies we need access checks for write permissions */
	if (open_flag & O_TRUNC)
		acc_mode |= MAY_WRITE;

	/* Allow the LSM permission hook to distinguish append 
	   access from general write access. */
	if (open_flag & O_APPEND)
		acc_mode |= MAY_APPEND;

	/* find the parent */
	/* 在开始查找之前, 初始化一下nameidata,
	 * 话说这函数名居然叫path_init, 不是很地道啊...
	 * 根据pathname使用的是绝对路径还是相对路径,
	 * nd.path = current->fs->root 或者 current->fs->pwd
	 *
	 * 这里我说下我的看法, 未经验证的:
	 * 内核必须保证有2个dcache必须在内存里面,
	 * 1 是根目录, 2 是当前进程的pwd.
	 * 所以这一步可以说是确定我们的开始位置, 然后再开始查找工作.
	 *
	 * LOOKUP_PARENT 的意思是我们要找到target的parent,
	 * 比如这个目录: /path/to/your/file,
	 * 我们想找的是'your'.
	 */
reval:
	error = path_init(dfd, pathname, LOOKUP_PARENT, &nd);
	if (error)
		return ERR_PTR(error);
	if (force_reval)
		nd.flags |= LOOKUP_REVAL;

	current->total_link_count = 0;

	/* link_path_walk在这里完成的任务比较纠结
	 * 以/path/to/your/file这个pathname作为例子的话,
	 * 最终nd->path将会保存'your'的dcache,
	 * nd->last.name将会指向file这个字符串,
	 * 就是说, 我们现在拿到了parent的dcache,
	 * 和目标文件的qstr */
	error = link_path_walk(pathname, &nd);
	if (error) {
		filp = ERR_PTR(error);
		goto out;
	}
	/* ??? */
	if (unlikely(!audit_dummy_context()) && (open_flag & O_CREAT))
		audit_inode(pathname, nd.path.dentry);

	/*
	 * We have the parent and last component.
	 */

	error = -ENFILE;
	/* 分配一个空的struct file */
	filp = get_empty_filp();
	if (filp == NULL)
		goto exit_parent;
	nd.intent.open.file = filp;
	/* 记录open传进来的flags */
	filp->f_flags = open_flag;
	nd.intent.open.flags = flag;
	nd.intent.open.create_mode = mode;
	/* 清除掉PARENT标志位, 加上OPEN标志位 */
	nd.flags &= ~LOOKUP_PARENT;
	nd.flags |= LOOKUP_OPEN;
	/* 如果需要, 加上CREAT标志位 */
	if (open_flag & O_CREAT) {
		nd.flags |= LOOKUP_CREATE;
		if (open_flag & O_EXCL)
			nd.flags |= LOOKUP_EXCL;
	}
	if (open_flag & O_DIRECTORY)
		nd.flags |= LOOKUP_DIRECTORY;
	if (!(open_flag & O_NOFOLLOW))
		nd.flags |= LOOKUP_FOLLOW;
	/* do_last么, 你可以看作是最后一步, 但是这一步可够繁琐的... */
	filp = do_last(&nd, &path, open_flag, acc_mode, mode, pathname);
	/*
	 * filp == NULL 说明我们要打开的文件是个符号链接,
	 */
	while (unlikely(!filp)) { /* trailing symlink */
		struct path holder;
		struct inode *inode = path.dentry->d_inode;
		void *cookie;
		error = -ELOOP;
		/* S_ISDIR part is a temporary automount kludge */
		if (!(nd.flags & LOOKUP_FOLLOW) && !S_ISDIR(inode->i_mode))
			goto exit_dput;
		if (count++ == 32)
			goto exit_dput;
		/*
		 * This is subtle. Instead of calling do_follow_link() we do
		 * the thing by hands. The reason is that this way we have zero
		 * link_count and path_walk() (called from ->follow_link)
		 * honoring LOOKUP_PARENT.  After that we have the parent and
		 * last component, i.e. we are in the same situation as after
		 * the first path_walk().  Well, almost - if the last component
		 * is normal we get its copy stored in nd->last.name and we will
		 * have to putname() it when we are done. Procfs-like symlinks
		 * just set LAST_BIND.
		 */
		nd.flags |= LOOKUP_PARENT;
		error = security_inode_follow_link(path.dentry, &nd);
		if (error)
			goto exit_dput;
		error = __do_follow_link(&path, &nd, &cookie);
		if (unlikely(error)) {
			/* nd.path had been dropped */
			if (!IS_ERR(cookie) && inode->i_op->put_link)
				inode->i_op->put_link(path.dentry, &nd, cookie);
			path_put(&path);
			release_open_intent(&nd);
			filp = ERR_PTR(error);
			goto out;
		}
		holder = path;
		nd.flags &= ~LOOKUP_PARENT;
		filp = do_last(&nd, &path, open_flag, acc_mode, mode, pathname);
		if (inode->i_op->put_link)
			inode->i_op->put_link(holder.dentry, &nd, cookie);
		path_put(&holder);
	}
out:
	if (nd.root.mnt)
		path_put(&nd.root);
	if (filp == ERR_PTR(-ESTALE) && !force_reval) {
		force_reval = 1;
		goto reval;
	}
	return filp;

exit_dput:
	path_put_conditional(&path, &nd);
	if (!IS_ERR(nd.intent.open.file))
		release_open_intent(&nd);
exit_parent:
	path_put(&nd.path);
	filp = ERR_PTR(error);
	goto out;
}

/* 
 * nd 保存了我们目标文件的parent, 以及打开目标文件的一些flags等等
 * path 找到目标文件的dcache后, 保存在path中.
 * 所谓do_last, last指的是/path/to/your/file中的file.
 */
static struct file *do_last(struct nameidata *nd, struct path *path,
			    int open_flag, int acc_mode,
			    int mode, const char *pathname)
{
	struct dentry *dir = nd->path.dentry;
	struct file *filp;
	int error = -EISDIR;

	/* last_type是指我们要处理的的文件的类型 */
	switch (nd->last_type) {
		/* 如果last是"..", 那我们要的target其实就是nd->path.dentry,
		 * 所以我么现在要找parent的parent... */
	case LAST_DOTDOT:
		follow_dotdot(nd);
		dir = nd->path.dentry;
	case LAST_DOT:
		/* ??? */
		if (nd->path.mnt->mnt_sb->s_type->fs_flags & FS_REVAL_DOT) {
			if (!dir->d_op->d_revalidate(dir, nd)) {
				error = -ESTALE;
				goto exit;
			}
		}
		/* fallthrough */
	case LAST_ROOT:
		/* 如果last是根目录, 我们不允许创建, 也就是说,
		 * 根目录是不可能通过open来创建的... */
		if (open_flag & O_CREAT)
			goto exit;
		/* fallthrough */
	case LAST_BIND:
		/* ??? */
		audit_inode(pathname, dir);
		goto ok;
	}

	/* trailing slashes? */
	/* Target可能是个目录或者符号链接 */
	if (nd->last.name[nd->last.len]) {
		/* 看起来, open不允许被用来创建目录啊... */
		if (open_flag & O_CREAT)
			goto exit;
		nd->flags |= LOOKUP_DIRECTORY | LOOKUP_FOLLOW;
	}

	/* just plain open? */
	if (!(open_flag & O_CREAT)) {
		/* 以nd为parent, 寻找nd->last, 结果保存在path中. */
		error = do_lookup(nd, &nd->last, path);
		if (error)
			goto exit;
		error = -ENOENT;
		/* 文件不存在... */
		if (!path->dentry->d_inode)
			goto exit_dput;
		/* i_op支持follow_link说明当前我们在处理的last是个符号链接,
		 * 直接return NULL返回, do_filp_open()后续会通过该链接
		 * 找到真正的文件后再重新调用do_last */
		if (path->dentry->d_inode->i_op->follow_link)
			return NULL;
		error = -ENOTDIR;
		if (nd->flags & LOOKUP_DIRECTORY) {
			if (!path->dentry->d_inode->i_op->lookup)
				goto exit_dput;
		}
		/* OK 终于找到了目标文件的dcache, 保存到nd中 */
		path_to_nameidata(path, nd);
		audit_inode(pathname, nd->path.dentry);
		goto ok;
	}

	/* OK, it's O_CREAT */
	mutex_lock(&dir->d_inode->i_mutex);

	/* 
	 * nd中保存的是parent的dentry, 和Target的qstr,
	 * 利用这些信息可以查询dentry hash table,
	 * 如果无法查到, 则分配一个新的dentry.
	 */
	path->dentry = lookup_hash(nd);
	path->mnt = nd->path.mnt;

	error = PTR_ERR(path->dentry);
	if (IS_ERR(path->dentry)) {
		mutex_unlock(&dir->d_inode->i_mutex);
		goto exit;
	}

	if (IS_ERR(nd->intent.open.file)) {
		error = PTR_ERR(nd->intent.open.file);
		goto exit_mutex_unlock;
	}

	/* Negative dentry, just create the file */
	/* 如果dentry的d_inode为空, 说明这个dentry对应的文件并不存在,
	 * 需要创建. */
	if (!path->dentry->d_inode) {
		/*
		 * This write is needed to ensure that a
		 * ro->rw transition does not occur between
		 * the time when the file is created and when
		 * a permanent write count is taken through
		 * the 'struct file' in nameidata_to_filp().
		 */
		/* 该函数的用处是通知底层文件系统,
		 * 我们接下来会进行一个写操作... */
		error = mnt_want_write(nd->path.mnt);
		if (error)
			goto exit_mutex_unlock;
		/* 该函数会调用vfs_create, 创建一个inode与当前的dentry关联 */
		error = __open_namei_create(nd, path, open_flag, mode);
		if (error) {
			mnt_drop_write(nd->path.mnt);
			goto exit;
		}
		/* 保存我们来之不易的filep... */
		filp = nameidata_to_filp(nd);
		mnt_drop_write(nd->path.mnt);
		if (!IS_ERR(filp)) {
			error = ima_file_check(filp, acc_mode);
			if (error) {
				fput(filp);
				filp = ERR_PTR(error);
			}
		}
		return filp;
	}

	/*
	 * It already exists.
	 */
	mutex_unlock(&dir->d_inode->i_mutex);
	audit_inode(pathname, path->dentry);

	error = -EEXIST;
	if (open_flag & O_EXCL)
		goto exit_dput;

	if (__follow_mount(path)) {
		error = -ELOOP;
		if (open_flag & O_NOFOLLOW)
			goto exit_dput;
	}

	error = -ENOENT;
	if (!path->dentry->d_inode)
		goto exit_dput;

	if (path->dentry->d_inode->i_op->follow_link)
		return NULL;

	path_to_nameidata(path, nd);
	error = -EISDIR;
	if (S_ISDIR(path->dentry->d_inode->i_mode))
		goto exit;
ok:
	/* 目标文件的dcache已经找到,
	 * 下一步就是进一步完成struct file的初始化,
	 * 并将struct file和dcache关联起来:
	 * filp->f_path.dentry = nd->path.dentry */
	filp = finish_open(nd, open_flag, acc_mode);
	return filp;

exit_mutex_unlock:
	mutex_unlock(&dir->d_inode->i_mutex);
exit_dput:
	path_put_conditional(path, nd);
exit:
	if (!IS_ERR(nd->intent.open.file))
		release_open_intent(nd);
	path_put(&nd->path);
	return ERR_PTR(error);
}

/* 如果open()打开的是一个已经存在的文件,
 * 那do_last()的最后finish_open会被调用 */
static struct file *finish_open(struct nameidata *nd,
				int open_flag, int acc_mode)
{
	struct file *filp;
	int will_truncate;
	int error;

	/* 检测flag是否设置了O_TRUNC */
	will_truncate = open_will_truncate(open_flag, nd->path.dentry->d_inode);
	if (will_truncate) {
		/* 如果设置了, 通知底层文件系统我们可能会执行一个写操作,
		 * 改变文件大小 */
		error = mnt_want_write(nd->path.mnt);
		if (error)
			goto exit;
	}
	/* may_open里面主要是判断当前打开的文件类型,
	 * 比如是普通文件还是设备文件,或者socket, 
	 * 还会做一些权限验证, 等等. */
	error = may_open(&nd->path, acc_mode, open_flag);
	if (error) {
		if (will_truncate)
			mnt_drop_write(nd->path.mnt);
		goto exit;
	}
	/* 除了返回我们期盼已久的filp, 还将调用__dentry_open()
	 * 完成filp的一些初始化 */
	filp = nameidata_to_filp(nd);
	if (!IS_ERR(filp)) {
		/* IMA, 可以参考: http://lwn.net/Articles/137306/ */
		error = ima_file_check(filp, acc_mode);
		if (error) {
			fput(filp);
			filp = ERR_PTR(error);
		}
	}
	if (!IS_ERR(filp)) {
		if (will_truncate) {
			/* 如果设置了O_TRUNC... */
			error = handle_truncate(&nd->path);
			if (error) {
				fput(filp);
				filp = ERR_PTR(error);
			}
		}
	}
	/*
	 * It is now safe to drop the mnt write
	 * because the filp has had a write taken
	 * on its behalf.
	 */
	if (will_truncate)
		mnt_drop_write(nd->path.mnt);
	return filp;

exit:
	if (!IS_ERR(nd->intent.open.file))
		release_open_intent(nd);
	path_put(&nd->path);
	return ERR_PTR(error);
}

static struct file *__dentry_open(struct dentry *dentry, struct vfsmount *mnt,
					struct file *f,
					int (*open)(struct inode *, struct file *),
					const struct cred *cred)
{
	struct inode *inode;
	int error;

	f->f_mode = OPEN_FMODE(f->f_flags) | FMODE_LSEEK |
				FMODE_PREAD | FMODE_PWRITE;
	inode = dentry->d_inode;
	if (f->f_mode & FMODE_WRITE) {
		error = __get_file_write_access(inode, mnt);
		if (error)
			goto cleanup_file;
		if (!special_file(inode->i_mode))
			file_take_write(f);
	}

	f->f_mapping = inode->i_mapping;
	f->f_path.dentry = dentry;
	f->f_path.mnt = mnt;
	f->f_pos = 0;
	f->f_op = fops_get(inode->i_fop);
	file_sb_list_add(f, inode->i_sb);

	error = security_dentry_open(f, cred);
	if (error)
		goto cleanup_all;

	if (!open && f->f_op)
		open = f->f_op->open;
	if (open) {
		error = open(inode, f);
		if (error)
			goto cleanup_all;
	}
	ima_counts_get(f);

	f->f_flags &= ~(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC);

	file_ra_state_init(&f->f_ra, f->f_mapping->host->i_mapping);

	/* NB: we're sure to have correct a_ops only after f_op->open */
	if (f->f_flags & O_DIRECT) {
		if (!f->f_mapping->a_ops ||
		    ((!f->f_mapping->a_ops->direct_IO) &&
		    (!f->f_mapping->a_ops->get_xip_mem))) {
			fput(f);
			f = ERR_PTR(-EINVAL);
		}
	}

	return f;

cleanup_all:
	fops_put(f->f_op);
	if (f->f_mode & FMODE_WRITE) {
		put_write_access(inode);
		if (!special_file(inode->i_mode)) {
			/*
			 * We don't consider this a real
			 * mnt_want/drop_write() pair
			 * because it all happenend right
			 * here, so just reset the state.
			 */
			file_reset_write(f);
			mnt_drop_write(mnt);
		}
	}
	file_sb_list_del(f);
	f->f_path.dentry = NULL;
	f->f_path.mnt = NULL;
cleanup_file:
	put_filp(f);
	dput(dentry);
	mntput(mnt);
	return ERR_PTR(error);
}
