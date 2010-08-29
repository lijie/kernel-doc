SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)
{
	struct file *file;
	ssize_t ret = -EBADF;
	int fput_needed;

	file = fget_light(fd, &fput_needed);
	if (file) {
		loff_t pos = file_pos_read(file);
		ret = vfs_read(file, buf, count, &pos);
		/* 更新pos, 即file->f_pos = pos */
		file_pos_write(file, pos);
		fput_light(file, fput_needed);
	}

	return ret;
}

ssize_t vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
	ssize_t ret;

	if (!(file->f_mode & FMODE_READ))
		return -EBADF;
	/* 至少要支持read或者aio_read */
	if (!file->f_op || (!file->f_op->read && !file->f_op->aio_read))
		return -EINVAL;
	if (unlikely(!access_ok(VERIFY_WRITE, buf, count)))
		return -EFAULT;

	/* 这里最重要的是检查文件锁, 所以这里有可能block住 */
	ret = rw_verify_area(READ, file, pos, count);
	if (ret >= 0) {
		count = ret;
		/* 如果当前文件支持read操作, 就直接调用read,
		 * 一般来说, 具体的文件系统会实现read, 或者使用某个通用的read函数,
		 * 对于驱动开发者来说, 这里是很熟悉了, 字符设备驱动大都实现了read.
		 * 值得一提的是socket没有实现read...*/
		if (file->f_op->read)
			ret = file->f_op->read(file, buf, count, pos);
		else
			/* 如果没有read, 那我们就用aio_read来模拟read */
			ret = do_sync_read(file, buf, count, pos);
		if (ret > 0) {
			fsnotify_access(file);
			/* 这是统计当前进程read的总字节数 */
			add_rchar(current, ret);
		}
		/* 统计调用系统调用读的次数 */
		inc_syscr(current);
	}

	return ret;
}

/* 
 * 用异步IO模拟同步read
 */
ssize_t do_sync_read(struct file *filp, char __user *buf, size_t len, loff_t *ppos)
{
	/* iov这玩意用过readv的同学应该很熟悉 */
	struct iovec iov = { .iov_base = buf, .iov_len = len };
	/* kiocb这个结构出乎意料的复杂...  */
	struct kiocb kiocb;
	ssize_t ret;

	/* 初始化kiocb, 主要是记录了当前进程和当前打开的文件 */
	init_sync_kiocb(&kiocb, filp);
	/* 要读的字节数, 以及偏移量 */
	kiocb.ki_pos = *ppos;
	kiocb.ki_left = len;
	kiocb.ki_nbytes = len;

	for (;;) {
		/* OK, 这里有2种情况, 要么subsystem实现了自己的aio_read, 
		 * 要么调用我们下面的通用异步io_read. */
		ret = filp->f_op->aio_read(&kiocb, &iov, 1, kiocb.ki_pos);
		if (ret != -EIOCBRETRY)
			break;
		/* 这个函数没啥, 就是反复检测kiocb中的flag,
		 * 如果kicked没有置位, 则schedule() */
		wait_on_retry_sync_kiocb(&kiocb);
	}

	if (-EIOCBQUEUED == ret)
		/* ??? */
		ret = wait_on_sync_kiocb(&kiocb);
	*ppos = kiocb.ki_pos;
	return ret;
}

/**
 * generic_file_aio_read - generic filesystem read routine
 * @iocb:	kernel I/O control block
 * @iov:	io vector request
 * @nr_segs:	number of segments in the iovec
 * @pos:	current file position
 *
 * This is the "read()" routine for all filesystems
 * that can use the page cache directly.
 */
ssize_t
generic_file_aio_read(struct kiocb *iocb, const struct iovec *iov,
		unsigned long nr_segs, loff_t pos)
{
	struct file *filp = iocb->ki_filp;
	ssize_t retval;
	unsigned long seg = 0;
	size_t count;
	loff_t *ppos = &iocb->ki_pos;

	count = 0;

	/* iov指定的base事实上是由用户态程序分配, 内核这里会检测
	 * 该部分内存空间是否可写. */
	retval = generic_segment_checks(iov, &nr_segs, &count, VERIFY_WRITE);
	if (retval)
		return retval;

	/* coalesce the iovecs and go direct-to-BIO for O_DIRECT */
	/* 如果文件打开时指定了O_DIRECT... */
	if (filp->f_flags & O_DIRECT) {
		loff_t size;
		struct address_space *mapping;
		struct inode *inode;

		mapping = filp->f_mapping;
		inode = mapping->host;
		if (!count)
			goto out; /* skip atime */
		/* 读取文件size */
		size = i_size_read(inode);
		if (pos < size) {
			/* 
			 * 这个函数背后的处理非常复杂, 就是page-writeback机制,
			 * 因为directIO是直接读写磁盘, 所以在写之前, 内核需要将
			 * 相关的page-cache都写回磁盘.
			 */
			retval = filemap_write_and_wait_range(mapping, pos,
					pos + iov_length(iov, nr_segs) - 1);
			/* 调用direct_IO完成写磁盘 */
			if (!retval) {
				retval = mapping->a_ops->direct_IO(READ, iocb,
							iov, pos, nr_segs);
			}
			/* 更新pos */
			if (retval > 0) {
				*ppos = pos + retval;
				count -= retval;
			}

			/*
			 * Btrfs can have a short DIO read if we encounter
			 * compressed extents, so if there was an error, or if
			 * we've already read everything we wanted to, or if
			 * there was a short read because we hit EOF, go ahead
			 * and return.  Otherwise fallthrough to buffered io for
			 * the rest of the read.
			 */
			if (retval < 0 || !count || *ppos >= size) {
				file_accessed(filp);
				goto out;
			}
		}
	}

	/* 如果是非DirectIO, 或者DIO未能全部完成, 我们就来到buffered io... */
	count = retval;
	/* 多个iov, 逐个处理 */
	for (seg = 0; seg < nr_segs; seg++) {
		read_descriptor_t desc;
		loff_t offset = 0;

		/*
		 * If we did a short DIO read we need to skip the section of the
		 * iov that we've already read data into.
		 */
		if (count) {
			if (count > iov[seg].iov_len) {
				count -= iov[seg].iov_len;
				continue;
			}
			offset = count;
			count = 0;
		}

		desc.written = 0;
		desc.arg.buf = iov[seg].iov_base + offset;
		desc.count = iov[seg].iov_len - offset;
		if (desc.count == 0)
			continue;
		desc.error = 0;
		/* OK, read必须继续继续深入... */
		do_generic_file_read(filp, ppos, &desc, file_read_actor);
		retval += desc.written;
		if (desc.error) {
			retval = retval ?: desc.error;
			break;
		}
		if (desc.count > 0)
			break;
	}
out:
	return retval;
}
EXPORT_SYMBOL(generic_file_aio_read);

/**
 * do_generic_file_read - generic file read routine
 * @filp:	the file to read
 * @ppos:	current file position
 * @desc:	read_descriptor
 * @actor:	read method
 *
 * This is a generic file read routine, and uses the
 * mapping->a_ops->readpage() function for the actual low-level stuff.
 *
 * This is really ugly. But the goto's actually try to clarify some
 * of the logic when it comes to error handling etc.
 */
static void do_generic_file_read(struct file *filp, loff_t *ppos,
		read_descriptor_t *desc, read_actor_t actor)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode *inode = mapping->host;
	struct file_ra_state *ra = &filp->f_ra;
	pgoff_t index;
	pgoff_t last_index;
	pgoff_t prev_index;
	unsigned long offset;      /* offset into pagecache page */
	unsigned int prev_offset;
	int error;

	index = *ppos >> PAGE_CACHE_SHIFT;
	prev_index = ra->prev_pos >> PAGE_CACHE_SHIFT;
	prev_offset = ra->prev_pos & (PAGE_CACHE_SIZE-1);
	last_index = (*ppos + desc->count + PAGE_CACHE_SIZE-1) >> PAGE_CACHE_SHIFT;
	offset = *ppos & ~PAGE_CACHE_MASK;

	for (;;) {
		struct page *page;
		pgoff_t end_index;
		loff_t isize;
		unsigned long nr, ret;

		cond_resched();
find_page:
		/* 当前文件, 所以cache的page, 都以radix-tree的形式组织, tree-root保存在mapping中,
		 * 这里是从root开始, 寻找我们期望的那个page... */
		page = find_get_page(mapping, index);
		if (!page) {
			/* 没找着, 内核启动预读机制,
			 * 文件预读机制本身就可以写成一篇论文..
			 * 内核会在这里读取文件内容并cache,
			 * 因为是预读机制, 所以它可能一次
			 * 读取的数据量大于我们这一次read所需.
			 */
			page_cache_sync_readahead(mapping,
					ra, filp,
					index, last_index - index);
			/* 再找一次page... */
			page = find_get_page(mapping, index);
			/* 还是没有, 跳转... */
			if (unlikely(page == NULL))
				goto no_cached_page;
		}
		if (PageReadahead(page)) {
			/* Page被标志为预读, 内核启动异步预读机制 */
			page_cache_async_readahead(mapping,
					ra, filp, page,
					index, last_index - index);
		}
		if (!PageUptodate(page)) {
			/* page可能已经out-of-date... */
			if (inode->i_blkbits == PAGE_CACHE_SHIFT ||
					!mapping->a_ops->is_partially_uptodate)
				goto page_not_up_to_date;
			if (!trylock_page(page))
				goto page_not_up_to_date;
			if (!mapping->a_ops->is_partially_uptodate(page,
								desc, offset))
				goto page_not_up_to_date_locked;
			unlock_page(page);
		}
page_ok:
		/*
		 * i_size must be checked after we know the page is Uptodate.
		 *
		 * Checking i_size after the check allows us to calculate
		 * the correct value for "nr", which means the zero-filled
		 * part of the page is not copied back to userspace (unless
		 * another truncate extends the file - this is desired though).
		 */
		/* 读取文件size */
		isize = i_size_read(inode);
		/* 计算page数 */
		end_index = (isize - 1) >> PAGE_CACHE_SHIFT;
		if (unlikely(!isize || index > end_index)) {
			/* 如果文件size为0或者page的索引值超过了当前文件的最大值,
			 * 出错返回. 这里的release并不一定释放该page, 而是减少引用计数,
			 * 计数为0才正真释放. */
			page_cache_release(page);
			goto out;
		}

		/* nr is the maximum number of bytes to copy from this page */
		/* 这里是计算需要读取的字节数, PAGE_CACHE_SIZE就是PAGE_SIZE,
		 * 一般比较常见的是4K */
		nr = PAGE_CACHE_SIZE;
		if (index == end_index) {
			nr = ((isize - 1) & ~PAGE_CACHE_MASK) + 1;
			if (nr <= offset) {
				page_cache_release(page);
				goto out;
			}
		}
		/* 减去偏移量, 得到要读取的字节数 */
		nr = nr - offset;

		/* If users can be writing to this page using arbitrary
		 * virtual addresses, take care about potential aliasing
		 * before reading the page on the kernel side.
		 */
		/* ??? */
		if (mapping_writably_mapped(mapping))
			flush_dcache_page(page);

		/*
		 * When a sequential read accesses a page several times,
		 * only mark it as accessed the first time.
		 */
		/* ??? */
		if (prev_index != index || offset != prev_offset)
			mark_page_accessed(page);
		prev_index = index;

		/*
		 * Ok, we have the page, and it's up-to-date, so
		 * now we can copy it to user space...
		 *
		 * The actor routine returns how many bytes were actually used..
		 * NOTE! This may not be the same as how much of a user buffer
		 * we filled up (we may be padding etc), so we can only update
		 * "pos" here (the actor routine has to update the user buffer
		 * pointers and the remaining count).
		 */
		/* actor作为回调函数传进来, 完成真正的read动作 */
		ret = actor(desc, page, offset, nr);
		offset += ret;
		index += offset >> PAGE_CACHE_SHIFT;
		offset &= ~PAGE_CACHE_MASK;
		prev_offset = offset;

		page_cache_release(page);
		if (ret == nr && desc->count)
			continue;
		goto out;

page_not_up_to_date:
		/* Get exclusive access to the page ... */
		error = lock_page_killable(page);
		if (unlikely(error))
			goto readpage_error;

page_not_up_to_date_locked:
		/* Did it get truncated before we got the lock? */
		if (!page->mapping) {
			unlock_page(page);
			page_cache_release(page);
			continue;
		}

		/* Did somebody else fill it already? */
		if (PageUptodate(page)) {
			unlock_page(page);
			goto page_ok;
		}

readpage:
		/*
		 * A previous I/O error may have been due to temporary
		 * failures, eg. multipath errors.
		 * PG_error will be set again if readpage fails.
		 */
		ClearPageError(page);
		/* Start the actual read. The read will unlock the page. */
		error = mapping->a_ops->readpage(filp, page);

		if (unlikely(error)) {
			if (error == AOP_TRUNCATED_PAGE) {
				page_cache_release(page);
				goto find_page;
			}
			goto readpage_error;
		}

		if (!PageUptodate(page)) {
			error = lock_page_killable(page);
			if (unlikely(error))
				goto readpage_error;
			if (!PageUptodate(page)) {
				if (page->mapping == NULL) {
					/*
					 * invalidate_mapping_pages got it
					 */
					unlock_page(page);
					page_cache_release(page);
					goto find_page;
				}
				unlock_page(page);
				shrink_readahead_size_eio(filp, ra);
				error = -EIO;
				goto readpage_error;
			}
			unlock_page(page);
		}

		goto page_ok;

readpage_error:
		/* UHHUH! A synchronous read error occurred. Report it */
		desc->error = error;
		page_cache_release(page);
		goto out;

no_cached_page:
		/*
		 * Ok, it wasn't cached, so we need to create a new
		 * page..
		 */
		page = page_cache_alloc_cold(mapping);
		if (!page) {
			desc->error = -ENOMEM;
			goto out;
		}
		error = add_to_page_cache_lru(page, mapping,
						index, GFP_KERNEL);
		if (error) {
			page_cache_release(page);
			if (error == -EEXIST)
				goto find_page;
			desc->error = error;
			goto out;
		}
		goto readpage;
	}

out:
	ra->prev_pos = prev_index;
	ra->prev_pos <<= PAGE_CACHE_SHIFT;
	ra->prev_pos |= prev_offset;

	*ppos = ((loff_t)index << PAGE_CACHE_SHIFT) + offset;
	file_accessed(filp);
}

int file_read_actor(read_descriptor_t *desc, struct page *page,
			unsigned long offset, unsigned long size)
{
	char *kaddr;
	unsigned long left, count = desc->count;

	if (size > count)
		size = count;

	/*
	 * Faults on the destination of a read are common, so do it before
	 * taking the kmap.
	 */
	if (!fault_in_pages_writeable(desc->arg.buf, size)) {
		kaddr = kmap_atomic(page, KM_USER0);
		left = __copy_to_user_inatomic(desc->arg.buf,
						kaddr + offset, size);
		kunmap_atomic(kaddr, KM_USER0);
		if (left == 0)
			goto success;
	}

	/* Do it the slow way */
	kaddr = kmap(page);
	left = __copy_to_user(desc->arg.buf, kaddr + offset, size);
	kunmap(page);

	if (left) {
		size -= left;
		desc->error = -EFAULT;
	}
success:
	desc->count = count - size;
	desc->written += size;
	desc->arg.buf += size;
	return size;
}
