#include "lde.h"
#include "kallsyms.h"
#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/fs_struct.h>
#include <linux/list.h>
#include <linux/stat.h>

char buf[PATH_MAX];

static void sb_simple_info_dump(int num, struct super_block* my_sb)
{
	printk(KERN_INFO
		"\tsuper block num = %04d, dev num = %d\n"
		"\tfs type = %s\n"
		"\ts_flags = 0x%08lx ; s_iflags = 0x%08lx ; s_magic = 0x%08lx ;\n"
		"\td_flags = 0x%04x ; root path = [%s].\n",
		num, my_sb->s_dev, my_sb->s_type->name,
		my_sb->s_flags, my_sb->s_iflags, my_sb->s_magic,
		my_sb->s_root->d_flags, my_sb->s_root->d_name.name
	);
}

static void all_sb_simple_info_dump(void)
{
	int i;
	struct list_head* my_super_blocks;
	struct super_block* my_sb;
	spinlock_t* my_sb_lock;

	my_super_blocks = (struct list_head*)LDE_KLN_PTR("super_blocks");
	my_sb_lock = (spinlock_t*)LDE_KLN_PTR("sb_lock");
	if (!my_super_blocks || !my_sb_lock) {
		printk(KERN_ERR "unable to find symbol by [kallsyms_lookup_name], will exit ...\n");
		return;
	}
	else {
		printk(KERN_INFO "found symbol, super_blocks: 0x%px, sb_lock: 0x%px\n", my_super_blocks, my_sb_lock);
	}

	i = 0;
	printk(KERN_INFO "--------all super block simple info dump start--------\n");
	spin_lock(my_sb_lock);
	list_for_each_entry(my_sb, my_super_blocks, s_list) {
		sb_simple_info_dump(i, my_sb);

		i++;
	}
	spin_unlock(my_sb_lock);
	printk(KERN_INFO "--------all super block simple info dump end--------\n");
}

static void fs_simple_info_dump(int num, struct file_system_type* my_fs)
{
	printk(KERN_INFO "\tfs type, num = %04d, dev = %s, name = %s.\n",
		num, (my_fs->fs_flags & FS_REQUIRES_DEV) ? "hasdev" : "nodev", my_fs->name
	);
}

static void all_fs_simple_info_dump(void)
{
	int i;
	struct file_system_type* my_file_systems, ** my_fs;
	rwlock_t* my_file_systems_lock;

	my_file_systems = (struct file_system_type*)LDE_KLN_PTR("file_systems");
	my_file_systems_lock = (rwlock_t*)LDE_KLN_PTR("file_systems_lock");
	if (!my_file_systems || !my_file_systems_lock) {
		printk(KERN_ERR "unable to find symbol by [kallsyms_lookup_name], will exit ...\n");
		return;
	}
	else {
		printk(KERN_INFO "found symbol, file_systems: 0x%px, file_systems_lock: 0x%px\n", my_file_systems, my_file_systems_lock);
	}

	i = 0;
	my_fs = (struct file_system_type**)my_file_systems;
	read_lock(my_file_systems_lock);
	printk(KERN_INFO "--------all file system simple info dump start = 0x%px--------\n", my_fs);
	while (*my_fs) {
		fs_simple_info_dump(i, *my_fs);

		i++;
		my_fs = &(*my_fs)->next;
	}
	read_unlock(my_file_systems_lock);
	printk(KERN_INFO "--------all file system simple info dump end = 0x%px--------\n", my_fs);
}

void file_systems_info_dump(void)
{
	struct fs_struct* cur_fs;
	struct super_block* cur_sb;
    struct path cur_pwd;

	cur_fs = current->fs;
    get_fs_pwd(cur_fs, &cur_pwd);
	cur_sb = cur_pwd.dentry->d_sb;
	printk(KERN_INFO "current path = %s\n", d_path(&cur_pwd, buf, PATH_MAX));
	printk(KERN_INFO "inode name = %s, inode index num = %ld\n"
		"mode = 0x%04x; opflags = 0x%04x ; flags = 0x%04x ; uid = %04d ; gid = %04d.\n",
		cur_pwd.dentry->d_name.name, cur_pwd.dentry->d_inode->i_ino,
		cur_pwd.dentry->d_inode->i_mode,
		cur_pwd.dentry->d_inode->i_opflags,
		cur_pwd.dentry->d_inode->i_flags,
		cur_pwd.dentry->d_inode->i_uid.val,
		cur_pwd.dentry->d_inode->i_gid.val
	);
	fs_simple_info_dump(0, cur_sb->s_type);
	sb_simple_info_dump(0, cur_sb);

	all_fs_simple_info_dump();
	all_sb_simple_info_dump();
}
