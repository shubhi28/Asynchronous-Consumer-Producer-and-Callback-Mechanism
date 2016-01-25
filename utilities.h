#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/export.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/err.h>
#include <crypto/md5.h>
#include <crypto/hash.h>
#include <crypto/algapi.h>

#define UDBG printk(KERN_DEFAULT "DBG:%s:%s:%d\n", __FILE__, __func__, __LINE__)
#define MD5_CHECKSUM_SIZE 16

static int delete_partial_file(struct file *fp);
static int rename_temp_file(struct file *fp_old, struct file *fp_new);

static int validate_file(struct file *f, int flag)
{
	int err = 0;
	/* Checking if a file exists */
	if (!f) {
		err = -ENOENT;
		goto out;
	}
	/*Checking error in file poniter */
	if (IS_ERR(f)) {
		err = PTR_ERR(f);
		goto out;
	}
	/*Checking if File is a regular file */
	if (!S_ISREG(f->f_inode->i_mode)) {
		err = -ENOENT;
		goto out;
	}
	if (flag == 1) {
		/*Checking if the input file can be read */
		if (!f->f_op->read) {
			err = -EACCES;
			goto out;
		}
		/*Checking the read permissions for the input file */
		if (!(f->f_mode & FMODE_READ)) {
			err = -EIO;
			goto out;
		}
	} else {
		/* Checking the file write permissions of Output file */
		if (!(f->f_mode & FMODE_WRITE)) {
			err = -EIO;
			goto out;
		}
		/* Checking if Output File can be written */
		if (!f->f_op->write) {
			err = -EACCES;
			goto out;
		}
	}
out:
	return err;
}

static int is_file_exists(char *name)
{
	mm_segment_t fs;
	int rc;
	struct kstat stat;
	fs = get_fs();
	set_fs(get_ds());
	rc = !vfs_stat(name, &stat);
	set_fs(fs);
	return rc;
}

static char *md5_checksum(char *infile, unsigned char *digest)
{
	struct crypto_hash *tfm;
	struct scatterlist sg;
	struct hash_desc desc;
	struct file *fp = NULL;
	char *buf = NULL;
	int file_size = 0, rbytes = 0, rc = 0;
	mm_segment_t fs;
	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (IS_ERR(buf)) {
		rc = -ENOMEM;
		goto out;
	}
	fp = filp_open(infile, O_RDONLY, 0);
	if (!fp || IS_ERR(fp)) {
		rc = -ENOENT;
		goto out;
	}

	if (!fp->f_op || !fp->f_op->read) {
		rc = -EPERM;
		goto out;
	}

	if (!S_ISREG(fp->f_inode->i_mode)) {
		rc = -ENOENT;
		goto out;
	}

	tfm = crypto_alloc_hash("md5", 0, 0);
	desc.tfm = tfm;
	desc.flags = 0;
	crypto_hash_init(&desc);
	file_size = i_size_read(fp->f_inode);
	fs = get_fs();
	set_fs(get_ds());
	while (fp->f_pos < file_size) {
		rbytes = fp->f_op->read(fp, buf, PAGE_SIZE, &fp->f_pos);
		if (rbytes < 0) {
			rc = -EIO;
			set_fs(fs);
			goto out;
		}
		sg_init_one(&sg, buf, rbytes);
		crypto_hash_update(&desc, &sg, rbytes);

	}
	set_fs(fs);

	crypto_hash_final(&desc, digest);
	crypto_free_hash(tfm);

out:
	if (buf)
		kfree(buf);
	if (fp && !IS_ERR(fp)) {
		filp_close(fp, NULL);
	}
	if (!rc)
		return digest;
	else
		return ERR_PTR(rc);
}

static char *sha1_checksum(char *infile, unsigned char *digest)
{
	struct crypto_hash *tfm;
	struct scatterlist sg;
	struct hash_desc desc;
	struct file *fp = NULL;
	char *buf = NULL;
	int file_size = 0, rbytes = 0, rc = 0;
	mm_segment_t fs;
	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (IS_ERR(buf)) {
		rc = -ENOMEM;
		goto out;
	}
	fp = filp_open(infile, O_RDONLY, 0);
	if (!fp || IS_ERR(fp)) {
		rc = -ENOENT;
		goto out;
	}

	if (!fp->f_op || !fp->f_op->read) {
		rc = -EPERM;
		goto out;
	}

	if (!S_ISREG(fp->f_inode->i_mode)) {
		rc = -ENOENT;
		goto out;
	}

	tfm = crypto_alloc_hash("sha1", 0, 0);
	desc.tfm = tfm;
	desc.flags = 0;
	crypto_hash_init(&desc);
	file_size = i_size_read(fp->f_inode);
	fs = get_fs();
	set_fs(get_ds());
	while (fp->f_pos < file_size) {
		rbytes = fp->f_op->read(fp, buf, PAGE_SIZE, &fp->f_pos);
		if (rbytes < 0) {
			rc = -EIO;
			set_fs(fs);
			goto out;
		}
		sg_init_one(&sg, buf, rbytes);
		crypto_hash_update(&desc, &sg, rbytes);
	}
	set_fs(fs);

	crypto_hash_final(&desc, digest);
	crypto_free_hash(tfm);
out:
	if (buf)
		kfree(buf);
	if (fp && !IS_ERR(fp)) {
		filp_close(fp, NULL);
	}
	if (!rc)
		return digest;
	else
		return ERR_PTR(rc);
}

int compress(char *infile, char *outfile)
{
	struct file *filr = NULL, *filw = NULL, *filt = NULL;
	struct crypto_comp *tfm = NULL;
	mm_segment_t oldfs;
	int ret = 0, bytes_r = 1, bytes_w = 0, comp_bytes = 0, dlen =
	    PAGE_SIZE;
	char *buf = NULL, *buf_write = NULL;
	char size[5];
	int flag_outfile = 0, flag_delete_temp = 0;

	oldfs = get_fs();
	set_fs(KERNEL_DS);

	filr = filp_open(infile, O_RDONLY, 0);
	if (!filr || IS_ERR(filr)) {
		ret = PTR_ERR(filr);
		goto out_final;
	}
	if (!filr->f_op->read) {
		ret = -2;
		goto out_final;
	}

	if (!S_ISREG(filr->f_inode->i_mode)) {
		ret = -ENOENT;
		goto out_final;
	}

	set_fs(oldfs);
	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf) {
		ret = -ENOMEM;
		goto out_final;
	}

	flag_outfile = is_file_exists(outfile);

	if (flag_outfile)
		filw = filp_open(outfile, O_WRONLY, 0);
	else
		filw = filp_open(outfile, O_CREAT | O_WRONLY, 0);

	filt = filp_open(strcat(outfile, ".tmp"), O_CREAT | O_WRONLY, 0);

	if (!filw || IS_ERR(filw)) {
		ret = PTR_ERR(filw);
		goto out;
	}
	if (!filw->f_op->write) {
		ret = -2;
		goto out;
	}
	buf_write = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf_write) {
		ret = -ENOMEM;
		goto out;
	}
	oldfs = get_fs();
	tfm = crypto_alloc_comp("deflate", 0, 0);
	set_fs(KERNEL_DS);
	filr->f_pos = 0;
	filw->f_pos = 0;
	while (bytes_r != 0) {
		bytes_r = vfs_read(filr, buf, PAGE_SIZE, &filr->f_pos);
		if (bytes_r < 0) {
			ret = -1;
			goto out;
		}
		comp_bytes =
		    crypto_comp_compress(tfm, buf, bytes_r, buf_write,
					 &dlen);
		snprintf(size, 5, "%d", dlen);
		bytes_w = vfs_write(filt, size, 5, &filt->f_pos);
		bytes_w = vfs_write(filt, buf_write, dlen, &filt->f_pos);
		dlen = PAGE_SIZE;
	}
	set_fs(oldfs);
	flag_delete_temp = 1;
	ret = rename_temp_file(filt, filw);
	if (ret)
		printk("Rename operation failed \n");
out:
	if (flag_delete_temp == 0) {
		if (ret < 0) {
			if (delete_partial_file(filt))
				printk
				    ("Deleting partial temp file failed \n");
		}
	}
	printk("flag_outfile = %d \n", flag_outfile);
	if (flag_outfile == 0) {
		if (ret < 0) {
			if (delete_partial_file(filw))
				printk("Deleting out file failed\n");
		}
	}
out_final:
	if (filt && !IS_ERR(filt))
		filp_close(filt, NULL);
	if (buf_write)
		kfree(buf_write);
	if (buf)
		kfree(buf);
	if (filw != NULL)
		filw = NULL;
	if (filr != NULL)
		filr = NULL;
	return ret;
}


int decompress(char *infile, char *outfile)
{
	struct file *filr = NULL, *filw = NULL, *filt = NULL;
	struct crypto_comp *tfm = NULL;
	mm_segment_t oldfs;
	int clen = PAGE_SIZE, dlen = 0;
	int ret = 0, bytes_r = 1, bytes_w = 0, comp_bytes = 0, val = 0;
	char *buf = NULL, *buf_write = NULL, *buf_temp = NULL;
	int flag_outfile = 0, flag_delete_temp = 0;

	oldfs = get_fs();
	set_fs(KERNEL_DS);

	filr = filp_open(infile, O_RDONLY, 0);
	if (!filr || IS_ERR(filr)) {
		ret = PTR_ERR(filr);
		goto out_final;
	}
	if (!filr->f_op->read) {
		ret = -2;
		goto out_final;
	}

	if (!S_ISREG(filr->f_inode->i_mode)) {
		ret = -ENOENT;
		goto out_final;
	}

	set_fs(oldfs);
	buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf) {
		ret = -ENOMEM;
		goto out_final;
	}
	flag_outfile = is_file_exists(outfile);

	if (flag_outfile)
		filw = filp_open(outfile, O_WRONLY, 0);
	else
		filw = filp_open(outfile, O_CREAT | O_WRONLY, 0);

	filt = filp_open(strcat(outfile, ".tmp"), O_CREAT | O_WRONLY, 0);

	if (!filw || IS_ERR(filw)) {
		ret = PTR_ERR(filw);
		goto out;
	}

	if (!filw->f_op->write) {
		ret = -2;
		goto out;
	}
	buf_write = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf_write) {
		ret = -ENOMEM;
		goto out;
	}
	oldfs = get_fs();
	tfm = crypto_alloc_comp("deflate", 0, 0);
	set_fs(KERNEL_DS);
	filr->f_pos = 0;
	filw->f_pos = 0;
	buf_temp = kzalloc(8, GFP_KERNEL);
	if (!buf_temp) {
		ret = -ENOMEM;
		goto out;
	}
	while (bytes_r != 0) {
		bytes_r = vfs_read(filr, buf_temp, 5, &filr->f_pos);
		val = kstrtoint(buf_temp, 10, &dlen);
		if (val) {
			ret = -EINVAL;
			goto out;
		}
		bytes_r = vfs_read(filr, buf, dlen, &filr->f_pos);
		if (bytes_r < 0) {
			ret = -EFAULT;
			goto out;
		}
		comp_bytes =
		    crypto_comp_decompress(tfm, buf, dlen, buf_write,
					   &clen);
		bytes_w = vfs_write(filt, buf_write, clen, &filt->f_pos);
		clen = PAGE_SIZE;
	}
	set_fs(oldfs);
	flag_delete_temp = 1;
	ret = rename_temp_file(filt, filw);
	if (ret)
		printk("Rename operation failed \n");
out:
	if (flag_delete_temp == 0) {
		if (ret < 0) {
			if (delete_partial_file(filt))
				printk
				    ("Deleting partial temp file failed \n");
		}
	}
	if (flag_outfile == 0) {
		if (ret < 0) {
			if (delete_partial_file(filw))
				printk("Deleting out file failed\n");
		}
	}
out_final:
	if (filt && !IS_ERR(filt))
		filp_close(filt, NULL);
	if (buf_temp)
		kfree(buf_temp);
	if (buf_write)
		kfree(buf_write);
	if (buf)
		kfree(buf);
	if (filw != NULL)
		filw = NULL;
	if (filr != NULL)
		filr = NULL;
	return ret;
}

int concat_files(char *infile, char *outfile)
{
	int w_ret, ret = 0;
	struct file *in1 = NULL, *out1 = NULL, *out2 = NULL, *outt = NULL;
	struct filename *file = NULL;
	char *buf1, *buf2 = NULL, *p;
	int file_size;
	mm_segment_t ofs;
	int flag_outfile = 0, flag_delete_temp = 0;

	buf1 = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf1) {
		ret = -ENOMEM;
		goto out;
	}
	memset(buf1, 0, PAGE_SIZE);
	buf2 = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf2) {
		ret = -ENOMEM;
		goto out;
	}
	memset(buf2, 0, PAGE_SIZE);

	out1 = filp_open(infile, O_RDONLY, 0);
	ret = validate_file(out1, 1);
	if (ret < 0) {
		goto out;
	}

	flag_outfile = is_file_exists(outfile);

	if (flag_outfile)
		out2 = filp_open(outfile, O_WRONLY, 0);
	else
		out2 = filp_open(outfile, O_CREAT | O_WRONLY, 0);

	outt = filp_open(strcat(outfile, ".tmp"), O_CREAT | O_WRONLY, 0);

	ret = validate_file(out2, 2);
	if (ret < 0) {
		goto out;
	}
	ofs = get_fs();
	set_fs(get_ds());
	ret = out1->f_op->read(out1, buf1, PAGE_SIZE, &out1->f_pos);
	if (ret < 0) {
		ret = -EIO;
		set_fs(ofs);
		goto out;
	}
	while ((p = strsep(&buf1, "\n")) != NULL) {
		if (!*p) {
			continue;
		}
		file = getname(p);
		if (IS_ERR(file)) {
			ret = PTR_ERR(file);
			goto out;
		}
		in1 = filp_open(file->name, O_RDONLY, 0);
		ret = validate_file(in1, 1);
		if (ret < 0) {
			goto out;
		}
		file_size = i_size_read(in1->f_inode);
		while (in1->f_pos < file_size) {
			ret =
			    in1->f_op->read(in1, buf2, PAGE_SIZE,
					    &in1->f_pos);
			if (ret < 0) {
				ret = -EIO;
				set_fs(ofs);
				goto out;
			}
			w_ret =
			    outt->f_op->write(outt, buf2, ret,
					      &outt->f_pos);
			if (w_ret < 0) {
				set_fs(ofs);
				ret = -EIO;
				goto out;
			}
		}
		ret = 0;
		filp_close(in1, NULL);
		putname(file);
	}

	set_fs(ofs);
	flag_delete_temp = 1;
	ret = rename_temp_file(outt, out2);
	if (ret)
		printk("Rename operation failed \n");
out:
	if (flag_delete_temp == 0) {
		if (ret < 0) {
			if (delete_partial_file(outt))
				printk
				    ("Deleting partial temp file failed \n");
		}
	}
	printk("flag_outfile = %d \n", flag_outfile);
	if (flag_outfile == 0) {
		if (ret < 0) {
			if (delete_partial_file(out2))
				printk("Deleting out file failed\n");
		}
	}
	if (outt && !IS_ERR(outt))
		filp_close(outt, NULL);
	if (buf1)
		kfree(buf1);
	if (buf2)
		kfree(buf2);
	return ret;

}

static int delete_partial_file(struct file *fp)
{
	int rc;
	struct dentry *d = fp->f_path.dentry;
	struct inode *pi = fp->f_path.dentry->d_parent->d_inode;

	struct dentry *pd = NULL;
	dget(d);
	pd = dget_parent(d);
	mutex_lock_nested(&pd->d_inode->i_mutex, I_MUTEX_PARENT);

	rc = vfs_unlink(pi, d, NULL);
	if (rc) {
		printk("Error in vfs_unlink() \n");
		rc = -ECANCELED;
		goto out;
	}

out:
	mutex_unlock(&pd->d_inode->i_mutex);
	dput(pd);
	dput(d);
	return rc;
}

static int rename_temp_file(struct file *fp_old, struct file *fp_new)
{
	int rc;
	struct inode *pi_old = fp_old->f_path.dentry->d_parent->d_inode;
	struct inode *pi_new = fp_new->f_path.dentry->d_parent->d_inode;

	struct dentry *d_old = fp_old->f_path.dentry;
	struct dentry *d_new = fp_new->f_path.dentry;

	struct dentry *pd_old = NULL;
	struct dentry *pd_new = NULL;
	struct dentry *trap = NULL;

	dget(d_old);
	dget(d_new);
	pd_old = dget_parent(d_old);
	pd_new = dget_parent(d_new);

	trap = lock_rename(pd_old, pd_new);

	if (trap == d_old) {
		rc = -EINVAL;
		goto out;
	}

	if (trap == d_new) {
		rc = -ENOTEMPTY;
		goto out;
	}

	rc = vfs_rename(pi_old, d_old, pi_new, d_new, NULL, 0);
	if (rc) {
		printk("Error in vfs_rename() \n");
		rc = -ECANCELED;
		goto out;
	}
out:
	unlock_rename(pd_old, pd_new);
	dput(pd_new);
	dput(pd_old);
	dput(d_new);
	dput(d_old);

	return rc;
}

unsigned char *calculate_hash(unsigned char *pswd)
{
	struct hash_desc hash;
	struct crypto_hash *tfm;
	struct scatterlist sl_2;
	int ret;
	unsigned char *hashed_pswd;

	hashed_pswd = kmalloc(16, GFP_KERNEL);
	if (!hashed_pswd) {
		printk("not enough memory for hashing");
		ret = ENOMEM;
	}
	tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);

	if (IS_ERR(tfm)) {
		ret = -PTR_ERR(tfm);
		goto out;
	}
	hash.flags = 0;
	hash.tfm = tfm;
	sg_init_one(&sl_2, pswd, 16);
	crypto_hash_init(&hash);
	crypto_hash_update(&hash, &sl_2, 16);
	crypto_hash_final(&hash, hashed_pswd);
	crypto_free_hash(tfm);

	return hashed_pswd;
out:
	return ERR_PTR(ret);
}

static int encrypt(char *infile, char *outfile, unsigned char *key)
{
	struct file *filr = NULL, *filw = NULL, *filt = NULL;
	mm_segment_t oldfs;
	int ret = 0, bytes_r = 1, bytes_w = 0, mask = 0, mode = 0;
	int flag_outfile = 0, flag_delete_temp = 0;
	char *buf_write = NULL;
	struct crypto_blkcipher *blkcipher = NULL;
	char *cipher = "ctr(aes)";
	struct scatterlist sl_1;
	struct blkcipher_desc desc;
	unsigned char *hashed_pswd = NULL;

	oldfs = get_fs();
	set_fs(KERNEL_DS);

	filr = filp_open(infile, O_RDONLY, 0);
	if (!filr || IS_ERR(filr)) {
		set_fs(oldfs);
		ret = PTR_ERR(filr);
		goto out_final;
	}
	if (!filr->f_op->read) {
		set_fs(oldfs);
		ret = -2;
		goto out_final;
	}

	if (!S_ISREG(filr->f_inode->i_mode)) {
		printk("Input or Output file is not a regular file\n");
		ret = -ENOENT;
		goto out_final;
	}

	mask = current_umask();
	mode = 0666 & ~mask;

	flag_outfile = is_file_exists(outfile);

	if (flag_outfile)
		filw = filp_open(outfile, O_WRONLY, mode);
	else
		filw = filp_open(outfile, O_CREAT | O_WRONLY, mode);

	filt =
	    filp_open(strcat(outfile, ".tmp"), O_CREAT | O_WRONLY, mode);

	if (!filw || IS_ERR(filw)) {
		set_fs(oldfs);
		ret = PTR_ERR(filw);
		goto out;
	}
	if (!filw->f_op->write) {
		set_fs(oldfs);
		printk("no write permission");
		ret = -2;
		goto out;
	}
	set_fs(oldfs);
	buf_write = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf_write) {
		ret = -ENOMEM;
		goto out;
	}
	blkcipher = crypto_alloc_blkcipher(cipher, 0, 0);
	if (IS_ERR(blkcipher)) {
		ret = -PTR_ERR(blkcipher);
		goto out;
	}
	if (crypto_blkcipher_setkey(blkcipher, key, 16)) {
		ret = -EAGAIN;
		goto out;
	}
	desc.flags = 0;
	desc.tfm = blkcipher;

	hashed_pswd = kmalloc(16, GFP_KERNEL);
	if (!hashed_pswd) {
		ret = -ENOMEM;
		goto out;
	}

	filr->f_pos = 0;
	filw->f_pos = 0;
	oldfs = get_fs();
	set_fs(KERNEL_DS);

	hashed_pswd = calculate_hash(key);
	if (IS_ERR(hashed_pswd)) {
		ret = PTR_ERR(hashed_pswd);
		set_fs(oldfs);
		goto out;
	}
	vfs_write(filt, hashed_pswd, 16, &filt->f_pos);

	while (bytes_r != 0) {
		bytes_r =
		    vfs_read(filr, buf_write, PAGE_SIZE, &filr->f_pos);
		if (bytes_r < 0) {
			set_fs(oldfs);
			ret = -EFAULT;
			goto out;
		}
		sg_init_one(&sl_1, buf_write, bytes_r);
		if (crypto_blkcipher_encrypt(&desc, &sl_1, &sl_1, bytes_r)) {
			set_fs(oldfs);
			goto out;
		}
		bytes_w =
		    vfs_write(filt, buf_write, bytes_r, &filt->f_pos);
		if (bytes_w < 0) {
			set_fs(oldfs);
			ret = -EFAULT;
			goto out;
		}

	}
	set_fs(oldfs);
	flag_delete_temp = 1;
	ret = rename_temp_file(filt, filw);
	if (ret)
		printk("Rename operation failed \n");

out:
	if (flag_delete_temp == 0) {
		if (ret < 0) {
			if (delete_partial_file(filt))
				printk
				    ("Deleting partial temp file failed \n");
		}
	}
	printk("flag_outfile = %d \n", flag_outfile);
	if (flag_outfile == 0) {
		if (ret < 0) {
			if (delete_partial_file(filw))
				printk("Deleting out file failed\n");
		}
	}
	if (filt && !IS_ERR(filt))
		filp_close(filt, NULL);
	if (hashed_pswd)
		kfree(hashed_pswd);
	if (buf_write)
		kfree(buf_write);
	if (filw != NULL)
		filw = NULL;
out_final:
	if (filr != NULL)
		filr = NULL;
	return 0;
}

static int decrypt(char *infile, char *outfile, unsigned char *key)
{

	struct file *filr = NULL, *filw = NULL, *filt = NULL;
	mm_segment_t oldfs;
	int ret = 0, bytes_r = 1, bytes_w = 0, mask = 0, mode = 0;
	int flag_outfile = 0, flag_delete_temp = 0;
	char *buf_write = NULL;
	struct crypto_blkcipher *blkcipher = NULL;
	char *cipher = "ctr(aes)";
	struct scatterlist sl_1;
	struct blkcipher_desc desc;
	unsigned char *hashed_pswd = NULL, *buf_chk_pswd = NULL;
	bool pswd_cmp = 0;

	oldfs = get_fs();
	set_fs(KERNEL_DS);

	filr = filp_open(infile, O_RDONLY, 0);
	if (!filr || IS_ERR(filr)) {
		set_fs(oldfs);
		ret = PTR_ERR(filr);
		goto out_final;
	}
	if (!filr->f_op->read) {
		set_fs(oldfs);
		ret = -EPERM;
		goto out_final;
	}

	if (!S_ISREG(filr->f_inode->i_mode)) {
		printk("Input or Output file is not a regular file\n");
		ret = -ENOENT;
		goto out_final;
	}

	mask = current_umask();
	mode = 0666 & ~mask;
	flag_outfile = is_file_exists(outfile);

	if (flag_outfile)
		filw = filp_open(outfile, O_WRONLY, mode);
	else
		filw = filp_open(outfile, O_CREAT | O_WRONLY, mode);

	filt =
	    filp_open(strcat(outfile, ".tmp"), O_CREAT | O_WRONLY, mode);

	if (!filw || IS_ERR(filw)) {
		set_fs(oldfs);
		ret = PTR_ERR(filw);
		goto out;
	}
	if (!filw->f_op->write) {
		set_fs(oldfs);
		printk("no write permission");
		ret = -EPERM;
		goto out;
	}
	set_fs(oldfs);
	buf_write = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf_write) {
		ret = -ENOMEM;
		goto out;
	}
	blkcipher = crypto_alloc_blkcipher(cipher, 0, 0);
	if (IS_ERR(blkcipher)) {
		ret = -PTR_ERR(blkcipher);
		goto out;
	}
	if (crypto_blkcipher_setkey(blkcipher, key, 16)) {
		ret = -EAGAIN;
		goto out;
	}
	desc.flags = 0;
	desc.tfm = blkcipher;

	hashed_pswd = kmalloc(16, GFP_KERNEL);
	if (!hashed_pswd) {
		ret = -ENOMEM;
		goto out;
	}

	filr->f_pos = 0;
	filw->f_pos = 0;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	buf_chk_pswd = kmalloc(17, GFP_KERNEL);
	if (!buf_chk_pswd) {
		ret = -ENOMEM;
		goto out;
	}
	vfs_read(filr, buf_chk_pswd, 16, &filr->f_pos);
	hashed_pswd = calculate_hash(key);
	if (IS_ERR(hashed_pswd)) {
		ret = PTR_ERR(hashed_pswd);
		goto out;
	}
	pswd_cmp = memcmp(hashed_pswd, buf_chk_pswd, 16);
	if (pswd_cmp != 0) {
		printk(KERN_INFO "wrong digest!");
		ret = -EINVAL;
		goto out;
	}
	while (bytes_r != 0) {
		bytes_r =
		    vfs_read(filr, buf_write, PAGE_SIZE, &filr->f_pos);
		if (bytes_r < 0) {
			set_fs(oldfs);
			ret = -EFAULT;
			goto out;
		}
		sg_init_one(&sl_1, buf_write, bytes_r);
		if (crypto_blkcipher_decrypt(&desc, &sl_1, &sl_1, bytes_r)) {
			set_fs(oldfs);
			goto out;
		}
		bytes_w =
		    vfs_write(filt, buf_write, bytes_r, &filt->f_pos);
		if (bytes_w < 0) {
			set_fs(oldfs);
			ret = -EFAULT;
			goto out;
		}

	}
	set_fs(oldfs);
	flag_delete_temp = 1;
	ret = rename_temp_file(filt, filw);
	if (ret)
		printk("Rename operation failed \n");
out:
	if (flag_delete_temp == 0) {
		if (ret < 0) {
			if (delete_partial_file(filt))
				printk
				    ("Deleting partial temp file failed \n");
		}
	}
	printk("flag_outfile = %d \n", flag_outfile);
	if (flag_outfile == 0) {
		if (ret < 0) {
			if (delete_partial_file(filw))
				printk("Deleting out file failed\n");
		}
	}
	if (filt && !IS_ERR(filt))
		filp_close(filt, NULL);
	if (buf_chk_pswd)
		kfree(buf_chk_pswd);
	if (hashed_pswd)
		kfree(hashed_pswd);
	if (buf_write)
		kfree(buf_write);
	if (filw != NULL)
		filw = NULL;
out_final:
	if (filr != NULL)
		filr = NULL;
	return ret;
}
